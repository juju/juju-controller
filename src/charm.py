#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import controlsocket
import configchangesocket
import json
import logging
import secrets
import urllib.parse
import yaml
import ops
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from typing import List

logger = logging.getLogger(__name__)


class JujuControllerCharm(ops.CharmBase):
    METRICS_SOCKET_PATH = '/var/lib/juju/control.socket'
    CONFIG_SOCKET_PATH = '/var/lib/juju/configchange.socket'
    DB_BIND_ADDR_KEY = 'db-bind-address'
    ALL_BIND_ADDRS_KEY = 'db-bind-addresses'
    AGENT_ID_KEY = 'agent-id'

    _stored = ops.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._observe()

        self._stored.set_default(
            last_bind_addresses=[],
        )

        # TODO (manadart 2024-03-05): Get these at need.
        # No need to instantiate them for every invocatoin.
        self._control_socket = controlsocket.ControlSocketClient(
            socket_path=self.METRICS_SOCKET_PATH)
        self._config_change_socket = configchangesocket.ConfigChangeSocketClient(
            socket_path=self.CONFIG_SOCKET_PATH)

    def _observe(self):
        """Set up all framework event observers."""
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)
        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)
        self.framework.observe(
            self.on.dbcluster_relation_changed, self._on_dbcluster_relation_changed)
        self.framework.observe(
            self.on.dbcluster_relation_departed, self._on_dbcluster_relation_departed)

    def _on_install(self, event: InstallEvent):
        """Ensure that the controller configuration file exists."""
        file_path = self._controller_config_path()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        open(file_path, 'w+').close()

    def _on_start(self, _):
        self.unit.status = ops.ActiveStatus()

    def _on_collect_status(self, event: CollectStatusEvent):
        if len(self._stored.last_bind_addresses) > 1:
            event.add_status(ops.BlockedStatus(
                'multiple possible DB bind addresses; set a suitable dbcluster network binding'))

        try:
            self.api_port()
        except AgentConfException as e:
            event.add_status(BlockedStatus(
                f'cannot read controller API port from agent configuration: {e}'))

        event.add_status(ops.ActiveStatus())

    def _on_config_changed(self, _):
        controller_url = self.config['controller-url']
        logger.info('got a new controller-url: %r', controller_url)

    def _on_dashboard_relation_joined(self, event):
        logger.info('got a new dashboard relation: %r', event)
        if self.unit.is_leader():
            event.relation.data[self.app].update({
                'controller-url': self.config['controller-url'],
                'identity-provider-url': self.config['identity-provider-url'],
                'is-juju': str(self.config['is-juju']),
            })
        # TODO: do we need to poke something on the controller so that the `juju
        # dashboard` command will work?

    def _on_website_relation_joined(self, event):
        """Connect a website relation."""
        logger.info("got a new website relation: %r", event)
        port = self.api_port()
        if port is None:
            logger.error("machine does not appear to be a controller")
            self.unit.status = ops.BlockedStatus('machine does not appear to be a controller')
            return

        address = None
        binding = self.model.get_binding(event.relation)
        if binding:
            address = binding.network.ingress_address
            if self.unit.is_leader():
                event.relation.data[self.unit].update({
                    'hostname': str(address),
                    'private-address': str(address),
                    'port': str(api_port)
                })

    def _on_metrics_endpoint_relation_created(self, event: ops.RelationJoinedEvent):
        username = metrics_username(event.relation)
        password = generate_password()
        self._control_socket.add_metrics_user(username, password)

        # Set up Prometheus scrape config
        try:
            api_port = self.api_port()
        except AgentConfException as e:
            self.unit.status = ops.BlockedStatus(
                f"can't read controller API port from agent.conf: {e}")
            logger.error('cannot read controller API port from agent configuration: %s', e)
            return

        metrics_endpoint = MetricsEndpointProvider(
            self,
            jobs=[{
                "metrics_path": "/introspection/metrics",
                "scheme": "https",
                "static_configs": [{
                    "targets": [
                        f'*:{api_port}'
                    ]
                }],
                "basic_auth": {
                    "username": f'user-{username}',
                    "password": password,
                },
                "tls_config": {
                    "ca_file": self.ca_cert(),
                    "server_name": "juju-apiserver",
                },
            }],
        )
        metrics_endpoint.set_scrape_job_spec()

    def _on_metrics_endpoint_relation_broken(self, event: ops.RelationDepartedEvent):
        username = metrics_username(event.relation)
        self._control_socket.remove_metrics_user(username)

    def _on_dbcluster_relation_changed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _on_dbcluster_relation_departed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _update_bind_addresses(self, relation):
        """Maintain our own bind address in relation data.
        If we are the leader, aggregate the bind addresses for all the peers,
        and ensure the result is set in the application data bag.
        If the aggregate addresses have changed, rewrite the config file.
        """

        try:
            ip = self._set_db_bind_address(relation)
        except DBBindAddressException as e:
            logger.error(e)
            ip = None

        if self.unit.is_leader():
            # The event only has *other* units so include this
            # unit's bind address if we have managed to set it.
            all_bind_addresses = {self._controller_agent_id(): ip} if ip else dict()

            for unit in relation.units:
                unit_data = relation.data[unit]
                if self.DB_BIND_ADDR_KEY in unit_data:
                    agent_id = unit_data[self.AGENT_ID_KEY]
                    all_bind_addresses[agent_id] = unit_data[self.DB_BIND_ADDR_KEY]

            relation.data[self.app][self.ALL_BIND_ADDRS_KEY] = json.dumps(
                all_bind_addresses, sort_keys=True)
            self._update_config_file(all_bind_addresses)
        else:
            app_data = relation.data[self.app]
            if self.ALL_BIND_ADDRS_KEY in app_data:
                all_bind_addresses = json.loads(app_data[self.ALL_BIND_ADDRS_KEY])
            else:
                all_bind_addresses = dict()

            self._update_config_file(all_bind_addresses)

    def _set_db_bind_address(self, relation):
        """Set a db bind address for Dqlite in relation data, if we can
        determine a unique one from the relation's bound space.

        Returns the db bind address.
        """
        ips = [str(ip) for ip in self.model.get_binding(relation).network.ingress_addresses]
        self._stored.last_bind_addresses = ips
        ip = ips[0]

        if len(ips) > 1:
            raise DBBindAddressException(
                'multiple possible DB bind addresses;set a suitable cluster network binding')

        logger.info('setting DB bind address: %s', ip)
        relation.data[self.unit].update({
            self.DB_BIND_ADDR_KEY: ip,
            self.AGENT_ID_KEY: self._controller_agent_id()
        })
        return ip

    def _update_config_file(self, bind_addresses):
        logger.info('writing new DB cluster to config file: %s', bind_addresses)

        file_path = self._controller_config_path()
        with open(file_path) as conf_file:
            conf = yaml.safe_load(conf_file)

        if not conf:
            conf = dict()
        conf[self.ALL_BIND_ADDRS_KEY] = bind_addresses

        with open(file_path, 'w') as conf_file:
            yaml.dump(conf, conf_file)

        self._request_config_reload()
        self._stored.all_bind_addresses = bind_addresses

    def api_port(self) -> str:
        """Return the port on which the controller API server is listening."""
        api_addresses = self._agent_conf('apiaddresses')
        if not api_addresses:
            raise AgentConfException("agent.conf key 'apiaddresses' missing")
        if not isinstance(api_addresses, List):
            raise AgentConfException("agent.conf key 'apiaddresses' is not a list")

        parsed_url = urllib.parse.urlsplit('//' + api_addresses[0])
        if not parsed_url.port:
            raise AgentConfException('API address does not include port')
        return parsed_url.port

    def ca_cert(self) -> str:
        """Return the controller's CA certificate."""
        return self._agent_conf('cacert')

    def _agent_conf(self, key: str):
        """Read a value (by key) from the agent.conf file on disk."""
        unit_name = self.unit.name.replace('/', '-')
        agent_conf_path = f'/var/lib/juju/agents/unit-{unit_name}/agent.conf'

        with open(agent_conf_path) as agent_conf_file:
            agent_conf = yaml.safe_load(agent_conf_file)
            return agent_conf.get(key)

    def _controller_config_path(self) -> str:
        """Interrogate the running controller jujud service to determine
        the local controller ID, then use it to construct a config path.
        """
        controller_id = self._controller_agent_id()
        return f'/var/lib/juju/agents/controller-{controller_id}/controller.conf'

    def _controller_agent_id(self):
        return self._config_change_socket.get_controller_agent_id()

    def _request_config_reload(self):
        """Send a reload request to the config reload socket."""
        self._config_change_socket.reload_config()


def metrics_username(relation: ops.Relation) -> str:
    """
    Return the username used to access the metrics endpoint, for the given
    relation. This username has the form
        juju-metrics-r1
    """
    return f'juju-metrics-r{relation.id}'


def generate_password() -> str:
    return secrets.token_urlsafe(16)


class AgentConfException(Exception):
    """Raised when there are errors regarding agent configuration."""


class ControllerProcessException(Exception):
    """Raised when there are errors regarding detection of controller service or process."""


class DBBindAddressException(Exception):
    """Raised when there are errors regarding the database bind addresses"""


if __name__ == "__main__":
    ops.main(JujuControllerCharm)
