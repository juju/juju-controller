#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import controlsocket
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import urllib.parse
import yaml

from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import StoredState
from ops.charm import InstallEvent, RelationJoinedEvent, RelationDepartedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    DB_BIND_ADDR_KEY = 'db-bind-address'
    ALL_BIND_ADDRS_KEY = 'db-bind-addresses'

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)

        self._stored.set_default(
            db_bind_address='',
            last_bind_addresses=[],
            all_bind_addresses=dict(),
        )
        self.framework.observe(
            self.on.dbcluster_relation_changed, self._on_dbcluster_relation_changed)

        self.control_socket = controlsocket.Client(
            socket_path='/var/lib/juju/control.socket')
        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)

    def _on_install(self, event: InstallEvent):
        """Ensure that the controller configuration file exists."""
        file_path = self._controller_config_path()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        open(file_path, 'w+').close()

    def _on_collect_status(self, event: CollectStatusEvent):
        if len(self._stored.last_bind_addresses) > 1:
            event.add_status(BlockedStatus(
                'multiple possible DB bind addresses; set a suitable dbcluster network binding'))

        try:
            self.api_port()
        except AgentConfException as e:
            event.add_status(BlockedStatus(
                f'cannot read controller API port from agent configuration: {e}'))

        event.add_status(ActiveStatus())

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
        logger.info('got a new website relation: %r', event)

        try:
            api_port = self.api_port()
        except AgentConfException as e:
            logger.error('cannot read controller API port from agent configuration: %s', e)
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

    def _on_metrics_endpoint_relation_created(self, event: RelationJoinedEvent):
        username = metrics_username(event.relation)
        password = generate_password()
        self.control_socket.add_metrics_user(username, password)

        # Set up Prometheus scrape config
        try:
            api_port = self.api_port()
        except AgentConfException as e:
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

    def _on_metrics_endpoint_relation_broken(self, event: RelationDepartedEvent):
        username = metrics_username(event.relation)
        self.control_socket.remove_metrics_user(username)

    def _on_dbcluster_relation_changed(self, event):
        """Maintain our own bind address in relation data.
        If we are the leader, aggregate the bind addresses for all the peers,
        and ensure the result is set in the application data bag.
        If the aggregate addresses have changed, rewrite the config file.
        """
        relation = event.relation
        self._ensure_db_bind_address(relation)

        if self.unit.is_leader():
            # The event only has *other* units so include this
            # unit's bind address if we have managed to set it.
            ip = self._stored.db_bind_address
            all_bind_addresses = {self.unit.name: ip} if ip else dict()

            for unit in relation.units:
                unit_data = relation.data[unit]
                if self.DB_BIND_ADDR_KEY in unit_data:
                    all_bind_addresses[unit.name] = unit_data[self.DB_BIND_ADDR_KEY]

            if self._stored.all_bind_addresses == all_bind_addresses:
                return

            relation.data[self.app][self.ALL_BIND_ADDRS_KEY] = json.dumps(all_bind_addresses)
            self._update_config_file(all_bind_addresses)
        else:
            app_data = relation.data[self.app]
            if self.ALL_BIND_ADDRS_KEY in app_data:
                all_bind_addresses = json.loads(app_data[self.ALL_BIND_ADDRS_KEY])
            else:
                all_bind_addresses = dict()

            if self._stored.all_bind_addresses == all_bind_addresses:
                return

            self._update_config_file(all_bind_addresses)

    def _ensure_db_bind_address(self, relation):
        """Ensure that a bind address for Dqlite is set in relation data,
        if we can determine a unique one from the relation's bound space.
        """
        ips = [str(ip) for ip in self.model.get_binding(relation).network.ingress_addresses]
        self._stored.last_bind_addresses = ips

        if len(ips) > 1:
            logger.error(
                'multiple possible DB bind addresses; set a suitable cluster network binding')
            return

        ip = ips[0]
        if self._stored.db_bind_address == ip:
            return

        logger.info('setting new DB bind address: %s', ip)
        relation.data[self.unit].update({self.DB_BIND_ADDR_KEY: ip})
        self._stored.db_bind_address = ip

    def _update_config_file(self, bind_addresses):
        file_path = self._controller_config_path()
        with open(file_path) as conf_file:
            conf = yaml.safe_load(conf_file)

        if not conf:
            conf = dict()
        conf[self.ALL_BIND_ADDRS_KEY] = bind_addresses

        with open(file_path, 'w') as conf_file:
            yaml.dump(conf, conf_file)

        self._sighup_controller_process()
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
        match = re.search(r'jujud-machine-(\d+)\.service', self._controller_service_name())
        if not match:
            raise AgentConfException('Unable to determine ID for running controller')

        controller_id = match.group(1)
        return f'/var/lib/juju/agents/controller-{controller_id}/agent.conf'

    def _sighup_controller_process(self):
        res = subprocess.check_output(
            ["systemctl", "show", "--property=MainPID", self._controller_service_name()])

        pid = res.decode('utf-8').strip().split('=')[-1]
        os.kill(int(pid), signal.SIGHUP)

    def _controller_service_name(self) -> str:
        res = subprocess.check_output(
            ['systemctl', 'list-units', 'jujud-machine-*.service', '--no-legend'], text=True)

        services = [line.split()[0] for line in res.strip().split('\n') if line]
        if len(services) != 1:
            raise AgentConfException('Unable to determine service for running controller')

        return services[0]


def metrics_username(relation: Relation) -> str:
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


if __name__ == "__main__":
    main(JujuControllerCharm)
