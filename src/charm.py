#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import controlsocket
import configchangesocket
import ipaddress
import json
import logging
import secrets
import socket
import urllib.parse
import yaml

from ops.charm import CharmBase, CollectStatusEvent, InstallEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation
from pathlib import Path
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    METRICS_USERNAME_KEY = "metrics-username"
    METRICS_PASSWORD_KEY = "metrics-password"
    METRICS_SOCKET_PATH = '/var/lib/juju/control.socket'
    CONFIG_SOCKET_PATH = '/var/lib/juju/configchange.socket'
    DB_BIND_ADDR_KEY = 'db-bind-address'
    ALL_BIND_ADDRS_KEY = 'db-bind-addresses'
    AGENT_ID_KEY = 'agent-id'

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._stored.set_default(
            last_bind_addresses=[],
            tracing_endpoints={},
            ca_cert=None,
        )

        # TODO (manadart 2024-03-05): Get these at need.
        # No need to instantiate them for every invocation.
        self._control_socket = controlsocket.ControlSocketClient(
            socket_path=self.METRICS_SOCKET_PATH)
        self._config_change_socket = configchangesocket.ConfigChangeSocketClient(
            socket_path=self.CONFIG_SOCKET_PATH)

        self._observe()

    def _observe(self):
        """Set up all framework event observers."""
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.leader_elected, self._on_metrics_reconcile)
        self.framework.observe(self.on.upgrade_charm, self._on_metrics_reconcile)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)
        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_changed, self._on_metrics_reconcile)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)
        self.framework.observe(
            self.on.dbcluster_relation_changed, self._on_dbcluster_relation_changed)
        self.framework.observe(
            self.on.dbcluster_relation_departed, self._on_dbcluster_relation_departed)
        self.framework.observe(
            self.on.charm_tracing_relation_created, self._on_tracing_relation_created)
        self.framework.observe(
            self.on.charm_tracing_relation_changed, self._on_tracing_relation_changed)
        self.framework.observe(
            self.on.charm_tracing_relation_broken, self._on_tracing_relation_removed)
        self.framework.observe(
            self.on.charm_tracing_ca_cert_relation_created,
            self._on_certificate_relation_created)
        self.framework.observe(
            self.on.charm_tracing_ca_cert_relation_changed,
            self._on_certificate_relation_changed)
        self.framework.observe(
            self.on.charm_tracing_ca_cert_relation_broken,
            self._on_receive_ca_cert_removed)
        self.framework.observe(self.on.update_status, self._on_metrics_refresh)

    def _on_install(self, event: InstallEvent):
        """Ensure that the controller configuration file exists."""
        file_path = self._controller_config_path()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        open(file_path, 'w+').close()

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

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
        logger.info("got a new website relation: %r", event)
        port = self.api_port()
        if port is None:
            logger.error("machine does not appear to be a controller")
            self.unit.status = BlockedStatus('machine does not appear to be a controller')
            return

        address = None
        binding = self.model.get_binding(event.relation)
        if binding:
            address = binding.network.ingress_address
            if self.unit.is_leader():
                event.relation.data[self.unit].update({
                    'hostname': str(address),
                    'private-address': str(address),
                    'port': str(port)
                })

    def _metrics_credentials(self, relations):
        for relation in relations:
            data = relation.data[self.app]
            username = data.get(self.METRICS_USERNAME_KEY)
            password = data.get(self.METRICS_PASSWORD_KEY)
            if username and password:
                return username, password

            try:
                jobs = json.loads(data.get("scrape_jobs", "[]"))
                basic_auth = jobs[0]["basic_auth"]
                username = basic_auth["username"]
                # Use removeprefix once Python 3.8 support is dropped.
                if username.startswith("user-"):
                    username = username[len("user-"):]
                return username, basic_auth["password"]
            except (IndexError, KeyError, TypeError, ValueError):
                continue
        return None

    def _metrics_jobs(self, username, password):
        try:
            api_port = self.api_port()
        except AgentConfException as e:
            self.unit.status = BlockedStatus(
                f"can't read controller API port from agent.conf: {e}")
            logger.error('cannot read controller API port from agent configuration: %s', e)
            return None
        return [{
            "metrics_path": "/introspection/metrics",
            "scheme": "https",
            "static_configs": [{"targets": [f"*:{api_port}"]}],
            "basic_auth": {
                "username": f"user-{username}",
                "password": password,
            },
            "tls_config": {
                "ca_file": self.ca_cert(),
                "server_name": "juju-apiserver",
            },
        }]

    def _configure_metrics_endpoint(self, username, password):
        jobs = self._metrics_jobs(username, password)
        if jobs is None:
            return
        self._set_metrics_scrape_data(
            self.model.relations["metrics-endpoint"], jobs=jobs)

    def _configure_metrics_as_unit(self):
        self._set_metrics_scrape_data(
            self.model.relations["metrics-endpoint"], jobs=None)

    def _set_metrics_scrape_data(self, relations, jobs: Optional[List[dict]]):
        """Publish the prometheus_scrape relation data without the COSL-backed library."""
        for relation in relations:
            address, fqdn = self._metrics_unit_address(relation)
            relation.data[self.unit].update({
                "prometheus_scrape_unit_address": address,
                "prometheus_scrape_unit_path": "",
                "prometheus_scrape_unit_name": self.unit.name,
                "prometheus_scrape_unit_fqdn": fqdn,
            })

        if not self.unit.is_leader() or jobs is None:
            return

        metadata = json.dumps(self._prometheus_scrape_metadata(), sort_keys=True)
        scrape_jobs = json.dumps(jobs, sort_keys=True)
        for relation in relations:
            relation.data[self.app].update({
                "scrape_metadata": metadata,
                "scrape_jobs": scrape_jobs,
                "alert_rules": json.dumps({}),
            })

    def _metrics_unit_address(self, relation: Relation):
        binding = self.model.get_binding(relation)
        network = getattr(binding, "network", None)
        address = getattr(network, "bind_address", None)
        if address and self._is_valid_address(str(address)):
            return str(address), socket.getfqdn()

        fqdn = socket.getfqdn()
        return fqdn, fqdn

    def _is_valid_address(self, address: str) -> bool:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return False
        return True

    def _prometheus_scrape_metadata(self) -> dict:
        return {
            "model": self.model.name,
            "model_uuid": str(self.model.uuid),
            "application": self.app.name,
            "unit": self.unit.name,
            "charm_name": self.meta.name,
        }

    def _remove_metrics_user(self, username):
        try:
            self._control_socket.remove_metrics_user(username)
        except controlsocket.APIError as e:
            if e.code != 404:
                raise

    def _ensure_metrics_user(self, username, password):
        try:
            self._control_socket.add_metrics_user(username, password)
        except controlsocket.APIError as e:
            if e.code != 409:
                raise
            self._remove_metrics_user(username)
            self._control_socket.add_metrics_user(username, password)

    def _reconcile_metrics_as_leader(self, relations):
        credentials = self._metrics_credentials(relations)
        if credentials is None:
            # One scrape job is published to every metrics-endpoint relation,
            # so all Prometheus applications share one controller user. The
            # oldest relation only seeds its name.
            username = metrics_username(min(relations, key=lambda r: r.id))
            password = generate_password()
        else:
            username, password = credentials

        for relation in relations:
            relation.data[self.app].update({
                self.METRICS_USERNAME_KEY: username,
                self.METRICS_PASSWORD_KEY: password,
            })
        self._ensure_metrics_user(username, password)
        for relation in relations:
            old_username = metrics_username(relation)
            if old_username != username:
                self._remove_metrics_user(old_username)
        self._configure_metrics_endpoint(username, password)

    def _reconcile_metrics(self, relations):
        if not relations:
            return False
        if self.unit.is_leader():
            self._reconcile_metrics_as_leader(relations)
        else:
            self._configure_metrics_as_unit()
        return True

    def _on_metrics_endpoint_relation_created(self, event):
        relations = self.model.relations["metrics-endpoint"]
        if not self._reconcile_metrics(relations):
            event.defer()

    def _on_metrics_reconcile(self, _event):
        self._reconcile_metrics(self.model.relations["metrics-endpoint"])

    def _on_metrics_refresh(self, _event):
        relations = self.model.relations["metrics-endpoint"]
        if not relations:
            return

        jobs = None
        if self.unit.is_leader():
            credentials = self._metrics_credentials(relations)
            if credentials:
                jobs = self._metrics_jobs(*credentials)
        self._set_metrics_scrape_data(relations, jobs)

    def _on_metrics_endpoint_relation_broken(self, event):
        relations = [
            relation for relation in self.model.relations["metrics-endpoint"]
            if relation.id != event.relation.id
        ]
        credentials = self._metrics_credentials(
            [event.relation] + relations
        )
        if relations:
            self._reconcile_metrics(relations)
            if self.unit.is_leader() and credentials:
                old_username = metrics_username(event.relation)
                if old_username != credentials[0]:
                    self._remove_metrics_user(old_username)
            return

        if not self.unit.is_leader():
            return
        usernames = {metrics_username(event.relation)}
        if credentials:
            usernames.add(credentials[0])
        for username in usernames:
            self._remove_metrics_user(username)

    def _on_dbcluster_relation_changed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _on_dbcluster_relation_departed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _on_tracing_relation_created(self, event):
        self._request_tracing_protocols(event.relation)

    def _request_tracing_protocols(self, relation: Relation):
        if self.unit.is_leader():
            relation.data[self.app]["receivers"] = json.dumps(["otlp_http", "otlp_grpc"])

    def _on_tracing_relation_changed(self, event):
        self._request_tracing_protocols(event.relation)
        endpoints = self._tracing_endpoints(event.relation)
        if not endpoints:
            if self._stored.tracing_endpoints:
                self._on_tracing_relation_removed(event)
            return

        self._stored.tracing_endpoints = endpoints
        logger.info("tracing endpoints updated: %s", self._stored.tracing_endpoints)
        self._update_charm_tracing_config()

    def _on_tracing_relation_removed(self, event):
        self._stored.tracing_endpoints = {}
        logger.info("tracing endpoints cleared")
        self._update_charm_tracing_config()

    def _tracing_endpoints(self, relation: Relation) -> Optional[dict]:
        if not relation.app:
            return None

        try:
            receivers = json.loads(relation.data[relation.app].get("receivers", "[]"))
        except (json.JSONDecodeError, TypeError):
            logger.info("failed parsing tracing receivers for relation %s", relation.id)
            return None

        if not isinstance(receivers, list):
            return None

        endpoints = {}
        for receiver in receivers:
            if not isinstance(receiver, dict):
                continue

            protocol = receiver.get("protocol")
            name = protocol.get("name") if isinstance(protocol, dict) else protocol
            url = receiver.get("url")
            if name in ("otlp_grpc", "otlp_http") and isinstance(url, str):
                endpoints[name] = url

        return endpoints or None

    def _on_certificate_relation_created(self, event):
        if self.unit.is_leader():
            event.relation.data[self.app]["version"] = json.dumps(1)

    def _on_certificate_relation_changed(self, event):
        ca_list = self._certificates_from_relation(event.relation)
        if not ca_list:
            return

        self._stored.ca_cert = '\n'.join(sorted(ca_list))
        logger.info("CA certificate updated from relation id %s", event.relation.id)
        self._update_charm_tracing_config()

    def _certificates_from_relation(self, relation: Relation) -> Set[str]:
        if relation.app:
            certificates = self._json_string_set(
                relation.data[relation.app].get("certificates"))
            if certificates:
                return certificates

        for unit in relation.units:
            certificates = self._json_string_set(relation.data[unit].get("chain"))
            if certificates:
                return certificates

        return set()

    def _json_string_set(self, value: Optional[str]) -> Set[str]:
        if not value:
            return set()

        try:
            data = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return set()

        if not isinstance(data, list):
            return set()

        return {item for item in data if isinstance(item, str)}

    def _on_receive_ca_cert_removed(self, event):
        self._stored.ca_cert = None
        logger.info("CA certificate removed from relation id %s", event.relation.id)
        self._update_charm_tracing_config()

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

    def _update_charm_tracing_config(self):
        """Update charm configuration with current tracing endpoint and CA cert information."""
        self._control_socket.set_charm_tracing_config(
            grpc_endpoint=(
                self._stored.tracing_endpoints["otlp_grpc"]
                if "otlp_grpc" in self._stored.tracing_endpoints
                else None
            ),
            http_endpoint=(
                self._stored.tracing_endpoints["otlp_http"]
                if "otlp_http" in self._stored.tracing_endpoints
                else None
            ),
            ca_cert=self._stored.ca_cert,
        )


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


class ControllerProcessException(Exception):
    """Raised when there are errors regarding detection of controller service or process."""


class DBBindAddressException(Exception):
    """Raised when there are errors regarding the database bind addresses"""


if __name__ == "__main__":
    main(JujuControllerCharm)
