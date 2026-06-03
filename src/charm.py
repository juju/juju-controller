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

from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.s3 import CredentialsChangedEvent, S3Requirer
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import StoredState
from ops.charm import InstallEvent, LeaderElectedEvent, RelationJoinedEvent, RelationDepartedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, Relation
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    METRICS_SOCKET_PATH = '/var/lib/juju/control.socket'
    CONFIG_SOCKET_PATH = '/var/lib/juju/configchange.socket'
    DB_BIND_ADDR_KEY = 'db-bind-address'
    ALL_BIND_ADDRS_KEY = 'db-bind-addresses'
    AGENT_ID_KEY = 'agent-id'

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self.tracing_requirer = TracingEndpointRequirer(
            self,
            protocols=["otlp_http", "otlp_grpc"],
            relation_name='charm-tracing'
        )
        self._certificate_transfer = CertificateTransferRequires(
            self, relationship_name='charm-tracing-ca-cert'
        )

        self._stored.set_default(
            last_bind_addresses=[],
            s3_credentials=dict(),
        )

        # TODO (manadart 2024-03-05): Get these at need.
        # No need to instantiate them for every invocation.
        self._control_socket = controlsocket.ControlSocketClient(
            socket_path=self.METRICS_SOCKET_PATH)
        self._config_change_socket = configchangesocket.ConfigChangeSocketClient(
            socket_path=self.CONFIG_SOCKET_PATH)
        self._s3 = S3Requirer(self, "s3-backend")

        self._observe()

    def _observe(self):
        """Set up all framework event observers."""
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
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
        self.framework.observe(
            self.tracing_requirer.on.endpoint_changed, self._on_tracing_relation_changed)
        self.framework.observe(
            self.tracing_requirer.on.endpoint_removed, self._on_tracing_relation_removed)
        self.framework.observe(
            self._certificate_transfer.on.certificate_set_updated,
            self._on_receive_ca_cert_updated,
        )
        self.framework.observe(
            self._certificate_transfer.on.certificates_removed, self._on_receive_ca_cert_removed)
        self.framework.observe(
            self._s3.on.credentials_changed, self._on_s3_credentials_changed)
        self.framework.observe(
            self._s3.on.credentials_gone, self._on_s3_credentials_gone)

    def _on_install(self, event: InstallEvent):
        """Ensure that the controller configuration file exists."""
        file_path = self._controller_config_path()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        open(file_path, 'w+').close()

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_leader_elected(self, _event: LeaderElectedEvent):
        grpc_endpoint, http_endpoint, ca_cert = self._current_tracing_config()
        if grpc_endpoint or http_endpoint or ca_cert:
            self._update_charm_tracing_config()

        # Read current relation data rather than relying on locally cached
        # state. This avoids replaying stale credentials if this unit becomes
        # leader before processing delayed relation events.
        s3_connection_info = self._s3.get_s3_connection_info()
        access_key = s3_connection_info.get("access-key")
        secret_key = s3_connection_info.get("secret-key")
        if not access_key or not secret_key:
            return

        credentials = {
            "access_key": access_key,
            "secret_key": secret_key,
            "endpoint": s3_connection_info.get("endpoint"),
        }
        self._stored.s3_credentials = credentials

        try:
            logger.info("reapplying S3 credentials after leadership change")
            self._control_socket.add_s3_credentials(credentials)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to reapply S3 credentials after leadership change: %s", exc)
            self.unit.status = BlockedStatus("failed to reapply s3 credentials")

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

    def _on_metrics_endpoint_relation_created(self, event: RelationJoinedEvent):
        username = metrics_username(event.relation)
        password = generate_password()
        self._control_socket.add_metrics_user(username, password)

        # Set up Prometheus scrape config
        try:
            api_port = self.api_port()
        except AgentConfException as e:
            self.unit.status = BlockedStatus(
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

    def _on_metrics_endpoint_relation_broken(self, event: RelationDepartedEvent):
        username = metrics_username(event.relation)
        self._control_socket.remove_metrics_user(username)

    def _on_dbcluster_relation_changed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _on_dbcluster_relation_departed(self, event):
        relation = event.relation
        self._update_bind_addresses(relation)

    def _on_tracing_relation_changed(self, event):
        if not self.tracing_requirer.is_ready(event.relation):
            return

        endpoints = {
            "otlp_grpc": self.tracing_requirer.get_endpoint("otlp_grpc", event.relation),
            "otlp_http": self.tracing_requirer.get_endpoint("otlp_http", event.relation),
        }
        logger.info("tracing endpoints updated: %s", endpoints)
        self._update_charm_tracing_config()

    def _on_tracing_relation_removed(self, event):
        logger.info("tracing endpoints cleared")
        self._update_charm_tracing_config()

    def _on_receive_ca_cert_updated(self, event):
        ca_list = event.certificates
        if not ca_list:
            return

        logger.info("CA certificate updated from relation id %s", event.relation_id)
        self._update_charm_tracing_config()

    def _on_receive_ca_cert_removed(self, event):
        logger.info("CA certificate removed from relation id %s", event.relation_id)
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

    def _current_tracing_config(
        self,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        grpc_endpoint: Optional[str] = None
        http_endpoint: Optional[str] = None

        tracing_data = self.tracing_requirer.get_all_endpoints()
        if tracing_data:
            for receiver in tracing_data.receivers:
                if receiver.protocol.name == "otlp_grpc" and grpc_endpoint is None:
                    grpc_endpoint = receiver.url
                if receiver.protocol.name == "otlp_http" and http_endpoint is None:
                    http_endpoint = receiver.url

        certificates = self._certificate_transfer.get_all_certificates()
        ca_cert = "\n".join(sorted(certificates)) if certificates else None
        return grpc_endpoint, http_endpoint, ca_cert

    def _update_charm_tracing_config(self):
        """Update charm configuration with current tracing endpoint and CA cert information."""
        if not self.unit.is_leader():
            return

        grpc_endpoint, http_endpoint, ca_cert = self._current_tracing_config()
        try:
            self._control_socket.set_charm_tracing_config(
                grpc_endpoint=grpc_endpoint,
                http_endpoint=http_endpoint,
                ca_cert=ca_cert,
            )
        except Exception as exc:
            logger.error("failed to set charm tracing config: %s", exc)
            self.unit.status = BlockedStatus("failed to set charm tracing config")

    def _on_s3_credentials_changed(self, event: CredentialsChangedEvent):
        """Handle new or updated S3 credentials."""
        # S3Requirer always negotiates a bucket, but right now each controller
        # uses its own Juju-managed bucket. We only need auth and endpoint
        # until we support shared or externally managed buckets.
        credentials = {
            'access_key': event.access_key,
            'secret_key': event.secret_key,
            'endpoint': event.endpoint,
        }
        self._stored.s3_credentials = credentials

        if not self.unit.is_leader():
            return

        try:
            logger.info("applying new S3 credentials")
            self._control_socket.add_s3_credentials(credentials)
            self.unit.status = MaintenanceStatus("applying s3 credentials")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to apply S3 credentials: %s", exc)
            self.unit.status = BlockedStatus("failed to apply s3 credentials")

    def _on_s3_credentials_gone(self, _event):
        """Handle removal of S3 credentials."""
        if not self.unit.is_leader():
            self._stored.s3_credentials = dict()
            return

        try:
            self._control_socket.remove_s3_credentials()
            self._stored.s3_credentials = dict()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to remove S3 credentials: %s", exc)
            self.unit.status = BlockedStatus("failed to remove s3 credentials")


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
