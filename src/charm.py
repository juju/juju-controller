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
from unixsocket import APIError

from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.s3 import CredentialsChangedEvent, S3Requirer
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import StoredState
from ops.charm import InstallEvent, LeaderElectedEvent, RelationJoinedEvent, RelationDepartedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, Relation
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    METRICS_SOCKET_PATH = '/var/snap/jujud/common/sockets/control.socket'
    CONFIG_SOCKET_PATH = '/var/snap/jujud/common/sockets/configchange.socket'
    DB_BIND_ADDR_KEY = 'db-bind-address'
    ALL_BIND_ADDRS_KEY = 'db-bind-addresses'
    AGENT_ID_KEY = 'agent-id'

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self.charm_tracing_requirer = TracingEndpointRequirer(
            self,
            protocols=["otlp_http", "otlp_grpc"],
            relation_name='charm-tracing'
        )
        self.charm_certificate_transfer = CertificateTransferRequires(
            self, relationship_name='charm-tracing-ca-cert'
        )
        self.workload_tracing_requirer = TracingEndpointRequirer(
            self,
            protocols=["otlp_http", "otlp_grpc"],
            relation_name='workload-tracing'
        )
        self.workload_certificate_transfer = CertificateTransferRequires(
            self, relationship_name='workload-tracing-ca-cert'
        )
        self._s3 = S3Requirer(self, "s3-backend")
        self._loki_consumer = LokiPushApiConsumer(self, "loki-push-api")
        self.loki_certificate_transfer = CertificateTransferRequires(
            self, relationship_name="loki-push-api-ca-cert"
        )

        self._stored.set_default(
            last_bind_addresses=[],
            tracing_status_error=None,
            workload_tracing_status_error=None,
            s3_status_error=None,
            s3_status_pending=False,
            loki_status_error=None,
            loki_endpoint_seen=False,
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
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        # Dashboard and website relation events are observed to set relation
        # data for the dashboard and website charms, so that they can connect to
        # the controller API and display the correct information about the
        # controller.
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)

        # Metrics endpoint relation events are observed to manage users for the
        # metrics endpoint, and to maintain the correct scrape configuration for
        # the controller API in the Prometheus scrape config provided to related
        # Prometheus charms.
        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)

        # DB cluster relation events are observed to maintain the current set of
        # bind addresses for the controller cluster in the charm's stored state,
        # and to apply it to the charm configuration when it changes.
        self.framework.observe(
            self.on.dbcluster_relation_changed, self._on_dbcluster_relation_changed)
        self.framework.observe(
            self.on.dbcluster_relation_departed, self._on_dbcluster_relation_departed)

        # Tracing relation events are observed to maintain the current tracing
        # endpoint information in the charm's stored state, and to apply it to
        # the charm configuration when it changes.
        self.framework.observe(
            self.charm_tracing_requirer.on.endpoint_changed, self._on_tracing_relation_changed)
        self.framework.observe(
            self.charm_tracing_requirer.on.endpoint_removed, self._on_tracing_relation_removed)
        self.framework.observe(
            self.charm_certificate_transfer.on.certificate_set_updated,
            self._on_receive_ca_cert_updated,
        )
        self.framework.observe(
            self.charm_certificate_transfer.on.certificates_removed,
            self._on_receive_ca_cert_removed,
        )
        self.framework.observe(
            self.workload_tracing_requirer.on.endpoint_changed,
            self._on_workload_tracing_relation_changed,
        )
        self.framework.observe(
            self.workload_tracing_requirer.on.endpoint_removed,
            self._on_workload_tracing_relation_removed,
        )
        self.framework.observe(
            self.workload_certificate_transfer.on.certificate_set_updated,
            self._on_receive_workload_ca_cert_updated,
        )
        self.framework.observe(
            self.workload_certificate_transfer.on.certificates_removed,
            self._on_receive_workload_ca_cert_removed,
        )
        # S3 credential events are observed to maintain the current S3
        # credentials in the charm's stored state, and to apply them via the
        # control socket when they change.
        self.framework.observe(
            self._s3.on.credentials_changed, self._on_s3_credentials_changed)
        self.framework.observe(
            self._s3.on.credentials_gone,
            self._on_s3_credentials_gone)

        # Loki Push API events are observed to maintain the correct controller
        # API port in the config file, which is needed for Loki to push logs to
        # the correct place.
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_joined,
            self._on_loki_push_api_endpoint_joined)
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_departed,
            self._on_loki_push_api_endpoint_departed)
        self.framework.observe(
            self.loki_certificate_transfer.on.certificate_set_updated,
            self._on_receive_loki_ca_cert_updated,
        )
        self.framework.observe(
            self.loki_certificate_transfer.on.certificates_removed,
            self._on_receive_loki_ca_cert_removed,
        )

    def _on_install(self, event: InstallEvent):
        """Ensure that the controller configuration file exists."""
        file_path = self._controller_config_path()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        open(file_path, 'w+').close()

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_leader_elected(self, _event: LeaderElectedEvent):
        self._update_charm_tracing_config()
        self._update_workload_tracing_config()
        self._reconcile_loki_endpoint()

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
        self._stored.s3_status_pending = True

        try:
            logger.info("reapplying S3 credentials after leadership change")
            self._control_socket.add_s3_credentials(credentials)
            self._stored.s3_status_error = None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to reapply S3 credentials after leadership change: %s", exc)
            self._stored.s3_status_pending = False
            self._stored.s3_status_error = "failed to reapply s3 credentials"

    def _on_collect_status(self, event: CollectStatusEvent):
        has_blocking_status = False
        if len(self._stored.last_bind_addresses) > 1:
            event.add_status(BlockedStatus(
                'multiple possible DB bind addresses; set a suitable dbcluster network binding'))
            has_blocking_status = True

        try:
            self.api_port()
        except AgentConfException as e:
            event.add_status(BlockedStatus(
                f'cannot read controller API port from agent configuration: {e}'))
            has_blocking_status = True

        if self._stored.tracing_status_error:
            event.add_status(BlockedStatus(self._stored.tracing_status_error))
            has_blocking_status = True

        if self._stored.workload_tracing_status_error:
            event.add_status(BlockedStatus(self._stored.workload_tracing_status_error))
            has_blocking_status = True

        if self._stored.s3_status_error:
            event.add_status(BlockedStatus(self._stored.s3_status_error))
            has_blocking_status = True

        if self._stored.loki_status_error:
            event.add_status(BlockedStatus(self._stored.loki_status_error))
            has_blocking_status = True

        if self._stored.s3_status_pending:
            if not has_blocking_status:
                event.add_status(MaintenanceStatus("applying s3 credentials"))
            self._stored.s3_status_pending = False
            return

        if not has_blocking_status:
            event.add_status(ActiveStatus())

    def _on_config_changed(self, _):
        controller_url = self.config['controller-url']
        logger.info('got a new controller-url: %r', controller_url)
        self._update_workload_tracing_config()

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
        if not self.charm_tracing_requirer.is_ready(event.relation):
            return

        endpoints = {
            "otlp_grpc": self.charm_tracing_requirer.get_endpoint("otlp_grpc", event.relation),
            "otlp_http": self.charm_tracing_requirer.get_endpoint("otlp_http", event.relation),
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

    def _on_workload_tracing_relation_changed(self, event):
        if not self.workload_tracing_requirer.is_ready(event.relation):
            return

        endpoints = {
            "otlp_grpc": self.workload_tracing_requirer.get_endpoint(
                "otlp_grpc", event.relation
            ),
            "otlp_http": self.workload_tracing_requirer.get_endpoint(
                "otlp_http", event.relation
            ),
        }
        logger.info("workload tracing endpoints updated: %s", endpoints)
        self._update_workload_tracing_config(allow_endpoint_only=True)

    def _on_workload_tracing_relation_removed(self, event):
        logger.info("workload tracing endpoints cleared")
        self._update_workload_tracing_config(allow_endpoint_only=True)

    def _on_receive_workload_ca_cert_updated(self, event):
        ca_list = event.certificates
        if not ca_list:
            return

        logger.info("workload CA certificate updated from relation id %s", event.relation_id)
        self._update_workload_tracing_config(allow_endpoint_only=True)

    def _on_receive_workload_ca_cert_removed(self, event):
        logger.info("workload CA certificate removed from relation id %s", event.relation_id)
        self._update_workload_tracing_config(allow_endpoint_only=True)

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
        api_addresses = self._controller_runtime_config('api-addresses')
        if not api_addresses:
            raise AgentConfException("runtime.conf key 'api-addresses' missing")
        if not isinstance(api_addresses, List):
            raise AgentConfException("runtime.conf key 'api-addresses' is not a list")

        parsed_url = urllib.parse.urlsplit('//' + api_addresses[0])
        if not parsed_url.port:
            raise AgentConfException('API address does not include port')
        return parsed_url.port

    def ca_cert(self) -> str:
        """Return the controller's CA certificate."""
        return self._controller_runtime_config('ca-cert')

    def _controller_runtime_config(self, key: str):
        """Read a value (by key) from the runtime.conf file on disk.

        The runtime.conf is read from the snap's current revision symlink
        (/var/snap/jujud/current). During snap refresh, snapd atomically
        updates this symlink, so the path may be briefly unavailable or
        point to a stale directory if the refresh is in progress. This
        edge case is acceptable for Phase 1 and will be revisited when
        snap refresh semantics are addressed.
        """
        runtime_conf_path = '/var/snap/jujud/current/agents/controller-0/runtime.conf'

        with open(runtime_conf_path) as runtime_conf_file:
            runtime_conf = yaml.safe_load(runtime_conf_file)
            return runtime_conf.get(key)

    def _controller_config_path(self) -> str:
        """Interrogate the running controller jujud service to determine
        the local controller ID, then use it to construct a config path.
        """
        controller_id = self._controller_agent_id()
        return f'/var/snap/jujud/common/agents/controller-{controller_id}/controller.conf'

    def _controller_agent_id(self):
        return self._config_change_socket.get_controller_agent_id()

    def _request_config_reload(self):
        """Send a reload request to the config reload socket."""
        self._config_change_socket.reload_config()

    @staticmethod
    def _endpoint_requires_ca_cert(endpoint: Optional[str]) -> bool:
        return bool(endpoint) and endpoint.startswith(("https://", "grpcs://"))

    def _current_tracing_config(
        self,
        tracing_requirer: TracingEndpointRequirer,
        certificate_transfer: CertificateTransferRequires,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        grpc_endpoint: Optional[str] = None
        http_endpoint: Optional[str] = None

        tracing_data = tracing_requirer.get_all_endpoints()
        if tracing_data:
            for receiver in tracing_data.receivers:
                if receiver.protocol.name == "otlp_grpc" and grpc_endpoint is None:
                    grpc_endpoint = receiver.url
                if receiver.protocol.name == "otlp_http" and http_endpoint is None:
                    http_endpoint = receiver.url

        return grpc_endpoint, http_endpoint, self._current_ca_cert(certificate_transfer)

    def _current_ca_cert(
        self, certificate_transfer: CertificateTransferRequires
    ) -> Optional[str]:
        certificates = certificate_transfer.get_all_certificates()
        return "\n".join(sorted(certificates)) if certificates else None

    def _current_charm_tracing_config(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        return self._current_tracing_config(
            tracing_requirer=self.charm_tracing_requirer,
            certificate_transfer=self.charm_certificate_transfer,
        )

    def _current_workload_tracing_config(
        self,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        return self._current_tracing_config(
            tracing_requirer=self.workload_tracing_requirer,
            certificate_transfer=self.workload_certificate_transfer,
        )

    def _validate_open_telemetry_sample_ratio(self, sample_ratio: float):
        if sample_ratio < 0 or sample_ratio > 1:
            raise ValueError(
                "invalid workload-tracing-sample-ratio: must be between 0 and 1"
            )

    def _current_open_telemetry_config(self) -> Tuple[bool, float, str, bool]:
        sample_ratio = float(self.config["workload-tracing-sample-ratio"])
        self._validate_open_telemetry_sample_ratio(sample_ratio)
        return (
            self.config["workload-tracing-stack-traces"],
            sample_ratio,
            self.config["workload-tracing-tail-sampling-threshold"],
            self.config["workload-tracing-insecure-skip-verify"],
        )

    def _update_charm_tracing_config(self):
        """Update charm configuration with current tracing endpoint and CA cert information."""
        if not self.unit.is_leader():
            return

        grpc_endpoint, http_endpoint, ca_cert = self._current_charm_tracing_config()
        if (
            any(
                self._endpoint_requires_ca_cert(endpoint)
                for endpoint in (grpc_endpoint, http_endpoint)
            ) and not ca_cert
        ):
            self._stored.tracing_status_error = (
                "charm tracing endpoint requires a CA cert, but none is available"
            )
            self.unit.status = BlockedStatus(self._stored.tracing_status_error)
            return

        try:
            self._control_socket.set_charm_tracing_config(
                grpc_endpoint=grpc_endpoint,
                http_endpoint=http_endpoint,
                ca_cert=ca_cert,
            )
            self._stored.tracing_status_error = None
        except Exception as exc:
            logger.error("failed to set charm tracing config: %s", exc)
            self._stored.tracing_status_error = "failed to set charm tracing config"

    def _update_workload_tracing_config(self, allow_endpoint_only=False):
        """Update workload tracing configuration with current endpoint and CA cert information."""
        if not self.unit.is_leader():
            return

        grpc_endpoint, http_endpoint, ca_cert = self._current_workload_tracing_config()
        open_telemetry_config = {}
        had_invalid_open_telemetry_config = False
        insecure_skip_verify = False
        try:
            (
                open_telemetry_stack_traces,
                open_telemetry_sample_ratio,
                open_telemetry_tail_sampling_threshold,
                insecure_skip_verify,
            ) = self._current_open_telemetry_config()
            open_telemetry_config = {
                "stack_traces": open_telemetry_stack_traces,
                "sample_ratio": open_telemetry_sample_ratio,
                "tail_sampling_threshold": open_telemetry_tail_sampling_threshold,
                "insecure_skip_verify": insecure_skip_verify,
            }
        except ValueError as exc:
            logger.error("%s", exc)
            self._stored.workload_tracing_status_error = str(exc)
            had_invalid_open_telemetry_config = True
            if not allow_endpoint_only:
                return

        if (
            any(
                self._endpoint_requires_ca_cert(endpoint)
                for endpoint in (grpc_endpoint, http_endpoint)
            ) and not ca_cert and not insecure_skip_verify
        ):
            if not had_invalid_open_telemetry_config:
                self._stored.workload_tracing_status_error = (
                    "workload tracing endpoint requires a CA cert, but none is available"
                )
            self.unit.status = BlockedStatus(self._stored.workload_tracing_status_error)
            return

        try:
            self._control_socket.set_workload_tracing_config(
                grpc_endpoint=grpc_endpoint,
                http_endpoint=http_endpoint,
                ca_cert=ca_cert,
                **open_telemetry_config,
            )
            if open_telemetry_config:
                self._stored.workload_tracing_status_error = None
        except Exception as exc:
            logger.error("failed to set workload tracing config: %s", exc)
            self._stored.workload_tracing_status_error = "failed to set workload tracing config"

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

        if not self.unit.is_leader():
            return

        self._stored.s3_status_pending = True
        try:
            logger.info("applying new S3 credentials")
            self._control_socket.add_s3_credentials(credentials)
            self._stored.s3_status_error = None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to apply S3 credentials: %s", exc)
            self._stored.s3_status_pending = False
            self._stored.s3_status_error = "failed to apply s3 credentials"

    def _on_s3_credentials_gone(self, _event):
        """Handle removal of S3 credentials."""
        if not self.unit.is_leader():
            return

        try:
            self._control_socket.remove_s3_credentials()
            self._stored.s3_status_error = None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to remove S3 credentials: %s", exc)
            self._stored.s3_status_error = "failed to remove s3 credentials"

    def _on_loki_push_api_endpoint_joined(self, _event):
        """Handle new or updated Loki push API endpoint."""
        self._stored.loki_endpoint_seen = bool(self.model.relations["loki-push-api"])
        self._reconcile_loki_endpoint(report_applying_status=True)

    def _on_loki_push_api_endpoint_departed(self, _event):
        """Handle removal of Loki push API endpoint."""
        self._reconcile_loki_endpoint()

    def _on_receive_loki_ca_cert_updated(self, event):
        ca_list = event.certificates
        if not ca_list:
            return

        logger.info("Loki CA certificate updated from relation id %s", event.relation_id)
        self._stored.loki_endpoint_seen = True
        self._reconcile_loki_endpoint(report_applying_status=True)

    def _on_receive_loki_ca_cert_removed(self, event):
        logger.info("Loki CA certificate removed from relation id %s", event.relation_id)
        self._reconcile_loki_endpoint()

    def _current_loki_endpoint(self) -> Optional[dict]:
        endpoints = self._loki_consumer.loki_endpoints
        if not endpoints:
            self._stored.loki_status_error = None
            return None
        endpoint = endpoints[0]["url"]
        ca_cert = self._current_ca_cert(self.loki_certificate_transfer)
        insecure_skip_verify = self.config["loki-insecure-skip-verify"]

        if self._endpoint_requires_ca_cert(endpoint) and (
            not ca_cert and not insecure_skip_verify
        ):
            self._stored.loki_status_error = (
                "loki endpoint requires a CA cert, but none is available"
            )
            self.unit.status = BlockedStatus(self._stored.loki_status_error)
            return None

        self._stored.loki_status_error = None
        return {
            "url": endpoint,
            "ca_cert": ca_cert,
            "insecure_skip_verify": insecure_skip_verify,
            "org_id": self.config["loki-org-id"],
        }

    def _reconcile_loki_endpoint(self, report_applying_status: bool = False):
        if not self.unit.is_leader():
            return

        endpoint = self._current_loki_endpoint()
        if endpoint:
            try:
                logger.info("applying Loki push API endpoint")
                self._control_socket.set_loki_endpoint(endpoint)
                self._stored.loki_status_error = None
                if report_applying_status:
                    self.unit.status = MaintenanceStatus("applying loki endpoint")
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("failed to apply Loki endpoint: %s", exc)
                self._stored.loki_status_error = "failed to apply loki endpoint"
                self.unit.status = BlockedStatus(self._stored.loki_status_error)
            return

        if self._stored.loki_status_error:
            return

        if not self._stored.loki_endpoint_seen:
            return

        try:
            self._control_socket.remove_loki_endpoint()
            self._stored.loki_status_error = None
            self._stored.loki_endpoint_seen = False
        except APIError as exc:
            if exc.code == 404:
                self._stored.loki_status_error = None
                self._stored.loki_endpoint_seen = False
                return
            logger.error("failed to remove Loki endpoint: %s", exc)
            self._stored.loki_status_error = "failed to remove loki endpoint"
            self.unit.status = BlockedStatus(self._stored.loki_status_error)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("failed to remove Loki endpoint: %s", exc)
            self._stored.loki_status_error = "failed to remove loki endpoint"
            self.unit.status = BlockedStatus(self._stored.loki_status_error)


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
