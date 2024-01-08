#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import controlsocket
import logging
import secrets
import urllib.parse
import yaml

from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import StoredState
from ops.charm import RelationJoinedEvent, RelationDepartedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ErrorStatus, Relation
from typing import List

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)

        self._stored.set_default(db_bind_address='')
        self._stored.set_default(last_bind_addresses=[])
        self.framework.observe(
            self.on.dbcluster_relation_changed, self._on_dbcluster_relation_changed)

        self.control_socket = controlsocket.Client(
            socket_path='/var/lib/juju/control.socket')
        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)

    def _on_collect_status(self, event: CollectStatusEvent):
        if len(self._stored.last_bind_addresses) > 1:
            event.add_status(BlockedStatus(
                'multiple possible DB bind addresses; set a suitable dbcluster network binding'))

        try:
            self.api_port()
        except AgentConfException as e:
            event.add_status(ErrorStatus(
                f"cannot read controller API port from agent configuration: {e}"))

        event.add_status(ActiveStatus())

    def _on_config_changed(self, _):
        controller_url = self.config['controller-url']
        logger.info("got a new controller-url: %r", controller_url)

    def _on_dashboard_relation_joined(self, event):
        logger.info("got a new dashboard relation: %r", event)
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
            logger.error("cannot read controller API port from agent configuration: {}", e)
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
            logger.error("cannot read controller API port from agent configuration: {}", e)
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
        ips = self.model.get_binding(event.relation).network.ingress_addresses
        self._stored.last_bind_addresses = ips

        if len(ips) > 1:
            logger.error(
                'multiple possible DB bind addresses; set a suitable bcluster network binding')
            return

        ip = str(ips[0])
        if self._stored.db_bind_address == ip:
            return

        self._stored.db_bind_address = ip
        event.relation.data[self.unit].update({'db-bind-address': ip})

    def api_port(self) -> str:
        """Return the port on which the controller API server is listening."""
        api_addresses = self._agent_conf('apiaddresses')
        if not api_addresses:
            raise AgentConfException("agent.conf key 'apiaddresses' missing")
        if not isinstance(api_addresses, List):
            raise AgentConfException("agent.conf key 'apiaddresses' is not a list")

        parsed_url = urllib.parse.urlsplit('//' + api_addresses[0])
        if not parsed_url.port:
            raise AgentConfException("API address does not include port")
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
    """Raised when there are errors reading info from agent.conf."""


if __name__ == "__main__":
    main(JujuControllerCharm)
