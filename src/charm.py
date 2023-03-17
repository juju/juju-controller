#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging
import os
import secrets

import yaml
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider

logger = logging.getLogger(__name__)


class JujuControllerCharm(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)

        # Set up Prometheus integration
        self.metrics_endpoint = MetricsEndpointProvider(self)
        self.framework.observe(
            self.on.metrics_endpoint_relation_joined, self._on_metrics_endpoint_relation_joined)
        self.framework.observe(
            self.on.metrics_endpoint_relation_departed, self._on_metrics_endpoint_relation_departed)

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, _):
        controller_url = self.config["controller-url"]
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
        logger.info("got a new website relation: %r", event)
        port = api_port()
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

    def _on_metrics_endpoint_relation_joined(self, event):
        # Add new user to access metrics
        username = metrics_username(event.relation)
        password = secrets.token_urlsafe(16)
        # juju add-user juju-metrics-<relation-id>
        # juju change-user-password prometheus
        # juju grant prometheus read controller

        self.metrics_endpoint.update_scrape_job_spec([{
            "job_name": "juju",
            "metrics_path": "/introspection/metrics",
            "scheme": "https",
            "static_configs": [{"targets": ["*:17070"]}],
            "basic_auth": {
                "username": username,
                "password": password,
            },
            "tls_config": {
                "ca_file": ca_cert(),
                "server_name": "juju-apiserver",
            },
        }])
        
    def _on_metrics_endpoint_relation_departed(self, event):
        # Remove metrics user
        username = metrics_username(event.relation)
        remove_user(username)
        self.metrics_endpoint.update_scrape_job_spec(None)


def _agent_conf(key: str):
    '''
    _agent_conf reads a value from the agent.conf file on disk.
    If the machine does not appear to be a Juju controller, then None is
    returned.
    '''
    machine = os.getenv('JUJU_MACHINE_ID')
    if machine is None:
        return None
    path = '/var/lib/juju/agents/machine-{}/agent.conf'.format(machine)
    with open(path) as f:
        params = yaml.safe_load(f)
    return params.get(key)

def api_port() -> str:
    '''
    api_port returns the port on which the controller API server is listening.
    '''
    return _agent_conf('apiport')

def ca_cert() -> str:
    '''
    ca_cert returns the controller's CA certificate.
    '''
    return _agent_conf('cacert')

def metrics_username(relation) -> str:
    '''
    metrics_username returns the username used to access the metrics endpoint,
    for the given relation.
    '''
    return f'juju-metrics-{relation.id}'

if __name__ == "__main__":
    main(JujuControllerCharm)
