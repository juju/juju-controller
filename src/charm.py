#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging
import os
import secrets
import subprocess
import yaml
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.charm import RelationJoinedEvent, RelationDepartedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation, Unit
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from typing import MutableMapping

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

        self.framework.observe(
            self.on.metrics_endpoint_relation_created, self._on_metrics_endpoint_relation_created)
        self.framework.observe(
            self.on.metrics_endpoint_relation_broken, self._on_metrics_endpoint_relation_broken)

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

    def _on_metrics_endpoint_relation_created(self, event: RelationJoinedEvent):
        # Ensure that user credentials exist to access the metrics endpoint.
        # We've done it this way because it's possible for this hook to run twice.
        logger.info(f'relation data: {event.relation.data[self.unit]}')
        username = metrics_username(event.relation, self.unit)
        password = ensure_metrics_user(username, event.relation.data[self.unit])

        # Set up Prometheus scrape config
        self.metrics_endpoint = MetricsEndpointProvider(self,
            jobs = [{
                # "job_name": "juju",
                "metrics_path": "/introspection/metrics",
                "scheme": "https",
                "static_configs": [{"targets": ["*:17070"]}],
                "basic_auth": {
                    "username": f'user-{username}',
                    "password": password,
                },
                "tls_config": {
                    "ca_file": ca_cert(),
                    "server_name": "juju-apiserver",
                },
            }],
        )
        self.metrics_endpoint.set_scrape_job_spec()
        
    def _on_metrics_endpoint_relation_broken(self, event: RelationDepartedEvent):
        # Remove metrics user
        username = metrics_username(event.relation, self.unit)
        remove_metrics_user(username)
        
        # self.metrics_endpoint.update_scrape_job_spec(self._prometheus_jobs())

    def _prometheus_jobs(self):
        '''
        Generates scrape configs for Prometheus based on the metrics_users
        in stored state.
        '''
        jobs = []
        for username, password in self._stored.metrics_users.items():
            jobs.append({
                "job_name": "juju",
                "metrics_path": "/introspection/metrics",
                "scheme": "https",
                "static_configs": [{"targets": ["*:17070"]}],
                "basic_auth": {
                    "username": f'user-{username}',
                    "password": password,
                },
                "tls_config": {
                    "ca_file": ca_cert(),
                    "server_name": "juju-apiserver",
                },
            })
        return jobs


def _agent_conf(key: str):
    '''
    _agent_conf reads a value from the agent.conf file on disk.
    If the machine does not appear to be a Juju controller, then None is
    returned.
    '''
    # TODO: get the unit number/name from an environment variable?
    path = '/var/lib/juju/agents/unit-controller-0/agent.conf'
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

def metrics_username(relation: Relation, unit: Unit) -> str:
    '''
    metrics_username returns the username used to access the metrics endpoint,
    for the given relation and unit. This username has the form
        juju-metrics-u0-r1
    '''
    unit_number = unit.name.split('/')[1]
    return f'juju-metrics-u{unit_number}-r{relation.id}'

def _introspect(command: str):
    '''
    Runs an introspection command inside the controller machine.
    '''
    try:
        result = subprocess.run(
            f"source /etc/profile.d/juju-introspection.sh && {command}",
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
        )
    except BaseException as e:
        logger.error(f"introspect command failed: {e}", exc_info=1)
    logger.info(f'stdout: {result.stdout}')
    
def _add_metrics_user(username: str, password: str):
    '''
    Runs the following introspection command:
        juju_add_metrics_user <username> <password>
    '''
    logger.info(f'adding metrics user {username}')
    _introspect(f"juju_add_metrics_user {username} {password}")

def ensure_metrics_user(username: str, relation_data: MutableMapping[str, str]) -> str:
    '''
    Ensures a metrics user with the given username exists.
    If the user exists, return their password as stored in relation data.
    If not, create the new user via the introspection endpoint, store their
    password in relation data, and return the new password.
    This function is idempotent.
    ''' 
    metrics_password_key = "metrics_password"

    # Check if user exists in relation data
    if metrics_password_key in relation_data:
        logger.debug(f'metrics user password found in relation data')
        return relation_data[metrics_password_key]
    
    # Create new user
    logger.debug(f'no password found in relation data, creating new metrics user')
    password = secrets.token_urlsafe(16)
    _add_metrics_user(username, password)
    relation_data[metrics_password_key] = password
    return password

def remove_metrics_user(username: str):
    '''
    Runs the following introspection command:
        juju_remove_metrics_user <username>
    '''
    logger.info(f'removing metrics user {username}')
    _introspect(f"juju_remove_metrics_user {username}")

if __name__ == "__main__":
    main(JujuControllerCharm)
