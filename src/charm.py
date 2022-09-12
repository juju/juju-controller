#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging
import os
import yaml

from charmhelpers.core import hookenv
from loki_push_api import LogProxyConsumer
from ops.charm import CharmBase, PebbleReadyEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ContainerMapping
from ops.framework import StoredState

logger = logging.getLogger(__name__)

LOGGING_RELATION_NAME = 'log-proxy'


class JujuControllerCharm(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self._setup_api_server_container()
 
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(
            self.on.dashboard_relation_joined, self._on_dashboard_relation_joined)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined)

        self._log_proxy = LogProxyConsumer(
            charm=self,
            log_files=['/var/log/juju/logsink.log'],
            relation_name=LOGGING_RELATION_NAME,
            enable_syslog=True,
            container_name='api-server'
        )
        self.framework.observe(
            self._log_proxy.on.promtail_digest_error,
            self._promtail_error,
        )

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, _):
        controller_url = self.config["controller-url"]
        logger.info("got a new controller-url: %r", controller_url)

    def _on_dashboard_relation_joined(self, event):
        logger.info("got a new dashboard relation: %r", event)

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

        ingress_address = hookenv.ingress_address(event.relation.id, hookenv.local_unit())

        event.relation.data[self.unit].update({
            'hostname': ingress_address,
            'private-address': ingress_address,
            'port': str(port)
        })

    def _setup_api_server_container(self):
        """The api-server container is not declared in metadata.yaml, so the
        operator framework does not know about it. We need to manually
        set things up.
        """

        # Reinitialise unit.containers including api-server
        containers = ['api-server']
        for name in iter(self.unit._containers):
            containers.append(name)
        self.unit._containers = ContainerMapping(containers, self.model._backend)

        # Setup Pebble event
        self.on.define_event('api_server_pebble_ready', PebbleReadyEvent)

    def _promtail_error(self, event):
        logger.error(event.message)
        self.unit.status = BlockedStatus(event.message)


def api_port():
    ''' api_port determines the port that the controller's API server is
        listening on.  If the machine does not appear to be a juju
        controller then None is returned.
    '''
    machine = os.getenv('JUJU_MACHINE_ID')
    if machine is None:
        return None
    path = '/var/lib/juju/agents/machine-{}/agent.conf'.format(machine)
    with open(path) as f:
        params = yaml.safe_load(f)
    return params.get('apiport')


if __name__ == "__main__":
    main(JujuControllerCharm)
