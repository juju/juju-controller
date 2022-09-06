#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging
import os
import yaml

from charmhelpers.core import hookenv
from charms.loki_k8s.v0.loki_push_api import LokiPushApiConsumer
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus
from ops.framework import StoredState, EventBase
from subprocess import check_call

logger = logging.getLogger(__name__)

LOGGING_RELATION_NAME = "logging"


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

        # TODO: inside __init__, this will be run on every hook
        # Move somewhere so it's only run once on deploy/install/start
        self._setup_promtail()
        self._loki_consumer = LokiPushApiConsumer(self,
            relation_name=LOGGING_RELATION_NAME)
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_joined,
            self._restart_promtail)
        self.framework.observe(
            self._loki_consumer.on.loki_push_api_endpoint_departed,
            self._restart_promtail)

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

    def _setup_promtail(self):
        # Download promtail binary
        check_call(["curl", "-LO", "https://github.com/grafana/loki/releases/download/v2.6.1/promtail-linux-amd64.zip"])
        check_call(["busybox", "unzip", "promtail-linux-amd64.zip"])
        check_call(["sudo", "mv", "promtail-linux-amd64", "/usr/local/bin/promtail"])
        check_call(["sudo", "mkdir", "-p", "/etc/promtail"])

        # Create promtail service
        svc_file = open("/etc/systemd/system/promtail.service", "w")
        svc_file.write('''[Unit]
Description=Promtail service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/promtail -config.file /etc/promtail/config.yaml

[Install]
WantedBy=multi-user.target
''')
        svc_file.close()
        check_call(["sudo", "systemctl", "daemon-reload"])

        # Start promtail service
        self._restart_promtail()

    def _restart_promtail(self, event: EventBase = None):
        '''Reconfigures and restarts the promtail service when the logging
        relation is changed.
        Assumes the promtail service has already been set up by _setup_promtail
        '''

        # Find client push urls
        endpoints = []
        for relation in self.model.relations[LOGGING_RELATION_NAME]:
            for unit in relation.units:
                ip = relation.data[unit].get("private-address")
                if ip:
                    endpoints.append({'url': f'http://{ip}:3100/loki/api/v1/push'})

        if len(endpoints) == 0:
            # There are no targets, so we can't run Promtail
            # Make sure the Promtail service is stopped
            check_call(["sudo", "systemctl", "stop", "promtail.service"])
        else:
            # Create Promtail config object
            config = self._promtail_base_config()
            config['clients'] = endpoints

            # Write config file
            cfg_file = open("/etc/promtail/config.yaml", "w")
            yaml.dump(config, cfg_file)
            cfg_file.close()

            # Start/restart Promtail
            check_call(["sudo", "systemctl", "restart", "promtail.service"])


    def _promtail_base_config(self):
        '''Returns base configuration for Promtail (to be serialised to yaml)'''
        return {
            'server': {
                'http_listen_port': 9080,
                'grpc_listen_port': 0
            },
            'positions': {
                'filename': '/etc/promtail/positions.yaml'
            },
            # 'clients': to be filled in later
            'scrape_configs': [{
                'job_name': 'varlog',
                'static_configs': [{
                    'labels': {
                        'job': 'varlog',
                        '__path__': '/var/log/*log'
                    }
                }]
            }, {
                'job_name': 'logsink',
                'static_configs': [{
                    'labels': {
                        'job': 'logsink',
                        '__path__': '/var/log/juju/logsink.log'
                    }
                }]
            }]
        }


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
