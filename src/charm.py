#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging
import os
import yaml

from charmhelpers.core import hookenv
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus
from ops.framework import StoredState

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

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, _):
        controller_url = self.config["controller-url"]
        logger.info("got a new controller-url: %r", controller_url)

    def _on_dashboard_relation_joined(self, event):
        logger.info("got a new dashboard relation: %r", event)
        if not self.model.relations:
            return
        for relation in self.model.relations['dashboard']:
            relation.data[self.app]['controller-url'] = self.config['controller-url']
            relation.data[self.app]['identity-provider-url'] = self.config['identity-provider-url']
            relation.data[self.app]['is-juju'] = str(self.config['is-juju'])

    def _on_website_relation_joined(self, event):
        """Connect a website relation."""
        logger.info("got a new website relation: %r", event)
        port = api_port()
        if port is None:
            logger.error("machine does not appear to be a controller")
            self.unit.status = BlockedStatus('machine does not appear to be a controller')
            return

        for relation in self.model.relations['website']:
            ingress_address = hookenv.ingress_address(relation.id, hookenv.local_unit())
            relation.data[self.unit]['hostname'] = ingress_address
            relation.data[self.unit]['private-address'] = ingress_address
            relation.data[self.unit]['port'] = str(port)


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
