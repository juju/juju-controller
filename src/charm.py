#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus
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
            relation.data[self.app]['model-url-template'] = self.config['model-url-template']
            relation.data[self.app]['identity-provider-url'] = self.config['identity-provider-url']
            relation.data[self.app]['is-juju'] = str(self.config['is-juju'])


if __name__ == "__main__":
    main(JujuControllerCharm)
