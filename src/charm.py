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
        self._stored.set_default(controller_config=[])

    def _on_start(self, _):
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, _):
        current = self.config["controller-url"]
        if current not in self._stored.controller_config:
            logger.info("got a new controller-url: %r", current)
            self._stored.controller_config.append(current)


if __name__ == "__main__":
    main(JujuControllerCharm)
