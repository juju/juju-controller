# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import unittest

from ops.testing import Harness
from charm import JujuControllerCharm


class TestCharm(unittest.TestCase):
    def test_config_changed(self):
        harness = Harness(JujuControllerCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        self.assertEqual(list(harness.charm._stored.things), [])
        harness.update_config({"controller-url": "https://controller"})
        self.assertEqual(list(harness.charm._stored.things), ["https://controller"])
