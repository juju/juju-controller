# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import unittest

from ops.testing import Harness
from charm import JujuControllerCharm


class TestCharm(unittest.TestCase):
    def test_relation_joined(self):
        harness = Harness(JujuControllerCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.set_leader(True)
        harness.update_config({"controller-url": "wss://controller/api"})
        harness.update_config({"identity-provider-url": ""})
        harness.update_config({"is-juju": "true"})
        relation_id = harness.add_relation('dashboard', 'juju-dashboard')
        harness.add_relation_unit(relation_id, 'juju-dashboard/0')

        data = harness.get_relation_data(relation_id, 'juju-controller')
        self.assertEqual(data["controller-url"], "wss://controller/api")
        self.assertEqual(data["is-juju"], "true")
        self.assertEqual(data.get("identity-provider-url"), None)
