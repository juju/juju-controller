# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import os
import unittest
from unittest.mock import mock_open, patch

from charm import JujuControllerCharm
from ops.testing import Harness

agent_conf = '''
apiport: 17070
'''


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

    @patch.dict(os.environ, {
        "JUJU_MACHINE_ID": "machine-0",
        "JUJU_UNIT_NAME": "controller/0"
    })
    @patch("ops.model.Model.get_binding")
    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    def test_website_relation_joined(self, open, ingress_address):
        ingress_address.return_value = mockBinding("192.168.1.17")

        harness = Harness(JujuControllerCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        relation_id = harness.add_relation('website', 'haproxy')
        harness.add_relation_unit(relation_id, 'haproxy/0')

        data = harness.get_relation_data(relation_id, 'juju-controller/0')
        self.assertEqual(data["hostname"], "192.168.1.17")
        self.assertEqual(data["private-address"], "192.168.1.17")
        self.assertEqual(data["port"], '17070')


class mockBinding:
    def __init__(self, address):
        self.network = mockNetwork(address)


class mockNetwork:
    def __init__(self, address):
        self.ingress_address = address
