# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import ipaddress
import json
import os
import unittest
from charm import JujuControllerCharm, AgentConfException
from ops.model import BlockedStatus, ActiveStatus, ErrorStatus
from ops.testing import Harness
from unittest.mock import mock_open, patch

agent_conf = '''
apiaddresses:
- localhost:17070
cacert: fake
'''

agent_conf_apiaddresses_missing = '''
cacert: fake
'''

agent_conf_apiaddresses_not_list = '''
apiaddresses:
  foo: bar
cacert: fake
'''

agent_conf_ipv4 = '''
apiaddresses:
- "127.0.0.1:17070"
cacert: fake
'''

agent_conf_ipv6 = '''
apiaddresses:
- "[::1]:17070"
cacert: fake
'''


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(JujuControllerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_dashboard_relation_joined(self):
        harness = self.harness

        harness.set_leader(True)
        harness.update_config({"controller-url": "wss://controller/api"})
        harness.update_config({"identity-provider-url": ""})
        harness.update_config({"is-juju": True})
        relation_id = harness.add_relation('dashboard', 'juju-dashboard')
        harness.add_relation_unit(relation_id, 'juju-dashboard/0')

        data = harness.get_relation_data(relation_id, 'juju-controller')
        self.assertEqual(data["controller-url"], "wss://controller/api")
        self.assertEqual(data["is-juju"], 'True')
        self.assertEqual(data.get("identity-provider-url"), None)

    @patch.dict(os.environ, {
        "JUJU_MACHINE_ID": "machine-0",
        "JUJU_UNIT_NAME": "controller/0"
    })
    @patch("ops.model.Model.get_binding")
    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    def test_website_relation_joined(self, _, binding):
        harness = self.harness
        binding.return_value = mockBinding(["192.168.1.17"])

        harness.set_leader()
        relation_id = harness.add_relation('website', 'haproxy')
        harness.add_relation_unit(relation_id, 'haproxy/0')

        data = harness.get_relation_data(relation_id, 'juju-controller/0')
        self.assertEqual(data["hostname"], "192.168.1.17")
        self.assertEqual(data["private-address"], "192.168.1.17")
        self.assertEqual(data["port"], '17070')

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("charm.MetricsEndpointProvider", autospec=True)
    @patch("charm.generate_password", new=lambda: "passwd")
    @patch("controlsocket.Client.add_metrics_user")
    @patch("controlsocket.Client.remove_metrics_user")
    def test_metrics_endpoint_relation(self, mock_remove_user, mock_add_user,
                                       mock_metrics_provider, _):
        harness = self.harness
        harness.add_network(address="192.168.1.17", endpoint="metrics-endpoint")

        relation_id = harness.add_relation('metrics-endpoint', 'prometheus-k8s')
        mock_add_user.assert_called_once_with(f'juju-metrics-r{relation_id}', 'passwd')

        mock_metrics_provider.assert_called_once_with(
            harness.charm,
            jobs=[{
                "metrics_path": "/introspection/metrics",
                "scheme": "https",
                "static_configs": [{"targets": ["*:17070"]}],
                "basic_auth": {
                    "username": f'user-juju-metrics-r{relation_id}',
                    "password": 'passwd',
                },
                "tls_config": {
                    "ca_file": 'fake',
                    "server_name": "juju-apiserver",
                },
            }],
        )
        mock_metrics_provider.return_value.set_scrape_job_spec.assert_called_once()

        harness.remove_relation(relation_id)
        mock_remove_user.assert_called_once_with(f'juju-metrics-r{relation_id}')

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_apiaddresses_missing)
    def test_apiaddresses_missing(self, _):
        harness = self.harness

        with self.assertRaisesRegex(AgentConfException, "agent.conf key 'apiaddresses' missing"):
            harness.charm.api_port()

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_apiaddresses_not_list)
    def test_apiaddresses_not_list(self, _):
        harness = self.harness

        with self.assertRaisesRegex(
            AgentConfException, "agent.conf key 'apiaddresses' is not a list"
        ):
            harness.charm.api_port()

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_apiaddresses_missing)
    @patch("controlsocket.Client.add_metrics_user")
    def test_apiaddresses_missing_status(self, *_):
        harness = self.harness

        harness.add_relation('metrics-endpoint', 'prometheus-k8s')
        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ErrorStatus)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_ipv4)
    def test_apiaddresses_ipv4(self, _):
        harness = self.harness

        self.assertEqual(harness.charm.api_port(), 17070)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_ipv6)
    def test_apiaddresses_ipv6(self, _):
        harness = self.harness

        self.assertEqual(harness.charm.api_port(), 17070)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("ops.model.Model.get_binding")
    def test_dbcluster_relation_changed_single_addr(self, binding, _):
        harness = self.harness
        binding.return_value = mockBinding(['192.168.1.17'])

        # Have another unit enter the relation.
        # Its bind address should end up in the application data bindings list.
        relation_id = harness.add_relation('dbcluster', 'controller')
        harness.add_relation_unit(relation_id, 'juju-controller/1')
        self.harness.update_relation_data(
            relation_id, 'juju-controller/1', {'db-bind-address': '192.168.1.100'})

        harness.set_leader()
        harness.charm._on_dbcluster_relation_changed(
            harness.charm.model.get_relation('dbcluster').data[harness.charm.unit])

        unit_data = harness.get_relation_data(relation_id, 'juju-controller/0')
        self.assertEqual(unit_data['db-bind-address'], '192.168.1.17')

        app_data = harness.get_relation_data(relation_id, 'juju-controller')
        exp = {"juju-controller/0": "192.168.1.17", "juju-controller/1": "192.168.1.100"}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), exp)

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("ops.model.Model.get_binding")
    def test_dbcluster_relation_changed_multi_addr_error(self, binding, _):
        harness = self.harness
        binding.return_value = mockBinding(["192.168.1.17", "192.168.1.18"])

        relation_id = harness.add_relation('dbcluster', 'controller')
        harness.add_relation_unit(relation_id, 'juju-controller/1')

        harness.charm._on_dbcluster_relation_changed(
            harness.charm.model.get_relation('dbcluster').data[harness.charm.unit])

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)


class mockNetwork:
    def __init__(self, addresses):
        self.ingress_addresses = [ipaddress.ip_address(addr) for addr in addresses]
        self.ingress_address = addresses[0]


class mockBinding:
    def __init__(self, addresses):
        self.network = mockNetwork(addresses)
