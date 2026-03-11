# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import ipaddress
import json
import os
import unittest

import yaml

from charm import JujuControllerCharm, AgentConfException
from ops.model import BlockedStatus, ActiveStatus
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
    @patch("controlsocket.ControlSocketClient.add_metrics_user")
    @patch("controlsocket.ControlSocketClient.remove_metrics_user")
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
    @patch("controlsocket.ControlSocketClient.add_metrics_user")
    def test_apiaddresses_missing_status(self, *_):
        harness = self.harness

        harness.add_relation('metrics-endpoint', 'prometheus-k8s')
        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        self.assertEqual(
            harness.charm.unit.status,
            BlockedStatus(
                "cannot read controller API port from agent configuration: "
                "agent.conf key 'apiaddresses' missing"
            )
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_ipv4)
    def test_apiaddresses_ipv4(self, _):
        self.assertEqual(self.harness.charm.api_port(), 17070)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf_ipv6)
    def test_apiaddresses_ipv6(self, _):
        self.assertEqual(self.harness.charm.api_port(), 17070)

    @patch("tempfile.NamedTemporaryFile")
    @patch("os.replace")
    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_single_addr(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, mock_open,
            mock_replace, mock_named_tempfile):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])

        # This unit's agent ID happens to correspond with the unit ID.
        mock_get_agent_id.return_value = '0'

        temp_file_path = '/var/lib/juju/agents/controller-0/tmp.conf'
        temp_files = []

        def fake_tempfile(*_, **__):
            tmp_file = FakeNamedTemporaryFile(temp_file_path)
            temp_files.append(tmp_file)
            return tmp_file

        mock_named_tempfile.side_effect = fake_tempfile

        harness.set_leader()

        # Have another unit enter the relation.
        # Its bind address should end up in the application data bindings list.
        # Note that the agent ID doesn not correspond with the unit's ID
        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')
        self.harness.update_relation_data(
            relation_id, 'juju-controller/1', {
                'db-bind-address': '192.168.1.100',
                'agent-id': '9',
            })

        mock_reload_config.assert_called_once()

        unit_data = harness.get_relation_data(relation_id, 'juju-controller/0')
        self.assertEqual(unit_data['db-bind-address'], '192.168.1.17')
        self.assertEqual(unit_data['agent-id'], '0')

        app_data = harness.get_relation_data(relation_id, 'juju-controller')
        exp = {'0': '192.168.1.17', '9': '192.168.1.100'}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), exp)

        expected_conf = yaml.safe_load(agent_conf)
        expected_conf['db-bind-addresses'] = exp
        self.assertGreaterEqual(mock_named_tempfile.call_count, 1)
        last_call_args, last_call_kwargs = mock_named_tempfile.call_args
        self.assertEqual(last_call_args, ('w',))
        self.assertEqual(last_call_kwargs, {
            'dir': '/var/lib/juju/agents/controller-0', 'delete': False})

        self.assertGreaterEqual(len(temp_files), 1)
        self.assertEqual(yaml.safe_load(temp_files[-1].written), expected_conf)
        last_replace_args, last_replace_kwargs = mock_replace.call_args
        self.assertEqual(
            last_replace_args,
            (temp_file_path, '/var/lib/juju/agents/controller-0/controller.conf'))
        self.assertEqual(last_replace_kwargs, {})
        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch("tempfile.NamedTemporaryFile")
    @patch("os.replace")
    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_multi_addr_error(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, mock_open,
            mock_replace, mock_named_tempfile):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(["192.168.1.17", "192.168.1.18"])
        mock_get_agent_id.return_value = '0'

        temp_file_path = '/var/lib/juju/agents/controller-0/tmp.conf'
        temp_files = []

        def fake_tempfile(*_, **__):
            tmp_file = FakeNamedTemporaryFile(temp_file_path)
            temp_files.append(tmp_file)
            return tmp_file

        mock_named_tempfile.side_effect = fake_tempfile

        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')

        self.harness.update_relation_data(
            relation_id, 'juju-controller/1', {'db-bind-address': '192.168.1.100'})

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        expected_conf = yaml.safe_load(agent_conf)
        expected_conf['db-bind-addresses'] = {}
        self.assertGreaterEqual(mock_named_tempfile.call_count, 1)
        last_call_args, last_call_kwargs = mock_named_tempfile.call_args
        self.assertEqual(last_call_args, ('w',))
        self.assertEqual(last_call_kwargs, {
            'dir': '/var/lib/juju/agents/controller-0', 'delete': False})
        self.assertGreaterEqual(len(temp_files), 1)
        self.assertEqual(yaml.safe_load(temp_files[-1].written), expected_conf)
        last_replace_args, last_replace_kwargs = mock_replace.call_args
        self.assertEqual(
            last_replace_args,
            (temp_file_path, '/var/lib/juju/agents/controller-0/controller.conf'))
        self.assertEqual(last_replace_kwargs, {})
        mock_reload_config.assert_called_once()

    @patch("tempfile.NamedTemporaryFile")
    @patch("os.replace")
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("builtins.open", new_callable=mock_open, read_data="")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_write_file(
            self, mock_reload_config, mock_get_binding, mock_open, mock_get_agent_id,
            mock_replace, mock_named_tempfile):

        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])
        mock_get_agent_id.return_value = '0'

        temp_file_path = '/var/lib/juju/agents/controller-0/tmp.conf'
        temp_files = []

        def fake_tempfile(*_, **__):
            tmp_file = FakeNamedTemporaryFile(temp_file_path)
            temp_files.append(tmp_file)
            return tmp_file

        mock_named_tempfile.side_effect = fake_tempfile

        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')
        bound = {'juju-controller/0': '192.168.1.17', 'juju-controller/1': '192.168.1.100'}
        self.harness.update_relation_data(
            relation_id, harness.charm.app.name, {'db-bind-addresses': json.dumps(bound)})

        file_path = '/var/lib/juju/agents/controller-0/controller.conf'
        self.assertEqual(mock_open.call_count, 1)

        # First call to read out the YAML
        first_open_args, _ = mock_open.call_args_list[0]
        self.assertEqual(first_open_args, (file_path,))

        expected_conf = {'db-bind-addresses': bound}
        self.assertGreaterEqual(mock_named_tempfile.call_count, 1)
        last_call_args, last_call_kwargs = mock_named_tempfile.call_args
        self.assertEqual(last_call_args, ('w',))
        self.assertEqual(last_call_kwargs, {
            'dir': '/var/lib/juju/agents/controller-0', 'delete': False})
        self.assertGreaterEqual(len(temp_files), 1)
        self.assertEqual(yaml.safe_load(temp_files[-1].written), expected_conf)
        last_replace_args, last_replace_kwargs = mock_replace.call_args
        self.assertEqual(last_replace_args, (temp_file_path, file_path))
        self.assertEqual(last_replace_kwargs, {})

        # The last thing we should have done is send a reload request via the socket.
        mock_reload_config.assert_called_once()

    @patch("tempfile.NamedTemporaryFile")
    @patch("os.replace")
    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_departed(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, mock_open,
            mock_replace, mock_named_tempfile):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])

        # This unit's agent ID happens to correspond with the unit ID.
        mock_get_agent_id.return_value = '0'

        temp_file_path = '/var/lib/juju/agents/controller-0/tmp.conf'
        temp_files = []

        def fake_tempfile(*_, **__):
            tmp_file = FakeNamedTemporaryFile(temp_file_path)
            temp_files.append(tmp_file)
            return tmp_file

        mock_named_tempfile.side_effect = fake_tempfile

        harness.set_leader()

        # Have another unit enter the relation.
        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')
        self.harness.update_relation_data(
            relation_id, 'juju-controller/1', {
                'db-bind-address': '192.168.1.100',
                'agent-id': '9',
            })

        # Assert that the second units agent bind address is in the data bag.
        app_data = harness.get_relation_data(relation_id, 'juju-controller')
        initial_exp = {'0': '192.168.1.17', '9': '192.168.1.100'}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), initial_exp)

        # Remove the second unit.
        harness.remove_relation_unit(relation_id, 'juju-controller/1')

        # Assert that the second unit's address is gone from the data bag.
        app_data = harness.get_relation_data(relation_id, 'juju-controller')
        final_exp = {'0': '192.168.1.17'}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), final_exp)

        initial_conf = yaml.safe_load(agent_conf)
        initial_conf['db-bind-addresses'] = initial_exp
        final_conf = yaml.safe_load(agent_conf)
        final_conf['db-bind-addresses'] = final_exp

        self.assertGreaterEqual(mock_named_tempfile.call_count, 2)
        self.assertGreaterEqual(len(temp_files), 2)
        self.assertEqual(yaml.safe_load(temp_files[0].written), initial_conf)
        self.assertEqual(yaml.safe_load(temp_files[-1].written), final_conf)

        self.assertEqual(mock_replace.call_count, len(temp_files))
        last_replace_args, last_replace_kwargs = mock_replace.call_args
        self.assertEqual(
            last_replace_args,
            (temp_file_path, '/var/lib/juju/agents/controller-0/controller.conf'))
        self.assertEqual(last_replace_kwargs, {})
        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)


class mockNetwork:
    def __init__(self, addresses):
        self.ingress_addresses = [ipaddress.ip_address(addr) for addr in addresses]
        self.ingress_address = addresses[0]


class mockBinding:
    def __init__(self, addresses):
        self.network = mockNetwork(addresses)


class FakeNamedTemporaryFile:
    def __init__(self, name):
        self.name = name
        self.written = ''

    def write(self, data):
        self.written += data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False
