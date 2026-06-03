# Copyright 2021 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import ipaddress
import json
import os
import unittest

import yaml

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    ProviderApplicationData,
)
from charms.tempo_coordinator_k8s.v0.tracing import (
    ProtocolType,
    Receiver,
    TracingProviderAppData,
    TransportProtocolType,
)
from charm import JujuControllerCharm, AgentConfException
from ops.model import BlockedStatus, ActiveStatus, MaintenanceStatus
from ops.testing import Harness
from unittest.mock import mock_open, patch
from unixsocket import ConnectionError as SocketConnectionError

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


def tracing_provider_data():
    return TracingProviderAppData(
        receivers=[
            Receiver(
                protocol=ProtocolType(name="otlp_grpc", type=TransportProtocolType.grpc),
                url="tempo-grpc:4317",
            ),
            Receiver(
                protocol=ProtocolType(name="otlp_http", type=TransportProtocolType.http),
                url="http://tempo-http:4318",
            ),
        ]
    ).dump()


def certificate_provider_data(certificates):
    return ProviderApplicationData(certificates=certificates).dump()


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(JujuControllerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_start_sets_active_status(self):
        harness = Harness(JujuControllerCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        harness.charm.on.start.emit()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

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

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_updates_endpoints(self, mock_set_tracing_config, *_):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()

        relation_id = harness.add_relation("charm-tracing", "tempo-coordinator")
        harness.add_relation_unit(relation_id, "tempo-coordinator/0")

        provider_data = tracing_provider_data()

        harness.update_relation_data(relation_id, "tempo-coordinator", provider_data)

        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint="tempo-grpc:4317",
            http_endpoint="http://tempo-http:4318",
            ca_cert=None,
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_cleared_on_leader_elected_without_relations(
        self, mock_set_tracing_config, *_
    ):
        harness = self.harness

        harness.set_leader(True)

        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint=None,
            http_endpoint=None,
            ca_cert=None,
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_replayed_on_leader_elected(
        self, mock_set_tracing_config, *_
    ):
        harness = self.harness

        relation_id = harness.add_relation("charm-tracing", "tempo-coordinator")
        harness.add_relation_unit(relation_id, "tempo-coordinator/0")

        harness.update_relation_data(
            relation_id, "tempo-coordinator", tracing_provider_data()
        )

        mock_set_tracing_config.assert_not_called()

        harness.set_leader(True)

        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint="tempo-grpc:4317",
            http_endpoint="http://tempo-http:4318",
            ca_cert=None,
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_change_ignores_not_ready(
        self, mock_set_tracing_config, *_
    ):
        harness = self.harness

        event = type("Event", (), {"relation": object()})()
        with patch.object(harness.charm.tracing_requirer, "is_ready", return_value=False):
            harness.charm._on_tracing_relation_changed(event)

        mock_set_tracing_config.assert_not_called()

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_update_sets_blocked_on_socket_error(
        self, mock_set_tracing_config, *_
    ):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()
        mock_set_tracing_config.side_effect = SocketConnectionError("could not connect to socket")

        relation_id = harness.add_relation("charm-tracing", "tempo-coordinator")
        harness.add_relation_unit(relation_id, "tempo-coordinator/0")

        harness.update_relation_data(
            relation_id, "tempo-coordinator", tracing_provider_data()
        )

        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()

        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        self.assertEqual(
            harness.charm.unit.status.message, "failed to set charm tracing config"
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_status_error_clears_after_success(self, mock_set_tracing_config, *_):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()

        relation_id = harness.add_relation("charm-tracing", "tempo-coordinator")
        harness.add_relation_unit(relation_id, "tempo-coordinator/0")

        mock_set_tracing_config.side_effect = [
            SocketConnectionError("could not connect to socket"),
            None,
        ]
        harness.update_relation_data(
            relation_id, "tempo-coordinator", tracing_provider_data()
        )
        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertEqual(
            harness.charm.unit.status.message, "failed to set charm tracing config"
        )

        harness.remove_relation(relation_id)
        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_tracing_relation_removed_clears_endpoints(self, mock_set_tracing_config, *_):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()

        relation_id = harness.add_relation("charm-tracing", "tempo-coordinator")
        harness.add_relation_unit(relation_id, "tempo-coordinator/0")

        harness.update_relation_data(
            relation_id, "tempo-coordinator", tracing_provider_data()
        )
        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint="tempo-grpc:4317",
            http_endpoint="http://tempo-http:4318",
            ca_cert=None,
        )

        harness.remove_relation(relation_id)

        self.assertEqual(mock_set_tracing_config.call_count, 2)
        mock_set_tracing_config.assert_called_with(
            grpc_endpoint=None,
            http_endpoint=None,
            ca_cert=None,
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_receive_ca_cert_updates_tracing_config(self, mock_set_tracing_config, *_):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()

        relation_id = harness.add_relation("charm-tracing-ca-cert", "cert-provider")
        harness.add_relation_unit(relation_id, "cert-provider/0")

        cert_a = "-----BEGIN CERTIFICATE-----\na\n-----END CERTIFICATE-----"
        cert_b = "-----BEGIN CERTIFICATE-----\nb\n-----END CERTIFICATE-----"
        harness.update_relation_data(
            relation_id,
            "cert-provider",
            certificate_provider_data({cert_b, cert_a}),
        )

        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint=None,
            http_endpoint=None,
            ca_cert="\n".join([cert_a, cert_b]),
        )

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_receive_ca_cert_update_ignores_empty_cert_list(
        self, mock_set_tracing_config, *_
    ):
        harness = self.harness

        event = type("Event", (), {"certificates": set(), "relation_id": 1})()
        harness.charm._on_receive_ca_cert_updated(event)

        mock_set_tracing_config.assert_not_called()

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("controlsocket.ControlSocketClient.set_charm_tracing_config")
    def test_receive_ca_cert_removed_clears_tracing_ca_cert(self, mock_set_tracing_config, *_):
        harness = self.harness
        harness.set_leader(True)
        mock_set_tracing_config.reset_mock()

        relation_id = harness.add_relation("charm-tracing-ca-cert", "cert-provider")
        harness.add_relation_unit(relation_id, "cert-provider/0")

        cert = "-----BEGIN CERTIFICATE-----\na\n-----END CERTIFICATE-----"
        harness.update_relation_data(
            relation_id,
            "cert-provider",
            certificate_provider_data({cert}),
        )
        mock_set_tracing_config.assert_called_once_with(
            grpc_endpoint=None,
            http_endpoint=None,
            ca_cert=cert,
        )

        harness.remove_relation(relation_id)

        self.assertEqual(mock_set_tracing_config.call_count, 2)
        mock_set_tracing_config.assert_called_with(
            grpc_endpoint=None,
            http_endpoint=None,
            ca_cert=None,
        )

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

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_single_addr(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, *__):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])

        # This unit's agent ID happens to correspond with the unit ID.
        mock_get_agent_id.return_value = '0'

        harness.set_leader()
        harness.charm._stored.tracing_status_error = None

        # Have another unit enter the relation.
        # Its bind address should end up in the application data bindings list.
        # Note that the agent ID does not correspond with the unit's ID
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

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_multi_addr_error(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, *_):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(["192.168.1.17", "192.168.1.18"])
        mock_get_agent_id.return_value = '0'

        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')

        self.harness.update_relation_data(
            relation_id, 'juju-controller/1', {'db-bind-address': '192.168.1.100'})

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        mock_reload_config.assert_called_once()

    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("builtins.open", new_callable=mock_open)
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_changed_write_file(
            self, mock_reload_config, mock_get_binding, mock_open, mock_get_agent_id):

        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])

        mock_get_agent_id.return_value = '0'

        relation_id = harness.add_relation('dbcluster', harness.charm.app.name)
        harness.add_relation_unit(relation_id, 'juju-controller/1')
        bound = {'juju-controller/0': '192.168.1.17', 'juju-controller/1': '192.168.1.100'}
        self.harness.update_relation_data(
            relation_id, harness.charm.app.name, {'db-bind-addresses': json.dumps(bound)})

        file_path = '/var/lib/juju/agents/controller-0/controller.conf'
        self.assertEqual(mock_open.call_count, 2)

        # First call to read out the YAML
        first_open_args, _ = mock_open.call_args_list[0]
        self.assertEqual(first_open_args, (file_path,))

        # Second call to write the updated YAML.
        second_open_args, _ = mock_open.call_args_list[1]
        self.assertEqual(second_open_args, (file_path, 'w'))

        # yaml.dump appears to write the the file incrementally,
        # so we need to hoover up the call args to reconstruct.
        written = ''
        for args in mock_open().write.call_args_list:
            written += args[0][0]

        self.assertEqual(yaml.safe_load(written), {'db-bind-addresses': bound})

        # The last thing we should have done is send a reload request via the
        # socket..
        mock_reload_config.assert_called_once()

    @patch("builtins.open", new_callable=mock_open, read_data=agent_conf)
    @patch("configchangesocket.ConfigChangeSocketClient.get_controller_agent_id")
    @patch("ops.model.Model.get_binding")
    @patch("configchangesocket.ConfigChangeSocketClient.reload_config")
    def test_dbcluster_relation_departed(
            self, mock_reload_config, mock_get_binding, mock_get_agent_id, *__):
        harness = self.harness
        mock_get_binding.return_value = mockBinding(['192.168.1.17'])

        # This unit's agent ID happens to correspond with the unit ID.
        mock_get_agent_id.return_value = '0'

        harness.set_leader()
        harness.charm._stored.tracing_status_error = None

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
        exp = {'0': '192.168.1.17', '9': '192.168.1.100'}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), exp)

        # Remove the second unit.
        harness.remove_relation_unit(relation_id, 'juju-controller/1')

        # Assert that the second unit's address is gone from the data bag.
        app_data = harness.get_relation_data(relation_id, 'juju-controller')
        exp = {'0': '192.168.1.17'}
        self.assertEqual(json.loads(app_data['db-bind-addresses']), exp)

        harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_relation_credentials_changed(self, mock_add_s3_credentials):
        harness = self.harness
        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {
                "access-key": "ak",
                "secret-key": "sk",
                "bucket": "test-bucket",
                "endpoint": "https://s3.example",
            },
        )

        expected_credentials = {
            "access_key": "ak",
            "secret_key": "sk",
            "endpoint": "https://s3.example",
        }
        mock_add_s3_credentials.assert_called_once_with(expected_credentials)
        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, MaintenanceStatus)

    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_status_pending_clears_after_collect(self, mock_add_s3_credentials):
        harness = self.harness
        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk", "bucket": "test-bucket"},
        )
        mock_add_s3_credentials.assert_called_once_with(
            {"access_key": "ak", "secret_key": "sk", "endpoint": None}
        )

        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, MaintenanceStatus)

        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, ActiveStatus)

    @patch(
        "controlsocket.ControlSocketClient.add_s3_credentials",
        side_effect=RuntimeError("boom"),
    )
    def test_s3_relation_credentials_changed_failure_sets_blocked(self, _mock_add):
        harness = self.harness
        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk", "bucket": "test-bucket"},
        )

        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        self.assertIn(
            "failed to apply s3 credentials",
            harness.charm.unit.status.message,
        )

    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_relation_credentials_changed_non_leader_no_set(self, mock_add_s3_credentials):
        harness = self.harness
        harness.set_leader(False)

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk", "bucket": "test-bucket"},
        )

        mock_add_s3_credentials.assert_not_called()

    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_relation_credentials_replayed_on_leader_elected(self, mock_add_s3_credentials):
        harness = self.harness

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {
                "access-key": "ak",
                "secret-key": "sk",
                "bucket": "test-bucket",
                "endpoint": "https://s3.example",
            },
        )
        expected_credentials = {
            "access_key": "ak",
            "secret_key": "sk",
            "endpoint": "https://s3.example",
        }
        mock_add_s3_credentials.assert_not_called()

        harness.set_leader(True)

        mock_add_s3_credentials.assert_called_once_with(expected_credentials)

    @patch(
        "controlsocket.ControlSocketClient.add_s3_credentials",
        side_effect=RuntimeError("boom"),
    )
    def test_s3_relation_replay_failure_sets_blocked_status(self, _mock_add):
        harness = self.harness

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")
        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk", "bucket": "test-bucket"},
        )

        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None
        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        self.assertIn("failed to reapply s3 credentials", harness.charm.unit.status.message)

    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_relation_credentials_updated(self, mock_add_s3_credentials):
        harness = self.harness
        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk", "bucket": "test-bucket"},
        )

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak2", "secret-key": "sk2", "bucket": "test-bucket"},
        )
        mock_add_s3_credentials.assert_called_with(
            {"access_key": "ak2", "secret_key": "sk2", "endpoint": None}
        )
        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, MaintenanceStatus)

    def test_s3_relation_sets_bucket_on_join(self):
        harness = self.harness
        harness.set_leader(True)

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        # Bucket is auto-set by the S3Requirer when bucket_name is not provided.
        data = harness.get_relation_data(relation_id, harness.charm.app.name)
        self.assertEqual(data["bucket"], f"relation-{relation_id}")

    @patch("controlsocket.ControlSocketClient.remove_s3_credentials")
    @patch("controlsocket.ControlSocketClient.add_s3_credentials")
    def test_s3_relation_credentials_gone(
        self, mock_add_s3_credentials, mock_remove_s3_credentials
    ):
        harness = self.harness
        harness.set_leader(True)

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk"},
        )

        harness.remove_relation(relation_id)
        mock_add_s3_credentials.assert_called_once_with(
            {"access_key": "ak", "secret_key": "sk", "endpoint": None}
        )
        mock_remove_s3_credentials.assert_called_once_with()

    @patch("controlsocket.ControlSocketClient.remove_s3_credentials")
    def test_s3_relation_credentials_gone_non_leader(self, mock_remove_s3_credentials):
        harness = self.harness
        harness.set_leader(False)

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk"},
        )
        harness.remove_relation(relation_id)

        mock_remove_s3_credentials.assert_not_called()

    @patch(
        "controlsocket.ControlSocketClient.remove_s3_credentials",
        side_effect=RuntimeError("boom"),
    )
    def test_s3_relation_credentials_gone_failure_sets_blocked(self, _mock_remove):
        harness = self.harness
        harness.set_leader(True)
        harness.charm._stored.tracing_status_error = None

        relation_id = harness.add_relation("s3-backend", "s3-integrator")
        harness.add_relation_unit(relation_id, "s3-integrator/0")

        harness.update_relation_data(
            relation_id,
            "s3-integrator",
            {"access-key": "ak", "secret-key": "sk"},
        )

        harness.remove_relation(relation_id)

        with patch.object(harness.charm, "api_port", return_value=17070):
            harness.evaluate_status()
        self.assertIsInstance(harness.charm.unit.status, BlockedStatus)
        self.assertIn("failed to remove s3 credentials", harness.charm.unit.status.message)


class mockNetwork:
    def __init__(self, addresses):
        self.ingress_addresses = [ipaddress.ip_address(addr) for addr in addresses]
        self.ingress_address = addresses[0]


class mockBinding:
    def __init__(self, addresses):
        self.network = mockNetwork(addresses)
