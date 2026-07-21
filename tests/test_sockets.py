#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

import io
import unittest
import urllib.error
from controlsocket import ControlSocketClient
from configchangesocket import ConfigChangeSocketClient
from unixsocket import APIError, ConnectionError


class TestClass(unittest.TestCase):
    def test_add_metrics_user_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/metrics-users',
            method='POST',
            body=r'{"username": "juju-metrics-r0", "password": "passwd"}',
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"created user \"juju-metrics-r0\""}'
            )
        )
        control_socket.add_metrics_user('juju-metrics-r0', 'passwd')

    def test_add_metrics_user_fail(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/metrics-users',
            method='POST',
            body=r'{"username": "juju-metrics-r0", "password": "passwd"}',
            error=urllib.error.HTTPError(
                url='http://localhost/metrics-users',
                code=409,
                msg='',
                hdrs=None,
                fp=io.BytesIO(br'{"error":"user \"juju-metrics-r0\" already exists"}'),
            )
        )

        with self.assertRaises(APIError) as cm:
            control_socket.add_metrics_user('juju-metrics-r0', 'passwd')
        self.assertEqual(cm.exception.body, {'error': 'user "juju-metrics-r0" already exists'})
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.status, '')
        self.assertEqual(cm.exception.message, 'user "juju-metrics-r0" already exists')

    def test_remove_metrics_user_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/metrics-users/juju-metrics-r0',
            method='DELETE',
            body=None,
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"deleted user \"juju-metrics-r0\""}'
            )
        )
        control_socket.remove_metrics_user('juju-metrics-r0')

    def test_remove_metrics_user_fail(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/metrics-users/juju-metrics-r0',
            method='DELETE',
            body=None,
            error=urllib.error.HTTPError(
                url='http://localhost/metrics-users/juju-metrics-r0',
                code=404,
                msg='',
                hdrs=None,
                fp=io.BytesIO(br'{"error":"user \"juju-metrics-r0\" not found"}'),
            )
        )

        with self.assertRaises(APIError) as cm:
            control_socket.remove_metrics_user('juju-metrics-r0')
        self.assertEqual(cm.exception.body, {'error': 'user "juju-metrics-r0" not found'})
        self.assertEqual(cm.exception.code, 404)
        self.assertEqual(cm.exception.status, '')
        self.assertEqual(cm.exception.message, 'user "juju-metrics-r0" not found')

    def test_set_charm_tracing_config_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/charm-tracing-config',
            method='POST',
            body=(
                r'{"grpc_endpoint": "grpc://trace.example.com:4317", '
                r'"http_endpoint": "http://trace.example.com:4318", '
                r'"ca_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"}'
            ),
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"updated charm tracing config"}'
            )
        )

        control_socket.set_charm_tracing_config(
            grpc_endpoint='grpc://trace.example.com:4317',
            http_endpoint='http://trace.example.com:4318',
            ca_cert='-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----',
        )

    def test_set_workload_tracing_config_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/workload-tracing-config',
            method='POST',
            body=(
                r'{"grpc_endpoint": "grpc://trace.example.com:4317", '
                r'"http_endpoint": "http://trace.example.com:4318", '
                r'"ca_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----", '
                r'"stack_traces": true, '
                r'"sample_ratio": 0.5, '
                r'"tail_sampling_threshold": "250ms", '
                r'"insecure_skip_verify": true}'
            ),
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"updated workload tracing config"}'
            )
        )

        control_socket.set_workload_tracing_config(
            grpc_endpoint='grpc://trace.example.com:4317',
            http_endpoint='http://trace.example.com:4318',
            ca_cert='-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----',
            stack_traces=True,
            sample_ratio=0.5,
            tail_sampling_threshold='250ms',
            insecure_skip_verify=True,
        )

    def test_add_s3_config_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/s3-credentials',
            method='POST',
            body=(
                r'{"access_key": "ak", '
                r'"secret_key": "sk", '
                r'"bucket": "test-bucket", '
                r'"region": "us-east-1", '
                r'"endpoint": "https://s3.example"}'
            ),
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"updated s3 config"}'
            )
        )

        control_socket.add_s3_config(
            {
                'access_key': 'ak',
                'secret_key': 'sk',
                'bucket': 'test-bucket',
                'region': 'us-east-1',
                'endpoint': 'https://s3.example',
            }
        )

    def test_remove_s3_config_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/s3-credentials',
            method='DELETE',
            body=None,
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"removed s3 config"}'
            )
        )

        control_socket.remove_s3_config()

    def test_set_loki_endpoint_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/loki-endpoint',
            method='POST',
            body=(
                r'{"url": "http://loki:3100/loki/api/v1/push", '
                r'"ca_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----", '
                r'"insecure_skip_verify": true}'
            ),
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"set loki endpoint"}'
            )
        )
        control_socket.set_loki_endpoint(
            {
                "url": "http://loki:3100/loki/api/v1/push",
                "ca_cert": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
                "insecure_skip_verify": True,
            }
        )

    def test_set_loki_endpoint_fail(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/loki-endpoint',
            method='POST',
            body=(
                r'{"url": "http://loki:3100/loki/api/v1/push", '
                r'"ca_cert": null, '
                r'"insecure_skip_verify": false}'
            ),
            error=urllib.error.HTTPError(
                url='http://localhost/loki-endpoint',
                code=500,
                msg='',
                hdrs=None,
                fp=io.BytesIO(br'{"error":"internal error"}'),
            )
        )

        with self.assertRaises(APIError) as cm:
            control_socket.set_loki_endpoint(
                {
                    "url": "http://loki:3100/loki/api/v1/push",
                    "ca_cert": None,
                    "insecure_skip_verify": False,
                }
            )
        self.assertEqual(cm.exception.body, {'error': 'internal error'})
        self.assertEqual(cm.exception.code, 500)
        self.assertEqual(cm.exception.message, 'internal error')

    def test_remove_loki_endpoint_success(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/loki-endpoint',
            method='DELETE',
            body=None,
            response=MockResponse(
                headers=MockHeaders(content_type='application/json'),
                body=r'{"message":"removed loki endpoint"}'
            )
        )
        control_socket.remove_loki_endpoint()

    def test_remove_loki_endpoint_fail(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/loki-endpoint',
            method='DELETE',
            body=None,
            error=urllib.error.HTTPError(
                url='http://localhost/loki-endpoint',
                code=404,
                msg='',
                hdrs=None,
                fp=io.BytesIO(br'{"error":"loki endpoint not found"}'),
            )
        )

        with self.assertRaises(APIError) as cm:
            control_socket.remove_loki_endpoint()
        self.assertEqual(cm.exception.body, {'error': 'loki endpoint not found'})
        self.assertEqual(cm.exception.code, 404)
        self.assertEqual(cm.exception.message, 'loki endpoint not found')

    def test_connection_error(self):
        mock_opener = MockOpener(self)
        control_socket = ControlSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/metrics-users',
            method='POST',
            body=r'{"username": "juju-metrics-r0", "password": "passwd"}',
            error=urllib.error.URLError('could not connect to socket')
        )

        with self.assertRaisesRegex(ConnectionError, 'could not connect to socket'):
            control_socket.add_metrics_user('juju-metrics-r0', 'passwd')

    def test_get_controller_agent_id(self):
        mock_opener = MockOpener(self)
        config_reload_socket = ConfigChangeSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/agent-id',
            method='GET',
            body=None,
            response=MockResponse(
                headers=MockHeaders(content_type='application/text'),
                body=b'666'
            )
        )

        id = config_reload_socket.get_controller_agent_id()
        self.assertEqual(id, '666')

    def test_reload_config(self):
        mock_opener = MockOpener(self)
        config_reload_socket = ConfigChangeSocketClient('fake_socket_path', opener=mock_opener)

        mock_opener.expect(
            url='http://localhost/reload',
            method='POST',
            body=None,
            response=None,
        )

        config_reload_socket.reload_config()


class MockOpener:
    def __init__(self, test_case):
        self.test = test_case

    def expect(self, url, method, body, response=None, error=None):
        self.url = url
        self.method = method
        self.body = body

        self.response = response
        self.error = error

    def open(self, request, timeout):
        self.test.assertEqual(request.full_url, self.url)
        self.test.assertEqual(request.method, self.method)
        if self.body is None:
            self.test.assertEqual(request.data, None)
        else:
            self.test.assertEqual(request.data.decode('utf-8'), self.body)

        if self.error:
            raise self.error
        else:
            return self.response


class MockResponse:
    def __init__(self, headers, body=None):
        self.headers = headers
        self.body = body

    def read(self):
        return self.body


class MockHeaders:
    def __init__(self, content_type=None, params=None):
        self.content_type = content_type
        self.params = params

    def get_content_type(self):
        return self.content_type

    def get_params(self):
        return self.params
