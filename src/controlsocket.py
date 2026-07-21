#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.
import urllib
from typing import Optional

import unixsocket
import logging

logger = logging.getLogger(__name__)


class ControlSocketClient(unixsocket.SocketClient):
    """
    Client to Juju control socket.
    """
    def __init__(self, socket_path: str,
                 opener: Optional[urllib.request.OpenerDirector] = None):
        super().__init__(socket_path, opener=opener)

    def add_metrics_user(self, username: str, password: str):
        resp = self.json_request(
            method='POST',
            path='/metrics-users',
            body={"username": username, "password": password},
        )
        logger.debug('result of add_metrics_user request: %r', resp)

    def remove_metrics_user(self, username: str):
        resp = self.json_request(
            method='DELETE',
            path=f'/metrics-users/{username}',
        )
        logger.debug('result of remove_metrics_user request: %r', resp)

    def set_charm_tracing_config(
        self,
        grpc_endpoint: Optional[str],
        http_endpoint: Optional[str],
        ca_cert: Optional[str],
    ):
        """Set the tracing configuration for the charm."""
        body = {
            "grpc_endpoint": grpc_endpoint,
            "http_endpoint": http_endpoint,
            "ca_cert": ca_cert,
        }
        resp = self.json_request(
            method='POST',
            path='/charm-tracing-config',
            body=body,
        )
        logger.debug('result of set_charm_tracing_config request: %r', resp)

    def set_workload_tracing_config(
        self,
        grpc_endpoint: Optional[str],
        http_endpoint: Optional[str],
        ca_cert: Optional[str],
        stack_traces: Optional[bool] = None,
        sample_ratio: Optional[float] = None,
        tail_sampling_threshold: Optional[str] = None,
        insecure_skip_verify: Optional[bool] = None,
    ):
        """Set the tracing configuration for the controller workload."""
        body = {
            "grpc_endpoint": grpc_endpoint,
            "http_endpoint": http_endpoint,
            "ca_cert": ca_cert,
        }
        if stack_traces is not None:
            body["stack_traces"] = stack_traces
        if sample_ratio is not None:
            body["sample_ratio"] = sample_ratio
        if tail_sampling_threshold is not None:
            body["tail_sampling_threshold"] = (
                tail_sampling_threshold
            )
        if insecure_skip_verify is not None:
            body["insecure_skip_verify"] = insecure_skip_verify
        resp = self.json_request(
            method='POST',
            path='/workload-tracing-config',
            body=body,
        )
        logger.debug('result of set_workload_tracing_config request: %r', resp)

    def add_s3_config(self, config: dict):
        resp = self.json_request(
            method='POST',
            path='/s3-credentials',
            body=config,
        )
        logger.debug('result of add_s3_config request: %r', resp)

    def remove_s3_config(self):
        resp = self.json_request(
            method='DELETE',
            path='/s3-credentials',
        )
        logger.debug('result of remove_s3_config request: %r', resp)

    def set_loki_endpoint(self, endpoint: dict):
        resp = self.json_request(
            method='POST',
            path='/loki-endpoint',
            body=endpoint,
        )
        logger.debug('result of set_loki_endpoint request: %r', resp)

    def remove_loki_endpoint(self):
        resp = self.json_request(
            method='DELETE',
            path='/loki-endpoint',
        )
        logger.debug('result of remove_loki_endpoint request: %r', resp)
