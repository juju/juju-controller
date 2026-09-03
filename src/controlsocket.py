#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.
from functools import wraps
import logging
import os
import time
from typing import Optional
import urllib

import unixsocket
from unixsocket import APIError  # noqa: F401, re-exported for charm.py
from unixsocket import ConnectionError as SocketConnectionError  # noqa: F401

logger = logging.getLogger(__name__)

# Ops recommends retrying a very short-lived failure several times for no more
# than a second within a hook. These delays total 0.7 seconds.
_RETRY_MAX_ATTEMPTS = 4
_RETRY_BASE_DELAY = 0.1

# A missing socket means the controller has not created its listener yet, which
# can take considerably longer than a transient error from an existing socket.
_MISSING_SOCKET_MAX_ATTEMPTS = 12
_MISSING_SOCKET_RETRY_DELAY = 5.0


def _retry_on_connection_error(func):
    """Retry with exponential backoff when the control socket is not yet
    available.

    On a new HA node, the control socket may not be available until the
    domain services and Dqlite cluster have started. This decorator retries
    the call with increasing delays, giving the socket time to become
    available before the charm sees a failure.
    """

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        connection_attempt = 0
        missing_socket_attempt = 0
        last_exc = None

        while True:
            socket_exists = last_exc is None or os.path.exists(self.socket_path)
            if socket_exists:
                try:
                    return func(self, *args, **kwargs)
                except SocketConnectionError as e:
                    last_exc = e
                    socket_exists = os.path.exists(self.socket_path)

            if not socket_exists:
                if missing_socket_attempt == _MISSING_SOCKET_MAX_ATTEMPTS:
                    raise last_exc
                missing_socket_attempt += 1
                delay = _MISSING_SOCKET_RETRY_DELAY
                reason = "does not exist"
                attempt = missing_socket_attempt
                max_attempts = _MISSING_SOCKET_MAX_ATTEMPTS
            else:
                connection_attempt += 1
                if connection_attempt == _RETRY_MAX_ATTEMPTS:
                    raise last_exc
                delay = _RETRY_BASE_DELAY * (2 ** (connection_attempt - 1))
                reason = "is not available"
                attempt = connection_attempt
                max_attempts = _RETRY_MAX_ATTEMPTS

            logger.debug(
                "control socket %s, retrying in %.1fs (attempt %d/%d): %s",
                reason, delay, attempt, max_attempts, last_exc,
            )
            time.sleep(delay)

    return wrapper


class ControlSocketClient(unixsocket.SocketClient):
    """
    Client to Juju control socket.

    The control socket may not be available on a new HA node until the
    domain services and Dqlite cluster have started. All methods include
    retry with exponential backoff to handle this transient unavailability.
    By contrast, the config change socket (configchangesocket.py) is
    guaranteed to be available before the install hook runs and does not
    need retry.
    """

    def __init__(self, socket_path: str,
                 opener: Optional[urllib.request.OpenerDirector] = None):
        super().__init__(socket_path, opener=opener)

    @_retry_on_connection_error
    def add_metrics_user(self, username: str, password: str):
        resp = self.json_request(
            method='POST',
            path='/metrics-users',
            body={"username": username, "password": password},
        )
        logger.debug('result of add_metrics_user request: %r', resp)

    @_retry_on_connection_error
    def remove_metrics_user(self, username: str):
        resp = self.json_request(
            method='DELETE',
            path=f'/metrics-users/{username}',
        )
        logger.debug('result of remove_metrics_user request: %r', resp)

    @_retry_on_connection_error
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

    @_retry_on_connection_error
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

    @_retry_on_connection_error
    def add_s3_config(self, config: dict):
        resp = self.json_request(
            method='POST',
            path='/s3-config',
            body=config,
        )
        logger.debug('result of add_s3_config request: %r', resp)

    @_retry_on_connection_error
    def remove_s3_config(self):
        resp = self.json_request(
            method='DELETE',
            path='/s3-config',
        )
        logger.debug('result of remove_s3_config request: %r', resp)

    @_retry_on_connection_error
    def set_loki_endpoint(self, endpoint: dict):
        resp = self.json_request(
            method='POST',
            path='/loki-endpoint',
            body=endpoint,
        )
        logger.debug('result of set_loki_endpoint request: %r', resp)

    @_retry_on_connection_error
    def remove_loki_endpoint(self):
        resp = self.json_request(
            method='DELETE',
            path='/loki-endpoint',
        )
        logger.debug('result of remove_loki_endpoint request: %r', resp)
