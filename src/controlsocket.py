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

    def add_s3_credentials(self, credentials: dict):
        resp = self.json_request(
            method='POST',
            path='/s3-credentials',
            body=credentials,
        )
        logger.debug('result of add_s3_credentials request: %r', resp)

    def remove_s3_credentials(self):
        resp = self.json_request(
            method='DELETE',
            path='/s3-credentials',
        )
        logger.debug('result of remove_s3_credentials request: %r', resp)
