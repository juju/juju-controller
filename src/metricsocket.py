#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.
import urllib
from typing import Optional

import unixsocket
import logging

logger = logging.getLogger(__name__)


class MetricSocketClient(unixsocket.SocketClient):
    """
    Client to Juju metric socket.
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
