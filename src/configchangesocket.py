#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.
import urllib
from typing import Optional

import unixsocket
import logging

logger = logging.getLogger(__name__)


class ConfigChangeSocketClient(unixsocket.SocketClient):
    """
    Client to the Juju config change socket.
    """
    def __init__(self, socket_path: str,
                 opener: Optional[urllib.request.OpenerDirector] = None):
        super().__init__(socket_path, opener=opener)

    def reload_config(self):
        resp = self.request_raw(
            method='GET',
            path='/reload',
        )
        logger.debug('result of reload request: %r', resp)
