# Copyright 2026 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

"""Fixtures for the Jubilant-based smoke integration test."""

from __future__ import annotations

import jubilant
import pytest


@pytest.fixture(scope="session")
def controller() -> jubilant.Juju:
    return jubilant.Juju(model="controller")
