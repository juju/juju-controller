# Copyright 2026 Canonical Ltd.
# Licensed under the GPLv3, see LICENSE file for details.

"""Smoke integration test for the juju-controller charm."""

from __future__ import annotations

import jubilant


def test_controller_charm_is_active(controller: jubilant.Juju) -> None:
    """The juju-controller charm reaches active status after bootstrap."""
    controller.wait(
        lambda status: jubilant.all_active(status, "controller"),
        timeout=10 * 60,
    )
