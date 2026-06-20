"""
Integration tests: persistence mechanism detection.

Tests file writes to sensitive locations (cron, ld.so.preload, /tmp exec).
"""

import os
import pytest
from attacks.file_attacks import (
    modify_cron,
    overwrite_ld_preload,
    write_executable_to_tmp,
)
from attacks.exec_attacks import exec_from_tmp


pytestmark = pytest.mark.integration


def test_cron_write_fires_persistence_alert(alerts):
    proc = modify_cron()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "persist" in a.rule_id.lower() or "cron" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid

    # cleanup
    try:
        os.unlink("/etc/cron.d/test_persist")
    except FileNotFoundError:
        pass


def test_ld_preload_write_fires_alert(alerts):
    if not os.access("/etc/ld.so.preload", os.W_OK) and \
       not os.access("/etc", os.W_OK):
        pytest.skip("No write access to /etc/ld.so.preload")

    proc = overwrite_ld_preload()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "preload" in a.rule_id.lower() or
                            "persist" in a.rule_id.lower() or
                            "hijack" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid

    try:
        os.unlink("/etc/ld.so.preload")
    except FileNotFoundError:
        pass


def test_executable_dropped_in_tmp_fires_alert(alerts):
    proc = write_executable_to_tmp()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "tmp" in a.rule_id.lower() or
                            "drop" in a.rule_id.lower() or
                            "drift" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid

    try:
        os.unlink("/tmp/.x")
    except FileNotFoundError:
        pass


def test_exec_from_tmp_fires_drift_alert(alerts):
    proc = exec_from_tmp()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "tmp" in a.rule_id.lower() or "drift" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid

    try:
        os.unlink("/tmp/.guard_test_exec")
    except FileNotFoundError:
        pass
