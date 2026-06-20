"""
Integration tests: ransomware simulation (frequency-based and pattern-based detection).

These tests require real subprocess activity — Go YAML tests cannot cover
frequency-based rules (N renames in M seconds) or multi-event correlation.
All tests use a per-test temp directory so no cleanup is needed.
"""

import os
import pathlib

import pytest
from attacks.ransomware_attacks import (
    mass_encrypt_files,
    drop_ransom_note,
    delete_backups,
    enumerate_documents,
    rsync_backup,
)


pytestmark = pytest.mark.integration


def test_mass_file_encryption_fires_alert(alerts, tmp):
    proc = mass_encrypt_files(str(tmp), file_count=100)
    pid = proc.pid
    proc.wait(timeout=30)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "ransom" in a.rule_id.lower() or "encrypt" in a.rule_id.lower()
                             or "mass_rename" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.severity in ("warning", "critical")


def test_ransom_note_drop_fires_alert(alerts, tmp):
    note_path = str(tmp / "HOW_TO_DECRYPT.txt")
    proc = drop_ransom_note(note_path)
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "ransom" in a.rule_id.lower() or "note" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_backup_deletion_fires_alert(alerts, tmp):
    backup_dir = tmp / "test_backups"
    backup_dir.mkdir()
    for i in range(10):
        (backup_dir / f"backup_{i}.bak").write_bytes(b"backup data")

    proc = delete_backups(str(backup_dir))
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "backup" in a.rule_id.lower() or "shadow" in a.rule_id.lower()
                             or "delete" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_document_enumeration_fires_alert(alerts, tmp):
    doc_dir = tmp / "docs"
    doc_dir.mkdir()
    for i in range(20):
        (doc_dir / f"file_{i}.txt").write_bytes(os.urandom(512))

    proc = enumerate_documents(str(doc_dir))
    pid = proc.pid
    proc.wait(timeout=15)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "enum" in a.rule_id.lower() or "mass_read" in a.rule_id.lower()
                             or "ransom" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_rsync_backup_does_not_fire(alerts, tmp):
    src = tmp / "src"
    dst = tmp / "dst"
    src.mkdir()
    dst.mkdir()
    for i in range(5):
        (src / f"file_{i}.txt").write_bytes(b"data")

    proc = rsync_backup(str(src) + "/", str(dst))
    pid = proc.pid
    proc.wait(timeout=15)

    alerts.wait_for_no_alert(pid=pid, window=2)
