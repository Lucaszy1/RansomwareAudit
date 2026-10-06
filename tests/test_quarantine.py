import os

import pytest

from RansomwareAudit.quarantine.manager import QuarantineError, QuarantineManager


@pytest.fixture
def vault(tmp_path):
    return QuarantineManager(quarantine_dir=str(tmp_path / "vault"))


def make_file(tmp_path, name="secret.sh", content=b"#!/bin/sh\necho hi\n", mode=0o755):
    p = tmp_path / name
    p.write_bytes(content)
    os.chmod(p, mode)
    return str(p)


def test_quarantine_moves_and_encrypts(vault, tmp_path):
    original = make_file(tmp_path)
    content = open(original, "rb").read()
    entry = vault.quarantine_file(original)
    assert entry and not os.path.exists(original)      # original removed
    stored = open(entry["vault_path"], "rb").read()
    assert content not in stored                        # not stored in the clear


def test_quarantined_file_is_not_executable(vault, tmp_path):
    entry = vault.quarantine_file(make_file(tmp_path))
    mode = os.stat(entry["vault_path"]).st_mode
    assert not (mode & 0o111)                           # no execute bits
    assert not (mode & 0o077)                           # no group/other access


def test_restore_roundtrip_and_hash(vault, tmp_path):
    original = make_file(tmp_path, content=b"important data")
    entry = vault.quarantine_file(original)
    vault.restore_file(entry["id"])
    assert open(original, "rb").read() == b"important data"


def test_restore_refuses_overwrite(vault, tmp_path):
    original = make_file(tmp_path)
    entry = vault.quarantine_file(original)
    open(original, "wb").close()                        # something back at the path
    with pytest.raises(QuarantineError):
        vault.restore_file(entry["id"])
    assert vault.restore_file(entry["id"], force=True)


def test_restore_detects_tampering(vault, tmp_path):
    entry = vault.quarantine_file(make_file(tmp_path))
    with open(entry["vault_path"], "ab") as f:
        f.write(b"tampered")
    with pytest.raises(Exception):
        vault.restore_file(entry["id"])


def test_cannot_quarantine_own_vault_file(vault, tmp_path):
    entry = vault.quarantine_file(make_file(tmp_path))
    assert vault.quarantine_file(entry["vault_path"]) is None
