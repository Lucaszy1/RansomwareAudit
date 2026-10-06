import os

from RansomwareAudit.scanner.entropy import calculate_entropy, entropy_of_bytes
from RansomwareAudit.scanner.permissions import get_permissions, is_executable, is_world_writable


def test_entropy_bounds(tmp_path):
    zeros = tmp_path / "zeros.bin"
    zeros.write_bytes(b"\x00" * 10_000)
    rand = tmp_path / "rand.bin"
    rand.write_bytes(os.urandom(200_000))
    assert calculate_entropy(str(zeros)) == 0.0
    assert calculate_entropy(str(rand)) > 7.9


def test_chunked_entropy_matches_whole_file(tmp_path):
    p = tmp_path / "mixed.bin"
    data = os.urandom(100_000) + b"A" * 150_000
    p.write_bytes(data)
    assert abs(calculate_entropy(str(p), max_bytes=None) - entropy_of_bytes(data)) < 1e-9


def test_entropy_sampling_limits_bytes_read(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"A" * 100_000 + os.urandom(100_000))
    assert calculate_entropy(str(p), max_bytes=50_000) == 0.0


def test_missing_file_entropy_is_zero(tmp_path):
    assert calculate_entropy(str(tmp_path / "nope")) == 0.0


def test_permission_helpers(tmp_path):
    p = tmp_path / "f"
    p.write_text("x")
    os.chmod(p, 0o644)
    assert get_permissions(str(p)) == "644"
    assert not is_executable("644") and is_executable("755") and is_executable("701")
    assert is_world_writable("666") and is_world_writable("777") and not is_world_writable("664")
