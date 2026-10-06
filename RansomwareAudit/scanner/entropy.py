"""Shannon entropy of a file's bytes, on a 0-8 bits-per-byte scale.

Reads the file in chunks through a generator so memory stays flat, and only
samples the first `max_bytes` so huge files don't stall a scan.
"""
import math

CHUNK_SIZE = 65_536


def iter_chunks(file_path, max_bytes=None, chunk_size=CHUNK_SIZE):
    """Yield the file's bytes chunk by chunk, stopping after max_bytes."""
    remaining = max_bytes
    with open(file_path, "rb") as f:
        while remaining is None or remaining > 0:
            size = chunk_size if remaining is None else min(chunk_size, remaining)
            chunk = f.read(size)
            if not chunk:
                return
            if remaining is not None:
                remaining -= len(chunk)
            yield chunk


def entropy_of_bytes(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return _entropy_from_counts(counts, len(data))


def _entropy_from_counts(counts, total):
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def calculate_entropy(file_path, max_bytes=1_048_576):
    """Return entropy for the file, or 0.0 if it can't be read."""
    counts = [0] * 256
    total = 0
    try:
        for chunk in iter_chunks(file_path, max_bytes):
            for b in chunk:
                counts[b] += 1
            total += len(chunk)
    except OSError:
        return 0.0
    return _entropy_from_counts(counts, total) if total else 0.0
