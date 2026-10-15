import os
import time

import pytest

from RansomwareAudit.ml.model import RansomwareMLModel, SKLEARN_AVAILABLE


def test_features_use_real_report_fields():
    """Regression test: these were always 0 before the fix."""
    model = RansomwareMLModel()
    feats = model.extract_features({
        "file": "/x/.hidden.sh", "entropy": 7.9, "permissions": "777",
        "size_bytes": 1000, "mtime": time.time(),
    })
    entropy, log_size, is_exec, is_hidden, world_writable, recent = feats
    assert entropy == 7.9
    assert log_size > 6
    assert (is_exec, is_hidden, world_writable, recent) == (1, 1, 1, 1)


def test_iso_timestamp_accepted():
    model = RansomwareMLModel()
    feats = model.extract_features({"file": "a", "permissions": "644", "size_bytes": 1,
                                    "modified_time": "2001-01-01T00:00:00"})
    assert feats[5] == 0.0


@pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")
def test_model_flags_outlier(tmp_path):
    normal = [{"file": f"f{i}.txt", "entropy": 4.5 + (i % 5) * 0.05, "permissions": "644",
               "size_bytes": 2000 + i, "mtime": 0} for i in range(200)]
    model = RansomwareMLModel(model_path=str(tmp_path / "m.pkl"), contamination=0.01)
    assert model.train(normal)
    is_anom, _ = model.predict({"file": "x.bin", "entropy": 8.0, "permissions": "777",
                                "size_bytes": 50_000_000, "mtime": time.time()})
    assert is_anom == 1
    assert model.save_model() and os.path.exists(tmp_path / "m.pkl")


@pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")
def test_tampered_or_unsigned_model_is_refused(tmp_path, monkeypatch):
    """Unpickling runs code, so only models signed with our key may be loaded."""
    import pickle
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("RA_MODEL_KEY", raising=False)
    path = str(tmp_path / "m.pkl")
    normal = [{"file": f"f{i}.txt", "entropy": 4.5, "permissions": "644",
               "size_bytes": 2000 + i, "mtime": 0} for i in range(20)]
    model = RansomwareMLModel(model_path=path)
    assert model.train(normal) and model.save_model()
    assert RansomwareMLModel(model_path=path).load_model()  # signed: loads

    class Evil:  # would run on unpickle if loaded
        def __reduce__(self):
            return (os.system, ("touch " + str(tmp_path / "pwned"),))
    with open(path, "wb") as f:
        pickle.dump(Evil(), f)
    assert not RansomwareMLModel(model_path=path).load_model()
    os.remove(path + ".sig")
    assert not RansomwareMLModel(model_path=path).load_model()
    assert not os.path.exists(tmp_path / "pwned")
    key = tmp_path / "cfg" / "ransomwareaudit" / "model.key"
    assert oct(key.stat().st_mode & 0o777) == "0o600"
