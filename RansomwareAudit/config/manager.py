"""Loads config.yaml and merges it over safe defaults.

Every module reads its settings through get_config(), so changing a value in
config.yaml actually changes behavior (earlier versions hardcoded everything).
"""
import copy
import os

try:
    import yaml
except ImportError:  # PyYAML is optional; defaults still work without it
    yaml = None

DEFAULT_CONFIG = {
    "scanner": {
        "exclude_directories": [".git", "__pycache__", "node_modules",
                                "quarantine_vault", "ransomware_backups", ".venv", "venv"],
        "entropy_threshold": 7.5,
        "entropy_sample_bytes": 1_048_576,  # read at most 1 MB per file for entropy
        "max_file_size_mb": 100,
    },
    "risk": {
        # file score -> level; also used for the overall scan level
        "medium": 4,
        "high": 8,
        "critical": 12,
    },
    "behavior": {
        "time_window_seconds": 60,
        "burst_file_count": 20,
    },
    "monitoring": {
        "interval_seconds": 5,
        "sliding_window_seconds": 30,
        "mass_modify_count": 50,
        "mass_delete_count": 20,
        "mass_rename_count": 10,
    },
    "machine_learning": {
        "enabled": True,
        "model_path": "ransomware_ml_model.pkl",
        "contamination": 0.1,
    },
    "quarantine": {
        "enabled": True,
        "auto_quarantine": False,
        "quarantine_threshold": 8,
        "quarantine_dir": "quarantine_vault",
    },
    "backup": {"backup_dir": "ransomware_backups", "max_backups": 10},
    "virustotal": {"enabled": False, "rate_limit_delay": 15, "max_files": 5},
    "web_dashboard": {
        "host": "127.0.0.1",
        "port": 5001,
        "debug": False,
        # only paths under these roots may be scanned from the dashboard
        "allowed_scan_roots": ["~"],
    },
    "network": {"server_host": "127.0.0.1", "server_port": 5000},
}


def _deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class ConfigManager:
    def __init__(self, config_file=None):
        self.config_file = config_file or os.environ.get("RA_CONFIG", "config.yaml")
        self.config = self.load_config()

    def load_config(self):
        if yaml is None or not os.path.exists(self.config_file):
            return copy.deepcopy(DEFAULT_CONFIG)
        try:
            with open(self.config_file, "r") as f:
                user_config = yaml.safe_load(f) or {}
            return _deep_merge(DEFAULT_CONFIG, user_config)
        except Exception as e:
            print(f"[ERROR] Failed to load {self.config_file}, using defaults: {e}")
            return copy.deepcopy(DEFAULT_CONFIG)

    def get(self, key_path, default=None):
        value = self.config
        for key in key_path.split("."):
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value


_config = None


def get_config(reload=False):
    global _config
    if _config is None or reload:
        _config = ConfigManager()
    return _config
