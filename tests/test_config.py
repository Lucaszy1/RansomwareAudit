from RansomwareAudit.config.manager import ConfigManager


def test_defaults_when_no_file(tmp_path):
    cfg = ConfigManager(config_file=str(tmp_path / "none.yaml"))
    assert cfg.get("web_dashboard.host") == "127.0.0.1"
    assert cfg.get("web_dashboard.debug") is False
    assert cfg.get("risk.high") == 8


def test_user_file_overrides_and_merges(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("risk:\n  high: 99\nweb_dashboard:\n  port: 9000\n")
    cfg = ConfigManager(config_file=str(p))
    assert cfg.get("risk.high") == 99          # overridden
    assert cfg.get("risk.critical") == 12      # default preserved
    assert cfg.get("web_dashboard.port") == 9000
    assert cfg.get("web_dashboard.host") == "127.0.0.1"


def test_missing_key_returns_default(tmp_path):
    cfg = ConfigManager(config_file=str(tmp_path / "none.yaml"))
    assert cfg.get("nope.nope", "fallback") == "fallback"
