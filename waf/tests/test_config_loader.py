import os
from pathlib import Path
import tempfile
import pytest

from bastion.core.config import BastionConfig, load_config, reset_config, SiteConfig


def test_default_config_loading():
    reset_config()
    cfg = load_config(Path("/nonexistent/path/bastion.yaml"), set_global=False)
    assert cfg.server.port == 8080
    assert cfg.opensearch.enabled is True
    assert cfg.opensearch.index_prefix == "bastion-waf-events"
    assert cfg.policy.block_threshold == 5.0
    assert cfg.policy.challenge_threshold == 2.5


def test_custom_yaml_parsing():
    yaml_content = """
server:
  host: "127.0.0.1"
  port: 9090

opensearch:
  enabled: true
  hosts:
    - "http://siem.internal:9200"
  index_prefix: "security-waf"

sites:
  - domain: "test.app"
    upstream: "http://10.1.2.3:8000"
    defense_mode: false

policy:
  block_threshold: 4.5
  challenge_threshold: 2.0

rules:
  disabled_rules:
    - "942100"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = Path(f.name)

    try:
        cfg = load_config(temp_path, set_global=False)
        assert cfg.server.port == 9090
        assert cfg.server.host == "127.0.0.1"
        assert cfg.opensearch.hosts == ["http://siem.internal:9200"]
        assert cfg.opensearch.index_prefix == "security-waf"
        assert cfg.policy.block_threshold == 4.5
        assert cfg.rules.disabled_rules == ["942100"]

        # Site resolution
        site = cfg.get_site("test.app")
        assert site is not None
        assert site.upstream == "http://10.1.2.3:8000"
        assert site.defense_mode is False

        target, defense = cfg.resolve_upstream("test.app:9090")
        assert target == "http://10.1.2.3:8000"
        assert defense is False

        # Unknown domain returns None, True
        target_unknown, defense_unknown = cfg.resolve_upstream("unknown.domain")
        assert target_unknown is None
        assert defense_unknown is True
    finally:
        if temp_path.is_file():
            temp_path.unlink()
