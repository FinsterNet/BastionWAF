import os
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from bastion.core.config import load_config, reset_config
from bastion.core.proxy import app as proxy_app


def test_healthz_endpoint():
    """Verify cloud health probe returns HTTP 200 for Render."""
    client = TestClient(proxy_app)
    res = client.get("/healthz")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "bastion-waf"

    # Also test alias /health
    res_alias = client.get("/health")
    assert res_alias.status_code == 200
    assert res_alias.json()["status"] == "healthy"


def test_render_port_environment_override():
    """Verify Render PORT environment variable overrides defaults."""
    old_port = os.environ.get("PORT")
    reset_config()
    try:
        os.environ["PORT"] = "10000"
        cfg = load_config(set_global=False)
        assert cfg.server.port == 10000
    finally:
        if old_port is not None:
            os.environ["PORT"] = old_port
        else:
            os.environ.pop("PORT", None)
        reset_config()
