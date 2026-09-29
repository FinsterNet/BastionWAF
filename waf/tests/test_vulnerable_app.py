"""
WAF Reverse Proxy Integration Tests.
Verifies proxy forwarding, inspection filtering, and defense mode bypass.
"""

from fastapi.testclient import TestClient
from bastion.core.proxy import app as proxy_app
from database.db import init_db


def test_proxy_blocks_attack():
    init_db()
    client = TestClient(proxy_app)

    # Test that attack payload receives 403 Forbidden
    response = client.get("/search?q=%27+OR+%271%27%3D%271")
    assert response.status_code == 403
    assert response.json()["blocked"] is True
    assert response.json()["rule"] == "942100"


def test_proxy_blocks_xss():
    init_db()
    client = TestClient(proxy_app)

    response = client.get("/comment?msg=<script>alert(1)</script>")
    assert response.status_code == 403
    assert response.json()["blocked"] is True
    assert response.json()["rule"] == "941100"
