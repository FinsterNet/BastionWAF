from fastapi.testclient import TestClient
from api.server import app as api_app
from database.db import init_db, get_stats, get_rules, set_rule_state, add_site, get_sites, delete_site, clear_logs


def test_database_crud_and_queries():
    init_db()
    stats = get_stats()
    assert "total_requests" in stats
    assert "blocked_attacks" in stats

    rules = get_rules()
    assert len(rules) >= 5

    set_rule_state("942100", False)
    updated_rules = {r["rule_id"]: r["enabled"] for r in get_rules()}
    assert updated_rules["942100"] is False
    set_rule_state("942100", True)

    add_site("testsite.local", "127.0.0.1:9999")
    sites = get_sites()
    test_site = next((s for s in sites if s["domain"] == "testsite.local"), None)
    assert test_site is not None
    assert test_site["upstream"] == "127.0.0.1:9999"

    delete_site(test_site["id"])
    sites_after = get_sites()
    assert not any(s["domain"] == "testsite.local" for s in sites_after)


def test_api_server_endpoints():
    client = TestClient(api_app)

    res = client.get("/api/stats")
    assert res.status_code == 200
    assert "total_requests" in res.json()

    res = client.get("/api/rules")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    res = client.get("/api/sites")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    res = client.get("/api/system")
    assert res.status_code == 200
    assert "uptime" in res.json()
    assert "cpu_percent" in res.json()

    res = client.get("/api/export/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
