import pytest
from vulnerable_target.app import app as bank_app
from vulnerable_target.database import init_bank_db, set_toggle, get_toggle


def test_vulnerable_app_routes():
    init_bank_db()
    client = bank_app.test_client()

    # 1. Index
    res = client.get("/")
    assert res.status_code == 200
    assert b"Apex Global Bank" in res.data

    # 2. SQLi route in vulnerable vs secure mode
    set_toggle("sqli_enabled", True)
    res = client.get("/search?q=admin%27+OR+%271%27%3D%271")
    assert res.status_code == 200
    assert b"Executed Raw Query" in res.data

    set_toggle("sqli_enabled", False)
    res = client.get("/search?q=ACME")
    assert res.status_code == 200
    assert b"SECURE MODE" in res.data

    # 3. Reflected XSS
    set_toggle("xss_enabled", True)
    res = client.get("/comment?msg=<script>alert(1)</script>")
    assert res.status_code == 200
    assert b"<script>alert(1)</script>" in res.data

    set_toggle("xss_enabled", False)
    res = client.get("/comment?msg=<script>alert(1)</script>")
    assert res.status_code == 200
    assert b"&lt;script&gt;" in res.data

    # 4. RCE
    set_toggle("rce_enabled", True)
    res = client.get("/exec?cmd=whoami")
    assert res.status_code == 200
    assert b"RCE Vulnerable Lab" in res.data

    set_toggle("rce_enabled", False)
    res = client.get("/exec?cmd=cat+/etc/passwd")
    assert res.status_code == 200
    assert b"SECURE MODE REJECTED" in res.data

    # 5. Staff Portal
    res = client.get("/staff")
    assert res.status_code == 200
    assert b"Staff Management" in res.data
