def test_bootstrap_and_profile(client, admin_token):
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert me.status_code == 200
    profile = me.json()
    assert "super_admin" in profile["roles"]
    assert "assets:write" in profile["permissions"]
    assert profile["mfa_enabled"] is False


def test_unauthenticated_requests_are_rejected(client):
    assert client.get("/api/v1/assets").status_code == 401
    assert client.get("/api/v1/dashboard/overview").status_code == 401


def test_rbac_denies_developer_asset_access(client, developer_headers):
    # Developers have read-only visibility of inventory but cannot administer users or run scans.
    assert client.get("/api/v1/users", headers=developer_headers).status_code == 403
    assert client.get("/api/v1/dashboard/overview", headers=developer_headers).status_code == 200
    denied_scan = client.post(
        "/api/v1/scans",
        headers=developer_headers,
        json={
            "name": "Unauthorized",
            "scan_type": "port_scan",
            "target": "authorized.example",
            "scope": {"domains": ["authorized.example"]},
            "authorization_reference": "AUTH-X",
        },
    )
    assert denied_scan.status_code == 403


def test_executive_scope(client, executive_headers):
    assert client.get("/api/v1/dashboard/executive", headers=executive_headers).status_code == 200
    assert client.get("/api/v1/findings", headers=executive_headers).status_code == 403
    assert client.get("/api/v1/reports/types", headers=executive_headers).status_code == 200


def test_invalid_token_rejected(client):
    assert client.get("/api/v1/assets", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_tenant_scoping_returns_404_for_foreign_ids(client, admin_headers):
    import uuid

    random_id = uuid.uuid4()
    assert client.get(f"/api/v1/assets/{random_id}", headers=admin_headers).status_code == 404
    assert client.get(f"/api/v1/findings/{random_id}", headers=admin_headers).status_code == 404


def test_logout_revokes_session(client, admin_headers):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@test.atlas", "password": "Testing!Password2026"},
    )
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    # The original admin session remains valid.
    assert client.get("/api/v1/auth/me", headers=admin_headers).status_code == 200
