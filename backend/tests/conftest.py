import os
import pathlib
import uuid

import pytest

ROOT = pathlib.Path(__file__).resolve().parent
TEST_DB = ROOT / "atlas_test.db"

os.environ["ATLAS_APP_ENV"] = "test"
os.environ["ATLAS_SECRET_KEY"] = "atlas-test-signing-key-that-is-long-enough-48"
os.environ["ATLAS_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["ATLAS_SEED_DEMO_DATA"] = "false"
os.environ["ATLAS_RATE_LIMIT_PER_MINUTE"] = "10000"

BOOTSTRAP = {
    "organization_name": "Test Security Org",
    "full_name": "Test Owner",
    "email": "owner@test.atlas",
    "password": "Testing!Password2026",
}


@pytest.fixture(scope="session")
def client():
    if TEST_DB.exists():
        TEST_DB.unlink()
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    from app.database.session import engine

    engine.dispose()
    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture(scope="session")
def admin_token(client) -> str:
    status = client.get("/api/v1/auth/bootstrap-status").json()
    if status["requires_bootstrap"]:
        response = client.post("/api/v1/auth/bootstrap", json=BOOTSTRAP)
        assert response.status_code == 201, response.text
    response = client.post(
        "/api/v1/auth/login",
        json={"email": BOOTSTRAP["email"], "password": BOOTSTRAP["password"]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def developer_headers(client, admin_headers) -> dict:
    email = f"developer-{uuid.uuid4().hex[:6]}@test.atlas"
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Dev User",
            "password": "Developer!Password2026",
            "role": "developer",
        },
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": "Developer!Password2026"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.fixture(scope="session")
def executive_headers(client, admin_headers) -> dict:
    email = f"exec-{uuid.uuid4().hex[:6]}@test.atlas"
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Exec User",
            "password": "Executive!Password2026",
            "role": "executive",
        },
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": "Executive!Password2026"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
