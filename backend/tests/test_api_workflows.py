import json
import time
from datetime import UTC, datetime

from app.database.models.sbom import VulnerabilityRecord
from app.database.session import SessionLocal


def _seed_vulnerability():
    db = SessionLocal()
    try:
        existing = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.identifier == "GHSA-test-0001").first()
        if existing is None:
            db.add(
                VulnerabilityRecord(
                    identifier="GHSA-test-0001",
                    cve_id="CVE-2021-99999",
                    title="Test command injection in lodash",
                    description="Test vulnerability used by the automated suite.",
                    cvss_score=7.2,
                    severity="high",
                    published_at=datetime.now(UTC),
                    source="osv",
                    affected_packages=[
                        {
                            "package": {"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                        }
                    ],
                    fixed_versions=["4.17.21"],
                    remediation="Upgrade lodash to 4.17.21.",
                    raw={"test": True},
                )
            )
            db.commit()
    finally:
        db.close()


def test_sbom_upload_correlates_and_creates_findings(client, admin_headers):
    _seed_vulnerability()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "test-app", "version": "1.0"}},
        "components": [
            {
                "bom-ref": "pkg:npm/lodash@4.17.20",
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
            }
        ],
    }
    upload = client.post(
        "/api/v1/sbom/upload",
        headers=admin_headers,
        files={"file": ("test-app.cdx.json", json.dumps(document), "application/json")},
        data={"analyze": "false"},
    )
    assert upload.status_code == 201, upload.text
    sbom_id = upload.json()["id"]
    assert upload.json()["component_count"] == 2

    analysis = client.post(f"/api/v1/sbom/{sbom_id}/analyze?online=false", headers=admin_headers)
    assert analysis.status_code == 202

    deadline = time.time() + 15
    status = "queued"
    while time.time() < deadline:
        detail = client.get(f"/api/v1/sbom/{sbom_id}", headers=admin_headers).json()
        status = detail["status"]
        if status in {"analyzed", "failed"}:
            break
        time.sleep(0.3)
    assert status == "analyzed", detail
    assert detail["vulnerability_count"] >= 1

    findings = client.get("/api/v1/findings?category=dependency", headers=admin_headers).json()
    assert findings["pagination"]["total"] >= 1
    titles = [item["title"] for item in findings["items"]]
    assert any("lodash" in title for title in titles)


def test_api_spec_import_runs_security_checks(client, admin_headers):
    specification = {
        "openapi": "3.0.3",
        "info": {"title": "Test Public API", "version": "1.0.0"},
        "servers": [{"url": "http://legacy.test.example"}],
        "paths": {
            "/v1/public": {"get": {"summary": "Public endpoint", "security": [], "responses": {"200": {"description": "ok"}}}},
            "/swagger.json": {"get": {"summary": "Docs", "security": [], "responses": {"200": {"description": "ok"}}}},
        },
    }
    response = client.post(
        "/api/v1/apis/import",
        headers=admin_headers,
        files={"file": ("openapi.json", json.dumps(specification), "application/json")},
    )
    assert response.status_code == 201, response.text
    api_id = response.json()["id"]
    detail = client.get(f"/api/v1/apis/{api_id}", headers=admin_headers).json()
    checks = {item["check_key"] for item in detail["security_findings"]}
    assert "missing_authentication" in checks
    assert "insecure_transport" in checks


def test_classification_redacts_secrets(client, admin_headers):
    client.post("/api/v1/classification/seed-rules", headers=admin_headers)
    response = client.post(
        "/api/v1/classification/analyze",
        headers=admin_headers,
        json={
            "text": "email jane@example.com key AKIAIOSFODNN7EXAMPLE password=SuperSecretDemoValue123",
            "source_label": "unit-test",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["detections"] >= 2
    for detection in result["results"]:
        sample = detection["redacted_sample"]
        assert "AKIAIOSFODNN7EXAMPLE" not in sample
        assert "SuperSecretDemoValue123" not in sample
        assert "*" in sample or len(sample) < 8


def test_scan_scope_validation(client, admin_headers):
    denied = client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={
            "name": "Out of scope",
            "scan_type": "port_scan",
            "target": "outside.example",
            "scope": {"domains": ["authorized.example"]},
            "authorization_reference": "AUTH-1",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "scope_violation"

    missing_auth = client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={
            "name": "No authorization",
            "scan_type": "port_scan",
            "target": "authorized.example",
            "scope": {"domains": ["authorized.example"]},
        },
    )
    assert missing_auth.status_code == 422


def test_pdf_report_generation(client, admin_headers):
    created = client.post("/api/v1/reports", headers=admin_headers, json={"report_type": "executive", "format": "pdf"})
    assert created.status_code == 201, created.text
    report_id = created.json()["id"]
    download = client.get(f"/api/v1/reports/{report_id}/download", headers=admin_headers)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/pdf")
    assert download.content.startswith(b"%PDF")
