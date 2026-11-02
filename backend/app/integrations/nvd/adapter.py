"""NVD 2.0 API adapter for recently disclosed CVE intelligence."""

import httpx

from app.config import settings
from app.integrations.base import AdapterError


class NvdAdapter:
    key = "nvd"
    category = "vulnerability_intelligence"

    def availability(self) -> dict:
        return {"key": self.key, "category": self.category, "available": True, "mode": "remote_api", "url": settings.nvd_api_url}

    def recent(self, days: int = 7, limit: int = 50) -> list[dict]:
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        params = {"resultsPerPage": min(limit, 2000), "pubStartDate": _nvd_date(days)}
        try:
            response = httpx.get(settings.nvd_api_url, params=params, headers=headers, timeout=45)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AdapterError(f"NVD request failed: {exc}") from exc
        return response.json().get("vulnerabilities", [])

    def get(self, cve_id: str) -> dict:
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        response = httpx.get(settings.nvd_api_url, params={"cveId": cve_id}, headers=headers, timeout=45)
        response.raise_for_status()
        items = response.json().get("vulnerabilities", [])
        if not items:
            raise AdapterError(f"{cve_id} not found in NVD")
        return items[0]


def _nvd_date(days: int) -> str:
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
