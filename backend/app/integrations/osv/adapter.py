"""OSV intelligence adapter (read path).

The SBOM module queries OSV through ``app.modules.sbom.matching``; this adapter
exposes a single-record lookup for the vulnerability browser and manual
imports.
"""

import httpx

from app.config import settings
from app.integrations.base import AdapterError


class OsvAdapter:
    key = "osv"
    category = "vulnerability_intelligence"

    def availability(self) -> dict:
        return {"key": self.key, "category": self.category, "available": True, "mode": "remote_api", "url": settings.osv_api_url}

    def get(self, identifier: str) -> dict:
        response = httpx.get(f"{settings.osv_api_url.replace('/v1', '')}/v1/vulns/{identifier}", timeout=30)
        if response.status_code == 404:
            raise AdapterError(f"{identifier} not found in OSV")
        response.raise_for_status()
        return response.json()

    def query_package(self, purl: str, version: str | None = None) -> dict:
        payload = {"package": {"purl": purl}}
        if version:
            payload["version"] = version
        response = httpx.post(f"{settings.osv_api_url}/query", json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
