"""Version comparison and OSV vulnerability matching."""

from __future__ import annotations

import re
from datetime import datetime

import httpx

from app.config import settings
from app.core.logging import get_logger

logger = get_logger("sbom.matching")

_PRE_RELEASE = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "rc": -3, "pre": -2, "dev": -6, "snapshot": -7}


def _tokenize(version: str) -> list:
    version = version.strip().lower().lstrip("v")
    tokens: list = []
    for part in re.split(r"[.\-+_]", version):
        if not part:
            continue
        if part.isdigit():
            tokens.append(int(part))
        else:
            match = re.match(r"(\d+)([a-z]+)(\d*)", part)
            if match:
                tokens.extend([int(match.group(1)), _PRE_RELEASE.get(match.group(2), 0), int(match.group(3) or 0)])
            else:
                suffix = re.match(r"([a-z]+)(\d*)$", part)
                if suffix:
                    tokens.extend([_PRE_RELEASE.get(suffix.group(1), 0), int(suffix.group(2) or 0)])
                else:
                    tokens.append(_PRE_RELEASE.get(part, 0))
    return tokens


def compare_versions(left: str, right: str) -> int:
    a = _tokenize(left)
    b = _tokenize(right)
    for index in range(max(len(a), len(b))):
        va = a[index] if index < len(a) else 0
        vb = b[index] if index < len(b) else 0
        if isinstance(va, int) and isinstance(vb, int):
            if va != vb:
                return -1 if va < vb else 1
        else:
            sa, sb = str(va), str(vb)
            if sa != sb:
                return -1 if sa < sb else 1
    return 0


def is_affected(version: str | None, affected: list[dict]) -> bool:
    if not version or not affected:
        return False
    for entry in affected:
        for rng in entry.get("ranges") or []:
            introduced = None
            fixed = None
            last_affected = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]
            if introduced and introduced != "0" and compare_versions(version, introduced) < 0:
                continue
            if fixed and compare_versions(version, fixed) >= 0:
                continue
            if last_affected and compare_versions(version, last_affected) > 0:
                continue
            return True
        for explicit in entry.get("versions") or []:
            if compare_versions(version, explicit) == 0:
                return True
    return False


def first_fixed_version(affected: list[dict]) -> str | None:
    for entry in affected:
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    return event["fixed"]
    return None


def severity_from_osv(vulnerability: dict) -> tuple[str, float | None, str | None]:
    score = None
    vector = None
    for severity in vulnerability.get("severity") or []:
        if severity.get("type", "").startswith("CVSS"):
            vector = severity.get("score")
            score = _cvss_base_score(vector)
            break
    database_specific = vulnerability.get("database_specific") or {}
    severity_label = (database_specific.get("severity") or "").lower()
    if not severity_label and score is not None:
        severity_label = band_from_cvss(score)
    if not severity_label:
        severity_label = "medium"
    if severity_label not in {"critical", "high", "medium", "low", "info"}:
        severity_label = "medium"
    return severity_label, score, vector


def band_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _cvss_base_score(vector: str | None) -> float | None:
    if not vector:
        return None
    try:
        if vector.startswith("CVSS:4"):
            return None  # CVSS v4 scoring requires the full calculator; store vector only.
        parts = dict(item.split(":", 1) for item in vector.split("/") if ":" in item)
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27} if parts.get("S") != "C" else {"N": 0.85, "L": 0.68, "H": 0.5}
        pr = pr_map.get(parts.get("PR", "N"), 0.85)
        ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
        scope_changed = parts.get("S") == "C"
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = cia.get(parts.get("C", "N"), 0.0)
        i = cia.get(parts.get("I", "N"), 0.0)
        a = cia.get(parts.get("A", "N"), 0.0)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if scope_changed else 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        if scope_changed:
            return round(min(10.0, 1.08 * (impact + exploitability)), 1)
        return round(min(10.0, impact + exploitability), 1)
    except (ValueError, ZeroDivisionError):
        return None


async def query_osv(components: list[tuple[str, str | None]]) -> dict[str, list[dict]]:
    """Query OSV for purls. Returns mapping purl -> vulnerabilities.

    Failures are surfaced to the caller as an empty mapping with a logged
    warning; the offline correlation path still runs.
    """
    purls = [(purl, version) for purl, version in components if purl and purl.startswith("pkg:")]
    if not purls:
        return {}
    results: dict[str, list[dict]] = {}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            for start in range(0, len(purls), 1000):
                batch = purls[start : start + 1000]
                payload = {"queries": [{"package": {"purl": purl}, "version": version} if version else {"package": {"purl": purl}} for purl, version in batch]}
                response = await client.post(f"{settings.osv_api_url}/querybatch", json=payload)
                response.raise_for_status()
                data = response.json()
                for (purl, _version), result in zip(batch, data.get("results", []), strict=False):
                    if result.get("vulns"):
                        results[purl] = result["vulns"]
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("osv query failed: %s", exc)
    return results


def parse_osv_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
