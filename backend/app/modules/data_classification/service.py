"""Data classification: regex, entropy-based secret detection and redaction.

Detected values are never stored in full: samples are masked before they touch
the database or the API response.
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.refs import next_ref
from app.database.models.classification import ClassificationRule, DataClassification, SensitiveDataFinding
from app.database.models.findings import Finding, FindingStatusHistory
from app.database.models.infrastructure import Asset
from app.modules.risk_engine.scoring import compute_finding_risk, sla_due

DEFAULT_RULES: list[dict] = [
    {
        "name": "Email addresses (PII)",
        "category": "pii",
        "detection_method": "regex",
        "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "severity": "medium",
        "description": "Personally identifiable email address",
    },
    {
        "name": "US social security numbers",
        "category": "pii",
        "detection_method": "regex",
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "high",
        "description": "US SSN pattern",
    },
    {
        "name": "Payment card numbers",
        "category": "financial",
        "detection_method": "regex",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "severity": "critical",
        "description": "Card number pattern (Visa/Mastercard/Amex)",
    },
    {
        "name": "Private key material",
        "category": "credentials",
        "detection_method": "regex",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Embedded private key block",
    },
    {
        "name": "AWS access keys",
        "category": "api_keys",
        "detection_method": "regex",
        "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "severity": "critical",
        "description": "AWS access key identifier",
    },
    {
        "name": "JSON Web Tokens",
        "category": "access_tokens",
        "detection_method": "regex",
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "severity": "high",
        "description": "Signed JWT",
    },
    {
        "name": "Password assignments",
        "category": "credentials",
        "detection_method": "regex",
        "pattern": r"(?i)\b(?:password|passwd|secret)\b\s*[:=]\s*['\"]?([^\s'\"]{6,})",
        "severity": "high",
        "description": "Hard-coded credential assignment",
    },
    {
        "name": "High-entropy secrets",
        "category": "access_tokens",
        "detection_method": "entropy",
        "pattern": r"\b[A-Za-z0-9_\-+/=]{24,}\b",
        "severity": "medium",
        "description": "Token-like string with high Shannon entropy",
    },
]

CATEGORY_RISK = {
    "credentials": "critical",
    "api_keys": "critical",
    "access_tokens": "high",
    "financial": "high",
    "pii": "high",
    "confidential": "medium",
    "internal": "low",
    "public": "info",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "*" * len(value)
    visible = 3 if len(value) < 16 else 4
    return f"{value[:visible]}{'*' * min(len(value) - visible - 2, 24)}{value[-2:]}"


def seed_rules(db: Session, organization_id: uuid.UUID) -> int:
    existing = db.scalar(select(ClassificationRule.id).where(ClassificationRule.organization_id == organization_id))
    if existing:
        return 0
    for rule in DEFAULT_RULES:
        db.add(ClassificationRule(organization_id=organization_id, enabled=True, confidence_weight=0.85, **rule))
    db.commit()
    return len(DEFAULT_RULES)


def analyze_text(
    db: Session,
    *,
    organization_id: uuid.UUID,
    text: str,
    source_label: str,
    asset_id: uuid.UUID | None = None,
    microservice_id: uuid.UUID | None = None,
    service_name: str | None = None,
) -> dict:
    rules = db.scalars(
        select(ClassificationRule).where(ClassificationRule.organization_id == organization_id, ClassificationRule.enabled.is_(True))
    ).all()
    # Deterministic regex rules run first so entropy detection does not produce
    # overlapping duplicates of the same secret.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rules = sorted(rules, key=lambda rule: (rule.detection_method == "entropy", severity_rank.get(rule.severity, 4)))
    accepted_spans: list[tuple[int, int]] = []
    asset = db.get(Asset, asset_id) if asset_id else None
    exposure = asset.exposure if asset else "internal"
    results = []
    created_findings = 0
    for rule in rules:
        if not rule.pattern:
            continue
        try:
            pattern = re.compile(rule.pattern)
        except re.error:
            continue
        for match in pattern.finditer(text):
            start, end = match.span()
            candidate = match.group(0)
            if any(not (end <= s or start >= e) for s, e in accepted_spans):
                continue
            if rule.detection_method == "entropy":
                if shannon_entropy(candidate) < 3.6:
                    continue
                if candidate.startswith("eyJ"):
                    continue
                if (start > 0 and text[start - 1] == ".") or (end < len(text) and text[end] == "."):
                    continue
            accepted_spans.append((start, end))
            masked = redact(candidate)
            classification = DataClassification(
                organization_id=organization_id,
                asset_id=asset_id,
                microservice_id=microservice_id,
                category=rule.category,
                detection_method=rule.detection_method,
                confidence=rule.confidence_weight,
                exposure_location=f"{source_label}:{match.start()}-{match.end()}",
                service_name=service_name,
                risk_classification=CATEGORY_RISK.get(rule.category, "medium"),
                remediation="Rotate exposed credentials, remove sensitive values from the source, and enforce secret management.",
                last_seen=datetime.now(UTC),
            )
            db.add(classification)
            db.flush()
            db.add(
                SensitiveDataFinding(
                    organization_id=organization_id,
                    classification_id=classification.id,
                    rule_id=rule.id,
                    category=rule.category,
                    redacted_sample=masked,
                    location=classification.exposure_location,
                    confidence=rule.confidence_weight,
                    severity=rule.severity,
                    metadata_json={"rule": rule.name, "detection_method": rule.detection_method},
                )
            )
            results.append(
                {
                    "category": rule.category,
                    "rule": rule.name,
                    "severity": rule.severity,
                    "redacted_sample": masked,
                    "location": classification.exposure_location,
                    "confidence": rule.confidence_weight,
                }
            )
            if rule.severity in {"critical", "high"}:
                dedup = f"classification:{asset_id or 'source'}:{rule.category}:{hashlib.sha256(masked.encode()).hexdigest()[:16]}"
                existing = db.scalar(select(Finding.id).where(Finding.organization_id == organization_id, Finding.dedup_key == dedup))
                if existing is None:
                    risk, _band, _factors = compute_finding_risk(
                        severity=rule.severity,
                        exposure=exposure,
                        criticality=asset.criticality if asset else "medium",
                        sensitive_data=True,
                        first_seen=datetime.now(UTC),
                    )
                    finding = Finding(
                        organization_id=organization_id,
                        finding_ref=next_ref(db, Finding, "finding_ref", "FND", organization_id),
                        title=f"{rule.name} detected in {source_label}"[:300],
                        description=f"{rule.description}. Detected value is redacted in ATLAS.",
                        category="sensitive_data",
                        source_module="data_classification",
                        severity=rule.severity,
                        status="open",
                        asset_id=asset_id,
                        microservice_id=microservice_id,
                        business_unit=asset.business_unit if asset else None,
                        environment_id=asset.environment_id if asset else None,
                        exposure=exposure,
                        confidence=rule.confidence_weight,
                        risk_score=risk,
                        dedup_key=dedup,
                        location=source_label[:500],
                        remediation=classification.remediation,
                        first_seen=datetime.now(UTC),
                        last_seen=datetime.now(UTC),
                        sla_due_at=sla_due(rule.severity, datetime.now(UTC)),
                        tags=[rule.category],
                    )
                    db.add(finding)
                    db.flush()
                    db.add(FindingStatusHistory(organization_id=organization_id, finding_id=finding.id, to_status="open", note="Detected by data classification"))
                    classification.finding_id = finding.id
                    created_findings += 1
    db.commit()
    categories = sorted({result["category"] for result in results})
    return {"detections": len(results), "categories": categories, "created_findings": created_findings, "results": results}
