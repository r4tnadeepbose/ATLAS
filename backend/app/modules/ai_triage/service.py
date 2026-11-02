"""AI-assisted triage with a deterministic, clearly-labelled fallback.

When no LLM is configured ATLAS still produces heuristic context, marked
``provider=heuristic``. Heuristic output is never presented as model output.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.database.models.findings import Finding
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.ops import AiModelConfiguration, AiPromptVersion
from app.database.models.sbom import VulnerabilityRecord
from app.modules.ai_triage import providers

logger = get_logger("ai_triage")

PROMPT_TEMPLATE = """Analyse this security finding and return the required JSON object.

Finding reference: {finding_ref}
Title: {title}
Category: {category}
Source module: {source_module}
Severity: {severity}
CVSS: {cvss}
CVE: {cve_id}
Status: {status}
Asset: {asset_name}
Asset exposure: {exposure}
Asset criticality: {criticality}
Microservice: {service_name}
Business unit: {business_unit}
Location: {location}
Description: {description}
Known exploitation: {exploitability}
Vulnerability details: {vuln_details}
Remediation currently recorded: {remediation}

Only use the evidence above. State clearly when evidence is insufficient."""


def _context(db: Session, finding: Finding) -> dict:
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    service = db.get(Microservice, finding.microservice_id) if finding.microservice_id else None
    vulnerability = db.get(VulnerabilityRecord, finding.vulnerability_id) if finding.vulnerability_id else None
    return {
        "asset": asset,
        "service": service,
        "vulnerability": vulnerability,
        "values": {
            "finding_ref": finding.finding_ref,
            "title": finding.title,
            "category": finding.category,
            "source_module": finding.source_module,
            "severity": finding.severity,
            "cvss": finding.cvss_score if finding.cvss_score is not None else "not available",
            "cve_id": finding.cve_id or "none",
            "status": finding.status,
            "asset_name": (asset.name if asset else finding.location) or "unlinked",
            "exposure": finding.exposure,
            "criticality": asset.criticality if asset else "unknown",
            "service_name": service.name if service else "unlinked",
            "business_unit": finding.business_unit or (service.business_unit if service else None) or "unknown",
            "location": finding.location or "not recorded",
            "description": (finding.description or "")[:4000],
            "exploitability": finding.exploitability,
            "vuln_details": (vulnerability.description if vulnerability else "No linked vulnerability record")[:3000],
            "remediation": (finding.remediation or "No remediation recorded")[:1500],
        },
    }


def _heuristic(finding: Finding, context: dict) -> dict:
    asset = context["asset"]
    service = context["service"]
    exposure = finding.exposure
    sentences = []
    sentences.append(
        f"{finding.severity.title()} severity finding in {finding.category.replace('_', ' ')} affecting "
        f"{(service.name if service else (asset.name if asset else finding.location or 'an unlinked asset'))}."
    )
    if exposure == "public":
        sentences.append("The asset is internet-facing, which increases practical exposure.")
    else:
        sentences.append("The asset is not classified as internet-facing; exposure depends on internal reachability.")
    if asset and asset.criticality in {"critical", "high"}:
        sentences.append(f"Business criticality is {asset.criticality}, so remediation should be prioritised.")
    if finding.exploitability == "known_exploited":
        sentences.append("The linked intelligence indicates known exploitation activity.")
    if finding.cve_id and finding.cvss_score is not None:
        sentences.append(f"The linked record {finding.cve_id} carries a CVSS score of {finding.cvss_score}.")
    if not finding.cve_id and finding.category == "dependency":
        sentences.append("No CVE identifier is linked; confirm package identity and version before acting.")
    recommendation = finding.remediation or (
        "Validate the finding against the affected asset, confirm the vulnerable version is deployed, "
        "apply the vendor fix or compensating control, and reassess to verify remediation."
    )
    return {
        "classification": f"{finding.category}:{finding.severity}",
        "summary": " ".join(sentences),
        "technical_impact": f"Exploitation impact is constrained to the {finding.category.replace('_', ' ')} path described by the finding evidence.",
        "business_impact": (
            f"Potential impact on {finding.business_unit or 'the owning business unit'} depends on the data and transactions handled by "
            f"{(service.name if service else 'the affected asset')}."
        ),
        "recommendation": recommendation,
        "priority": finding.severity if finding.severity in {"critical", "high", "medium", "low"} else "medium",
        "false_positive_likelihood": round(max(0.05, 1.0 - float(finding.confidence or 0.5)), 2),
        "confidence": round(min(0.6, 0.25 + float(finding.confidence or 0.5) * 0.35), 2),
    }


def triage(
    db: Session,
    *,
    organization_id: uuid.UUID,
    finding: Finding,
    provider_config: dict | None = None,
) -> dict:
    from app.database.models.ops import AiAnalysisHistory, AiTriageResult

    if finding.organization_id != organization_id:
        raise NotFoundError("Finding not found")
    context = _context(db, finding)
    prompt = PROMPT_TEMPLATE.format(**context["values"])
    started = time.perf_counter()
    structured: dict
    provider_name: str
    model_name: str | None
    tokens_in = tokens_out = 0
    advisory = True

    effective = provider_config or {}
    configured_provider = effective.get("provider") or settings.ai_provider
    if configured_provider == "none":
        structured = _heuristic(finding, context)
        provider_name = "heuristic"
        model_name = "atlas-rules-v1"
        advisory = True
        outcome = "heuristic"
    else:
        try:
            response = providers.complete(prompt, model_config=effective)
            structured = providers.parse_structured(response.text)
            provider_name = response.provider
            model_name = response.model
            tokens_in = response.tokens_input
            tokens_out = response.tokens_output
            outcome = "success"
        except providers.ProviderError as exc:
            logger.warning("AI provider failed, falling back to heuristic: %s", exc)
            structured = _heuristic(finding, context)
            provider_name = "heuristic"
            model_name = "atlas-rules-v1"
            outcome = f"provider_error: {exc}"[:250]

    latency_ms = int((time.perf_counter() - started) * 1000)
    result = AiTriageResult(
        organization_id=organization_id,
        finding_id=finding.id,
        provider=provider_name,
        model=model_name,
        status="completed",
        classification=str(structured.get("classification") or "")[:120] or None,
        summary=structured.get("summary"),
        technical_impact=structured.get("technical_impact"),
        business_impact=structured.get("business_impact"),
        recommendation=structured.get("recommendation"),
        priority=str(structured.get("priority") or "medium")[:30],
        false_positive_likelihood=float(structured.get("false_positive_likelihood") or 0.0),
        confidence=float(structured.get("confidence") or 0.0),
        structured={"output": structured, "finding_snapshot": context["values"]},
        prompt_version="v1",
        tokens_input=tokens_in,
        tokens_output=tokens_out,
        latency_ms=latency_ms,
        advisory_only=advisory,
    )
    db.add(result)
    db.flush()
    db.add(
        AiAnalysisHistory(
            organization_id=organization_id,
            triage_id=result.id,
            finding_id=finding.id,
            provider=provider_name,
            request_summary={"prompt_version": "v1", "finding_ref": finding.finding_ref, "provider": configured_provider},
            response_summary={"priority": result.priority, "confidence": result.confidence},
            latency_ms=latency_ms,
            token_usage={"input": tokens_in, "output": tokens_out},
            outcome=outcome,
        )
    )
    db.commit()
    return {
        "id": str(result.id),
        "finding_id": str(finding.id),
        "provider": provider_name,
        "model": model_name,
        "advisory_only": advisory,
        "classified_at": datetime.now(UTC).isoformat(),
        **structured,
        "tokens_input": tokens_in,
        "tokens_output": tokens_out,
        "latency_ms": latency_ms,
    }


def ensure_prompt(db: Session, organization_id: uuid.UUID) -> AiPromptVersion:
    prompt = db.scalar(
        select(AiPromptVersion).where(AiPromptVersion.organization_id == organization_id, AiPromptVersion.prompt_key == "finding_triage", AiPromptVersion.is_active.is_(True))
    )
    if prompt is None:
        prompt = AiPromptVersion(
            organization_id=organization_id,
            prompt_key="finding_triage",
            version="v1",
            template=PROMPT_TEMPLATE,
            is_active=True,
        )
        db.add(prompt)
        db.commit()
    return prompt


def resolve_provider_config(db: Session, organization_id: uuid.UUID) -> dict:
    config = db.scalar(
        select(AiModelConfiguration).where(
            AiModelConfiguration.organization_id == organization_id,
            AiModelConfiguration.enabled.is_(True),
            AiModelConfiguration.is_default.is_(True),
        )
    )
    if config is None:
        return {}
    return {"provider": config.provider, "model": config.model, "base_url": config.base_url, "max_tokens": config.max_tokens}
