from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models.api_inventory import Api, ApiSecurityFinding
from app.database.models.findings import Finding
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.risk import RemediationTask, RiskAssessment
from app.database.models.sbom import SbomDocument, VulnerabilityRecord
from app.database.models.scans import ScanJob
from app.modules.dashboard.service import overview, risk_by_business_unit

REPORT_TYPES = {
    "executive": "Executive Security Report",
    "vulnerability": "Vulnerability Assessment Report",
    "sbom": "SBOM Intelligence Report",
    "attack_surface": "Attack Surface Report",
    "api_security": "API Security Report",
    "risk": "Risk Assessment Report",
    "remediation": "Remediation Report",
}


def build_report(db: Session, organization_id: uuid.UUID, report_type: str) -> dict:
    if report_type not in REPORT_TYPES:
        from app.core.exceptions import ValidationError

        raise ValidationError("Unknown report type", details={"allowed": sorted(REPORT_TYPES)})
    generated_at = datetime.now(UTC).isoformat()
    if report_type == "executive":
        data = overview(db, organization_id)
        data["business_units"] = risk_by_business_unit(db, organization_id)
        data["top_risks"] = [
            {
                "score": assessment.score,
                "severity": assessment.severity,
                "business_unit": assessment.business_unit,
                "status": assessment.status,
            }
            for assessment in db.scalars(
                select(RiskAssessment).where(RiskAssessment.organization_id == organization_id).order_by(RiskAssessment.score.desc()).limit(20)
            ).all()
        ]
    elif report_type == "vulnerability":
        findings = db.scalars(select(Finding).where(Finding.organization_id == organization_id).limit(5000)).all()
        data = {"findings": [_finding_row(item) for item in findings], "total": len(findings)}
    elif report_type == "sbom":
        documents = db.scalars(select(SbomDocument).where(SbomDocument.organization_id == organization_id)).all()
        data = {
            "documents": [
                {
                    "name": doc.name,
                    "format": doc.format,
                    "components": doc.component_count,
                    "vulnerabilities": doc.vulnerability_count,
                    "status": doc.status,
                }
                for doc in documents
            ],
            "vulnerability_records": db.scalar(select(VulnerabilityRecord.id).where(VulnerabilityRecord.id.is_not(None)).limit(1)) is not None,
        }
    elif report_type == "attack_surface":
        assets = db.scalars(select(Asset).where(Asset.organization_id == organization_id, Asset.deleted_at.is_(None))).all()
        scans = db.scalars(select(ScanJob).where(ScanJob.organization_id == organization_id).order_by(ScanJob.created_at.desc()).limit(100)).all()
        data = {
            "assets": [{"name": a.name, "domain": a.domain, "exposure": a.exposure, "risk_score": a.risk_score, "status": a.status} for a in assets],
            "scans": [{"name": s.name, "type": s.scan_type, "target": s.target, "status": s.status, "findings": s.findings_count} for s in scans],
        }
    elif report_type == "api_security":
        apis = db.scalars(select(Api).where(Api.organization_id == organization_id, Api.deleted_at.is_(None))).all()
        findings = db.scalars(select(ApiSecurityFinding).where(ApiSecurityFinding.organization_id == organization_id)).all()
        data = {
            "apis": [
                {"name": a.name, "base_url": a.base_url, "auth": a.auth_type, "exposure": a.exposure, "security_status": a.security_status}
                for a in apis
            ],
            "security_findings": [{"check": f.check_key, "severity": f.severity, "status": f.status} for f in findings],
        }
    elif report_type == "risk":
        assessments = db.scalars(select(RiskAssessment).where(RiskAssessment.organization_id == organization_id)).all()
        data = {
            "assessments": [
                {
                    "score": a.score,
                    "severity": a.severity,
                    "business_unit": a.business_unit,
                    "status": a.status,
                    "deadline": a.remediation_deadline.isoformat() if a.remediation_deadline else None,
                }
                for a in assessments
            ],
            "model": "atlas-risk-v1",
        }
    else:
        tasks = db.scalars(select(RemediationTask).where(RemediationTask.organization_id == organization_id)).all()
        data = {
            "tasks": [
                {"title": t.title, "status": t.status, "priority": t.priority, "due_at": t.due_at.isoformat() if t.due_at else None}
                for t in tasks
            ],
            "completed": len([t for t in tasks if t.status == "completed"]),
            "open": len([t for t in tasks if t.status != "completed"]),
        }
    return {"report_type": report_type, "title": REPORT_TYPES[report_type], "generated_at": generated_at, "data": data}


def _finding_row(finding: Finding) -> dict:
    return {
        "reference": finding.finding_ref,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "category": finding.category,
        "cvss": finding.cvss_score,
        "risk_score": finding.risk_score,
        "cve": finding.cve_id,
        "business_unit": finding.business_unit,
        "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
    }


def to_csv(report: dict) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["report", report["title"], "generated_at", report["generated_at"]])
    data = report["data"]
    for key, value in data.items():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            writer.writerow([])
            writer.writerow([key])
            headers = list(value[0].keys())
            writer.writerow(headers)
            for row in value:
                writer.writerow([row.get(header, "") for header in headers])
        elif not isinstance(value, (dict, list)):
            writer.writerow([key, value])
        elif isinstance(value, dict):
            writer.writerow([])
            writer.writerow([key])
            for sub_key, sub_value in value.items():
                if not isinstance(sub_value, (dict, list)):
                    writer.writerow([sub_key, sub_value])
    return buffer.getvalue().encode("utf-8")


def to_pdf(report: dict) -> bytes:
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, title=report["title"], author="ATLAS")
    styles = getSampleStyleSheet()
    story = [Paragraph("ATLAS", styles["Title"]), Paragraph(report["title"], styles["Heading1"])]
    story.append(Paragraph(f"Generated {report['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 16))
    data = report["data"]
    for key, value in data.items():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            headers = list(value[0].keys())
            rows = [[str(row.get(header, ""))[:60] for header in headers] for row in value[:40]]
            story.append(Paragraph(key.replace("_", " ").title(), styles["Heading2"]))
            table = Table([headers] + rows, repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#8892A0")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 12))
        elif isinstance(value, dict):
            story.append(Paragraph(key.replace("_", " ").title(), styles["Heading2"]))
            rows = [[str(sub_key), str(sub_value)[:80]] for sub_key, sub_value in value.items() if not isinstance(sub_value, (dict, list))]
            if rows:
                table = Table([["Metric", "Value"]] + rows)
                table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#8892A0")), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
                story.append(table)
            story.append(Spacer(1, 12))
        else:
            story.append(Paragraph(f"{key.replace('_', ' ').title()}: {value}", styles["Normal"]))
    story.append(PageBreak())
    story.append(Paragraph("This report is generated from ATLAS platform data. AI-assisted content is advisory only.", styles["Italic"]))
    document.build(story)
    return buffer.getvalue()
