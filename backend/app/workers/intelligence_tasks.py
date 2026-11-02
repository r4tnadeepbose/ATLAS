from app.workers.celery_app import celery_app


@celery_app.task(name="atlas.intelligence.osv_lookup")
def osv_lookup_task(identifier: str):
    from app.database.session import SessionLocal
    from app.integrations.osv.adapter import OsvAdapter
    from app.modules.sbom.service import _upsert_vulnerability

    db = SessionLocal()
    try:
        raw = OsvAdapter().get(identifier)
        record = _upsert_vulnerability(db, raw)
        db.commit()
        return {"status": "ok", "identifier": record.identifier}
    finally:
        db.close()


@celery_app.task(name="atlas.intelligence.reanalyze_org")
def reanalyze_organization_sboms(organization_id: str):
    import uuid

    from sqlalchemy import select

    from app.database.models.sbom import SbomDocument
    from app.database.session import SessionLocal
    from app.modules.sbom.service import correlate

    db = SessionLocal()
    try:
        documents = db.scalars(
            select(SbomDocument).where(SbomDocument.organization_id == uuid.UUID(organization_id))
        ).all()
        results = []
        for document in documents:
            results.append(correlate(db, document, use_online=True))
        return {"status": "ok", "documents": len(results)}
    finally:
        db.close()
