from app.workers.celery_app import celery_app


@celery_app.task(name="atlas.sbom.analyze", bind=True, max_retries=3, default_retry_delay=30)
def analyze_sbom_task(self, organization_id: str, sbom_id: str, use_online: bool = True):
    import uuid

    from app.modules.sbom.service import analyze_in_background

    try:
        analyze_in_background(uuid.UUID(organization_id), uuid.UUID(sbom_id), use_online)
        return {"status": "completed", "sbom_id": sbom_id}
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)
