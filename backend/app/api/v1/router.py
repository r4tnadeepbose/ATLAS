from fastapi import APIRouter

from app.api.v1 import admin
from app.auth.routes import router as auth_router
from app.modules.ai_triage.routes import router as triage_router
from app.modules.api_inventory.routes import router as api_inventory_router
from app.modules.assets.routes import env_router
from app.modules.assets.routes import router as asset_router
from app.modules.attack_surface.routes import router as scan_router
from app.modules.attack_surface.routes import schedule_router
from app.modules.dashboard.routes import router as dashboard_router
from app.modules.data_classification.routes import router as classification_router
from app.modules.microservices.routes import router as service_router
from app.modules.notifications.routes import router as notification_router
from app.modules.reporting.routes import router as report_router
from app.modules.risk_engine.routes import remediation_router
from app.modules.risk_engine.routes import router as risk_router
from app.modules.sbom.routes import router as sbom_router
from app.modules.vulnerabilities.routes import router as finding_router
from app.modules.vulnerabilities.routes import vuln_router
from app.organizations.routes import router as organization_router
from app.users.routes import router as user_router

api_router = APIRouter()

for router in (
    auth_router,
    dashboard_router,
    asset_router,
    env_router,
    service_router,
    sbom_router,
    finding_router,
    vuln_router,
    triage_router,
    scan_router,
    schedule_router,
    api_inventory_router,
    classification_router,
    risk_router,
    remediation_router,
    notification_router,
    report_router,
    organization_router,
    user_router,
    admin.integration_router,
    admin.settings_router,
    admin.rbac_router,
    admin.admin_router,
):
    api_router.include_router(router)
