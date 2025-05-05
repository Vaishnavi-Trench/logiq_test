"""GCP routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.cloud.gcp.gcs import router as gcs_router
from app.api.routes.cloud.gcp.audit_logs import router as audit_logs_router
from app.api.routes.cloud.gcp.iam import router as iam_router
from app.api.routes.cloud.gcp.logging import router as logging_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["gcp"])

# Include sub-routers
router.include_router(gcs_router, prefix="/gcs")
router.include_router(audit_logs_router, prefix="/audit_logs")
router.include_router(iam_router, prefix="/iam")
router.include_router(logging_router, prefix="/logging")
