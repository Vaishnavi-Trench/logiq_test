"""Cloud services routes package."""

from fastapi import APIRouter

# Import AWS sub-routers
from app.api.routes.cloud.aws import router as aws_router

# Import GCP sub-routers
from app.api.routes.cloud.gcp import router as gcp_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["cloud"])

# Include AWS router
router.include_router(aws_router, prefix="/aws")

# Include GCP router
router.include_router(gcp_router, prefix="/gcp")
