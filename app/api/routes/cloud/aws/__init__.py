"""AWS routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.cloud.aws.s3 import router as s3_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["aws"])

# Include sub-routers
router.include_router(s3_router, prefix="/s3")
