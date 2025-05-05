"""SIEM routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.siem.splunk import router as splunk_router
from app.api.routes.siem.wazuh import router as wazuh_router
from app.api.routes.siem.sentinel import router as sentinel_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["siem"])

# Include sub-routers
router.include_router(splunk_router, prefix="/splunk")
router.include_router(wazuh_router, prefix="/wazuh")
router.include_router(sentinel_router, prefix="/sentinel")
