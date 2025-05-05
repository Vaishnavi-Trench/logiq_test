"""General Ip utils routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.general.iputils import router as iputils_router
from app.api.routes.general.tools import router as tools_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["general"])

# Include sub-routers
router.include_router(iputils_router, prefix="/iputils")
router.include_router(tools_router, prefix="/tools")
