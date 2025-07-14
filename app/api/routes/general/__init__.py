"""General utils routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.general.iputils import router as iputils_router
from app.api.routes.general.domainutils import router as domainutils_router
from app.api.routes.general.filehashutils import router as filehashutils_router
from app.api.routes.general.userutils import router as userutils_router
from app.api.routes.general.urlutils import router as urlutils_router
from app.api.routes.general.tools import router as tools_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["general"])

# Include sub-routers
router.include_router(iputils_router, prefix="/iputils")
router.include_router(domainutils_router, prefix="/domainutils")
router.include_router(filehashutils_router, prefix="/filehashutils")
router.include_router(userutils_router, prefix="/userutils")
router.include_router(urlutils_router, prefix="/urlutils")
router.include_router(tools_router, prefix="/tools")
