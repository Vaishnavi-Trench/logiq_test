"""Intelligence routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.orbit.tablename import router as tablename_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["orbit"])

# Include sub-routers
router.include_router(tablename_router, prefix="/tablename")
