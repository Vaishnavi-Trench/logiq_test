from fastapi import APIRouter



# Import sub-routers
from app.api.routes.endpoint.crowdstrike import router as crowdstrike_router

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["endpoint"])

# Include sub-routers
router.include_router(crowdstrike_router, prefix="/crowdstrike")

