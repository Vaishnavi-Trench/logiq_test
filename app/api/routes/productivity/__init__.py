from fastapi import APIRouter



# Import sub-routers
from app.api.routes.productivity.gworkspace import router as gworkspace_router
from app.api.routes.productivity.slack import router as slack_router
# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["productivity"])

# Include sub-routers
router.include_router(gworkspace_router, prefix="/gworkspace")
router.include_router(slack_router, prefix="/slack")
