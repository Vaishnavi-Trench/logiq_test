from fastapi import APIRouter



# Import sub-routers
from app.api.routes.ticketing.jira import router as jira_router
# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["ticketing"])

# Include sub-routers
router.include_router(jira_router, prefix="/jira")
