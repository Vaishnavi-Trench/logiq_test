"""API routes package."""

from fastapi import APIRouter
from app.api.routes.tools import router as tools_router
from app.api.routes.prompt import router as prompt_router
from app.api.routes.intelligence import router as intelligence_router
from app.api.routes.cloud import router as cloud_router
from app.api.routes.siem import router as siem_router
from app.api.routes.general import router as general_router

# Create main API router
api_router = APIRouter()

# Include tools router (with its prefix "/tools")
api_router.include_router(tools_router)

# Include prompt router (with its prefix "/prompt")
api_router.include_router(prompt_router, prefix="/prompt")

# Include intelligence router with explicit prefix
api_router.include_router(intelligence_router, prefix="/intelligence")

# Include cloud router with explicit prefix
api_router.include_router(cloud_router, prefix="/cloud")

# Include siem router with explicit prefix
api_router.include_router(siem_router, prefix="/siem")

# Include sigeneral utils router with explicit prefix
api_router.include_router(general_router, prefix="/general")
