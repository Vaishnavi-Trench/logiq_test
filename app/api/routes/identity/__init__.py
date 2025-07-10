from fastapi import APIRouter

from app.api.routes.identity.retool import router as retool_router

router = APIRouter(tags=["identity"])


router.include_router(retool_router, prefix="/retool")
