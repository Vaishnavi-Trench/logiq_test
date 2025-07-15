"""Intelligence routes package."""

from fastapi import APIRouter

# Import sub-routers
from app.api.routes.intelligence.ipinfo import router as ipinfo_router
from app.api.routes.intelligence.virustotal import router as virustotal_router
from app.api.routes.intelligence.abuseipdb import router as abuseipdb_router
from app.api.routes.intelligence.spycloud import router as spycloud_router
from app.api.routes.intelligence.shodan import router as shodan_router  # 👈 Add this line

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["intelligence"])

# Include sub-routers
router.include_router(ipinfo_router, prefix="/ipinfo")
router.include_router(virustotal_router, prefix="/virustotal")
router.include_router(abuseipdb_router, prefix="/abuse")
router.include_router(spycloud_router, prefix="/spycloud")
router.include_router(shodan_router, prefix="/shodan")  # 👈 And this line
