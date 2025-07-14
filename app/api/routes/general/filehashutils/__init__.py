# filepath: /Users/harish/trench/logiq/app/api/routes/general/filehashutils/__init__.py
"""FileHashUtils routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.general.filehashutils import tools
from fastapi.encoders import jsonable_encoder
import json


class FileHashRequest(BaseModel):
    file_hash: str


class FileHashListResponse(BaseModel):
    result: bool
    description: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["filehashutils"])


@router.post("/is_whitelist_filehash/{intcid}", response_model=FileHashListResponse)
async def is_whitelist_filehash_route(
    intcid: str = Path(..., description="Customer ID"),
    request: FileHashRequest = Body(..., description="File hash request body"),
):
    file_hash = request.file_hash
    Logger.info(f"api: /general/filehashutils/is_whitelist_filehash/{intcid}: {file_hash}")
    try:
        result = tools.is_whitelist_filehash(file_hash, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking whitelist file hash: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking whitelist file hash: {str(e)}"},
        )


@router.post("/is_blocklist_filehash/{intcid}", response_model=FileHashListResponse)
async def is_blocklist_filehash_route(
    intcid: str = Path(..., description="Customer ID"),
    request: FileHashRequest = Body(..., description="File hash request body"),
):
    file_hash = request.file_hash
    Logger.info(f"api: /general/filehashutils/is_blocklist_filehash/{intcid}: {file_hash}")
    try:
        result = tools.is_blocklist_filehash(file_hash, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking blocklist file hash: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking blocklist file hash: {str(e)}"},
        )