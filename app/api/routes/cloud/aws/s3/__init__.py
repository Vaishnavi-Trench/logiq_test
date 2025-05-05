"""AWS S3 routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger

# Assuming this is implemented in the services layer
from app.services.cloud.aws.s3.tools import aws_s3_list_files


# Request models
class S3BucketRequest(BaseModel):
    task: str
    bucket_name: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["aws_s3"])


@router.post("/aws_s3_list_files/{intcid}")
async def aws_s3_list_files_route(
    intcid: str = Path(..., description="Customer ID"),
    request: S3BucketRequest = Body(..., description="S3 bucket request"),
):
    """
    List files in an AWS S3 bucket

    Args:
        intcid: Customer ID
        request: Request body containing bucket name

    Returns:
        JSON object with list of files in the bucket
    """
    Logger.info(
        f"api: /cloud/aws/s3/aws_s3_list_files/{intcid}: Listing files in bucket {request.bucket_name}"
    )
    try:
        result = aws_s3_list_files(intcid, request.bucket_name)
        return result
    except Exception as e:
        Logger.error(f"Error listing S3 files: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to list S3 files: {str(e)}"},
        )
