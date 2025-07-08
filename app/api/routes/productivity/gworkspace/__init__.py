from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any, Optional
from pltfrm import Logger2 as Logger
from app.services.productivity.gworkspace.tools import (
    disable_user_account,
    enable_user_account,
    send_email,
    reset_user_password
)
from fastapi.encoders import jsonable_encoder
import json



class GWorkspaceRequest(BaseModel):
    task: Optional[str] = None
    email_address: str

class EmailRequest(BaseModel):
    task: Optional[str] = None
    recipient_email: str
    subject: str
    message_body: str

class ResetPasswordRequest(BaseModel):
    task: Optional[str] = None
    email_address: str
    new_password: Optional[str] = None

router = APIRouter(tags=["gworkspace"])


@router.post("/disable_user_account/{intcid}", response_model=dict)
async def disable_user_account_route(
    intcid: str,
    request: GWorkspaceRequest
):
    email_address = request.email_address
    if not email_address:
        Logger.error("Email address is required to disable account.")
        return JSONResponse(
            status_code=400,
            content={"error": "Email address is required to disable account."}
        )
    Logger.info(f"Disabling account for {email_address} in integration {intcid}")
    # Call the service function to disable the account

    result = await disable_user_account(
        intcid=intcid,
        email_address=email_address
    )
    
    return result

@router.post("/enable_user_account/{intcid}", response_model=dict)
async def enable_user_account_route(
    intcid: str,
    request: GWorkspaceRequest
):
    email_address = request.email_address
    if not email_address:
        Logger.error("Email address is required to enable account.")
        return JSONResponse(
            status_code=400,
            content={"error": "Email address is required to enable account."}
        )
    Logger.info(f"Enabling account for {email_address} in integration {intcid}")
    # Call the service function to enable the account

    result = await enable_user_account(
        intcid=intcid,
        email_address=email_address
    )
    
    return result

@router.post("/reset_user_password/{intcid}", response_model=dict)
async def reset_user_password_route(
    intcid: str,
    request: ResetPasswordRequest
):
    email_address = request.email_address
    new_password = request.new_password

    if not email_address:
        Logger.error("Email address is required to reset password.")
        return JSONResponse(
            status_code=400,
            content={"error": "Email address is required to reset password."}
        )

    Logger.info(f"Resetting password for {email_address} in integration {intcid}")

    result = await reset_user_password(
        intcid=intcid,
        email_address=email_address,
        new_password=new_password
    )
    
    return result


@router.post("/send_email/{intcid}", response_model=dict)
async def send_email_route(
    intcid: str,
    request: EmailRequest
):
    recipient_email = request.recipient_email
    subject = request.subject
    message_body = request.message_body

    if not recipient_email or not subject or not message_body:
        Logger.error("Recipient email, subject, and message body are required to send an email.")
        return JSONResponse(
            status_code=400,
            content={"error": "Recipient email, subject, and message body are required to send an email."}
        )

    Logger.info(f"Sending email to {recipient_email} in integration {intcid}")

    result = await send_email(
        intcid=intcid,
        recipient_email=recipient_email,
        subject=subject,
        message_body=message_body
    )
    
    return result