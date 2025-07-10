from app.services.productivity.gworkspace.utils import GworkspaceUtils
from typing import Any, Optional
from pltfrm import Logger2 as Logger
from googleapiclient.discovery import build


async def disable_user_account(intcid: str, email_address: str) -> dict:
    """Disable/suspend a Google Workspace user account."""

    try:
        # Hardcoded email for testing
        email_address = "amandal@ocrolus.com"
        
        
        gworkspace_utils = GworkspaceUtils(intcid=intcid)
        delegated_creds = gworkspace_utils.delegated_auth()

        if not delegated_creds:
            Logger.error(f"Could not get delegated credentials for intcid {intcid}")
            return {
                "status": False,
                "description": f"Authentication failed for {email_address}. Check integration configuration.",
            }

        # First, check if user exists
        
        Logger.info(f"Checking if user exists: {email_address}")
        user_info = gworkspace_utils.get_user_info(email_address)
        if user_info is None:
            return {
                "status": False,
                "description": f"User with email {email_address} not found",
            }

        # Check if user is already suspended
        if user_info.get("suspended", False):
            description = f"User {email_address} is already suspended. No action taken."
            Logger.info(description)
            return {
                "status": True,
                "description": description,
            }

        # Build the Admin SDK service using delegated credentials
        admin_service = build("admin", "directory_v1", credentials=delegated_creds)

        # Update user to suspend/disable the account
        user_body = {
            "suspended": True,  # Disable/suspend the account
        }

        Logger.info(f"🔒 Suspending account for: {email_address}")
        result = (
            admin_service.users()
            .update(userKey=email_address, body=user_body)
            .execute()
        )
        if not result:
            return {
                "status": False,
                "description": f"Failed to disable account for {email_address}. No response from API.",
            }

        description = f"Account successfully disabled for user: {email_address}."
        Logger.info(description)
        Logger.info("User will no longer be able to access Google Workspace services.")

        return {
            "status": True,
            "description": description,
        }

    except Exception as e:
        Logger.error(f"Error disabling account for {email_address}: {e}")
        return {
            "status": False,
            "description": f"Error disabling account for {email_address}: {e}",
        }


async def enable_user_account(intcid: str, email_address: str) -> dict:
    """Enable/unsuspend a Google Workspace user account."""

    try:
        
        # Hardcoded email for testing
        email_address = "amandal@ocrolus.com"
        
        gworkspace_utils = GworkspaceUtils(intcid=intcid)
        delegated_creds = gworkspace_utils.delegated_auth()

        if not delegated_creds:
            Logger.error(f"Could not get delegated credentials for intcid {intcid}")
            return {
                "status": False,
                "description": f"Authentication failed for {email_address}. Check integration configuration.",
            }
        
        # First, check if user exists
        Logger.info(f"Checking if user exists: {email_address}")
        user_info = gworkspace_utils.get_user_info(email_address)
        if user_info is None:
            return {
                "status": False,
                "description": f"User with email {email_address} not found",
            }

        # Check if user is already active
        if not user_info.get("suspended", False):
            description = f"User {email_address} is already active. No action taken."
            Logger.info(description)
            return {
                "status": True,
                "description": description,
            }

        # Build the Admin SDK service using delegated credentials
        admin_service = build("admin", "directory_v1", credentials=delegated_creds)

        # Update user to unsuspend/enable the account
        user_body = {
            "suspended": False,  # Enable/unsuspend the account
        }

        Logger.info(f"🔓 Enabling account for: {email_address}")
        result = (
            admin_service.users()
            .update(userKey=email_address, body=user_body)
            .execute()
        )
        
        if not result:
            return {
                "status": False,
                "description": f"Failed to enable account for {email_address}. No response from API.",
            }

        description = f"Account successfully enabled for user: {email_address}."
        Logger.info(description)
        Logger.info("User can now access Google Workspace services again.")

        return {
            "status": True,
            "description": description,
        }

    except Exception as e:
        Logger.error(f"Error enabling account for {email_address}: {e}")
        return {
            "status": False,
            "description": f"Error enabling account for {email_address}: {e}",
        }


async def reset_user_password(
    intcid: str, email_address: str, new_password: Optional[str] = None
) -> dict:
    """Reset password for a Google Workspace user."""
    try:
        
        # Hardcoded email for testing
        email_address = "soc_automation@ocrolus.com"
        
        
        gworkspace_utils = GworkspaceUtils(intcid=intcid)
        delegated_creds = gworkspace_utils.delegated_auth()

        if not delegated_creds:
            Logger.error(f"Could not get delegated credentials for intcid {intcid}")
            return {
                "status": False,
                "description": f"Authentication failed for {email_address}. Check integration configuration.",
            }

        # First, check if user exists
        Logger.info(f"Checking if user exists: {email_address}")
        user_info = gworkspace_utils.get_user_info(email_address)
        if user_info is None:
            return {
                "status": False,
                "description": f"User with email {email_address} not found",
            }

        # Generate a random password if not provided
        if new_password is None:
            new_password = gworkspace_utils.generate_random_password()

        # Build the Admin SDK service using delegated credentials
        admin_service = build("admin", "directory_v1", credentials=delegated_creds)

        # Update user password
        user_body = {
            "password": new_password,
            "changePasswordAtNextLogin": True,  # Force user to change password on next login
        }

        Logger.info(f"Resetting password for: {email_address}")
        result = (
            admin_service.users().update(userKey=email_address, body=user_body).execute()
        )

        if not result:
            return {
                "status": False,
                "description": f"Failed to reset password for {email_address}. No response from API.",
            }

        description = f"Password reset successful for user: {email_address}. New temporary password: {new_password}"
        Logger.info(description)
        Logger.info("User will be required to change password at next login.")

        return {
            "status": True,
            "description": description
        }

    except Exception as e:
        Logger.error(f"Error resetting password for {email_address}: {e}")
        return {
            "status": False,
            "description": f"Error resetting password for {email_address}: {e}",
        }


async def send_email(
    intcid: str, to: str, subject: str, body: str
) -> dict:
    """Send an email using the delegated admin's Gmail account."""
    try:
        gworkspace_utils = GworkspaceUtils(intcid=intcid)
        delegated_creds = gworkspace_utils.delegated_auth()

        if not delegated_creds:
            Logger.error(f"Could not get delegated credentials for intcid {intcid}")
            return {
                "status": False,
                "description": "Authentication failed. Check integration configuration.",
            }

        # The sender is the delegated admin email
        sender_email = gworkspace_utils.admin_email

        # Create email message using the utility function
        email_content = gworkspace_utils.create_email_message(
            sender=sender_email,
            to=to,
            subject=subject,
            message_text=body,
        )

        if not email_content:
            return {
                "status": False,
                "description": "Failed to create email message.",
            }

        # Build the Gmail API service
        gmail_service = build("gmail", "v1", credentials=delegated_creds)

        # Send the email
        result = (
            gmail_service.users()  # pylint: disable=no-member
            .messages()  # pylint: disable=no-member
            .send(userId="me", body=email_content)
            .execute()
        )
        if not result:
            return {
                "status": False,
                "description": "Failed to send email. No response from Gmail API.",
            }
        description = f"Email sent successfully to {to} from {sender_email}."
        Logger.info(description)
        return {"status": True, "description": description}

    except Exception as e:
        Logger.error(f"Failed to send email: {e}")
        return {"status": False, "description": str(e)}

