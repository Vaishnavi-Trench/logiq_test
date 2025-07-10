import datetime
from app.services.identity.retool.utils import check_username_existence, get_domain_url_from_mongo
from pltfrm import Logger2 as Logger


def check_user_existence(intcid: str, email: str) -> dict:
    """Verifies if a user account with a specific email exists for a given service.

    This tool attempts to determine if an email is registered with a service by 
    analyzing the response from its login page. It is useful for identifying 
    valid user accounts before attempting other actions.

    Args:
        email (str): The email address of the user to check for existence.
        domain (str): The domain of the target application.
        login_url (str): The full URL of the login page where the check will be performed.

    Returns:
        dict: A dictionary containing the status of the check and a descriptive message.
    """
    domain, login_url = get_domain_url_from_mongo(intcid)
    if not email:
        Logger.error("Email is required to check user existence.")
        return {
            "status": False,
            "description": "Email is required to check user existence."
        }
    if not domain or not login_url:
        Logger.error(f"Domain or login URL not found for intcid {intcid}.")
        return {
            "status": False,
            "description": "Domain or login URL not found. Please check the integration configuration."
        }
    
    Logger.info(f"Checking existence of user: {email}")
    response = check_username_existence(email, domain, login_url)
    
    if response["status"]:
        Logger.info(f"User '{email}' exists.")
    else:
        Logger.info(f"User '{email}' does not exist. Reason: {response['description']}")
    
    return response
