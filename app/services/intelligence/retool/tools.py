import datetime
from app.services.intelligence.retool.utils import check_username_existence
from pltfrm import Logger2 as Logger


def check_user_existence(email: str) -> dict:
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
    #Hardcoded values for testing
    domain = "login.ocrolus.com"
    login_url = "https://app.ocrolus.com/login"
    
    Logger.info(f"Checking existence of user: {email}")
    response = check_username_existence(email, domain, login_url)
    
    if response["status"]:
        Logger.info(f"User '{email}' exists.")
    else:
        Logger.info(f"User '{email}' does not exist. Reason: {response['description']}")
    
    return response
