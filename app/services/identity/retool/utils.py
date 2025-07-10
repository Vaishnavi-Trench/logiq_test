"""This module contains utility functions for Retool identity service."""

import requests
from bs4 import BeautifulSoup
from pltfrm import Logger2 as Logger


def check_username_existence(email, domain, login_url):
    """
    Checks a single username by first getting a CSRF token and then submitting the form.
    
    Args:
        email (str): The email address to check
        domain (str): The domain to check for in the final URL
        login_url (str): The login URL to use for the check
        
    Returns:
        dict: A dictionary containing the status and description of the check
    """
    try:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # STEP 1: Get the login page to establish a session and find the CSRF token.
        response_get = session.get(login_url)
        response_get.raise_for_status()  # Ensure the request was successful
        
        # Use BeautifulSoup to parse the HTML and find the token
        soup = BeautifulSoup(response_get.text, 'html.parser')
        csrf_token_element = soup.find('input', {'name': 'csrf_token'})
        
        if not csrf_token_element:
            Logger.error("Could not find the CSRF token on the page. The website might have changed.")
            return {
                "status": False,
                "description": "Could not find the CSRF token on the page. The website might have changed."
            }
        
        csrf_token = csrf_token_element['value']
        
        # STEP 2: Submit the form with the email AND the CSRF token.
        payload = {
            'email_id': email,
            'csrf_token': csrf_token
        }
        
        # The session automatically handles cookies from the GET request.
        response_post = session.post(login_url, data=payload)
        response_post.raise_for_status()
        
        # FINAL CHECK: See if the final URL is the correct login domain.
        if domain in response_post.url:
            Logger.info(f"'{email}' is a REGISTERED user.")
            return {
                "status": True,
                "description": f"'{email}' is a registered user."
            }
        else:
            Logger.info(f"'{email}' is NOT a registered user.")
            return {
                "status": False,
                "description": f"'{email}' is NOT a registered user."
            }
            
    except requests.exceptions.RequestException as e:
        Logger.error(f"An error occurred while checking '{email}': {e}")
        return {
            "status": False,
            "description": f"An error occurred while checking '{email}': {e}"
        }
    finally:
        # Close the session to clean up resources
        if 'session' in locals():
            session.close()