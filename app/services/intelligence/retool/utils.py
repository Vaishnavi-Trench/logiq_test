"""This module contains utility functions for VirusTotal intelligence agent."""

import re
import datetime

import requests

from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX
import pycurl
from io import BytesIO
import os
from urllib.parse import urlencode



def find_csrf_token(html_body):
    """Uses regex to find the CSRF token in the HTML."""
    # This regex looks for an input with "csrf" in its name and captures its value.
    match = re.search(r'name="[^"]*csrf[^"]*"\s+value="([^"]+)"', html_body, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def check_username_existence(email, domain, login_url):
    """Checks a username using pycurl and regex."""
    cookie_file = 'cookies.txt'
    curl = None
    try:
        # Buffer to store the response
        buffer = BytesIO()
        login_page_url = login_url

        # --- STEP 1: GET request to fetch the page and CSRF token ---
        curl = pycurl.Curl()
        curl.setopt(curl.URL, login_page_url)
        curl.setopt(curl.WRITEDATA, buffer)
        curl.setopt(curl.COOKIEJAR, cookie_file) # Store cookies from this request
        curl.setopt(curl.USERAGENT, "Mozilla/5.0")
        curl.perform()

        # Get the HTML and find the token
        html_body = buffer.getvalue().decode('utf-8', errors='ignore')
        csrf_token = find_csrf_token(html_body)

        if not csrf_token:
            Logger.info(f"Could not find CSRF token for '{email}'.")
            curl.close()
            response ={
                "status": False,
                "description": f"CSRF token not found for '{email}'."
            }
            return response

        # --- STEP 2: POST request to submit the form ---
        # Prepare the data to be submitted
        post_data = {'email_id': email, 'csrf_token': csrf_token}
        postfields = urlencode(post_data)

        buffer.seek(0) # Reset buffer for the next response
        buffer.truncate(0)

        curl.setopt(curl.URL, login_page_url)
        curl.setopt(curl.POSTFIELDS, postfields)
        curl.setopt(curl.WRITEDATA, buffer)
        curl.setopt(curl.COOKIEFILE, cookie_file)
        curl.setopt(curl.FOLLOWLOCATION, 1) 
        curl.perform()

        # Get the final URL after all redirects
        final_url = curl.getinfo(pycurl.EFFECTIVE_URL)

        if domain in final_url:
            Logger.info(f"'{email}' is a REGISTERED user.")
            response = {
                "status": True,
                "description": f"'{email}' is a registered user."
            }
        else:
            Logger.info(f"'{email}' is NOT a registered user.")
            response = {
                "status": False,
                "description": f"'{email}' is NOT a registered user."
            }

    except pycurl.error as e:
        Logger.error(f"A pycurl error occurred: {e}")
    finally:
        if curl:
            curl.close()
        if os.path.exists(cookie_file):
            os.remove(cookie_file)
    return response