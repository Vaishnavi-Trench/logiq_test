from app.services.productivity.slack.utils import SlackUtils
from typing import Any, Optional
from pltfrm import Logger2 as Logger




async def send_notification(intcid: str, subject: str, body: str, to: Optional[str]) -> dict:
    """Send a message to a Slack channel using the configured webhook URL."""
    try:
        slack_utils = SlackUtils(intcid=intcid)
        
        if not slack_utils.webhook_url:
            Logger.error(f"Slack webhook URL is not configured for intcid {intcid}")
            return {
                "status": False,
                "description": "Slack webhook URL is not configured."
            }
        
        payload = {
            "text": f"*{subject}*\n{body}"
        }
        response = slack_utils.send_message(payload)
        
        return response
    except Exception as e:
        Logger.error(f"Error sending Slack message: {e}")
        return {
            "status": False,
            "description": f"Error sending message: {str(e)}"
        }