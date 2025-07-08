from pltfrm import PropX, Logger2 as Logger, MongoDBManager, AIManager, ElasticsearchManager
from typing import List, Dict, Any
import json
import secrets
import string
import requests
import json

class SlackUtils:
    """Utility class for CrowdStrike operations."""

    def __init__(self, intcid: str):
        """Initializes the SumologicUtils class."""
        Logger.info(f"Initializing CrowdStrikeUtils for intcid {intcid}")
        self.intcid = intcid
        self.main_db = PropX.get_property("module.integration.config.db")
        self.integration = PropX.get_property("module.integration.config.collection")
        self.toolsmetadata = PropX.get_property("module.integration.metadata.collection")
        self.templates_db = PropX.get_property("module.templates.collection")
        self.trenchrecords_db = PropX.get_property("module.trenchrun.collection")
        config = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration,
            {
                "intcid": self.intcid,
                "type": "productivity",
                "vendor": "slack",
                "recordType": "investigation",
            },
        )
        self.webhook_url = config.get("webhook","")
        self.channel_name = config.get("channel_name", "")
        if not self.webhook_url:
            Logger.error("Slack webhook URL is not configured.")
            
    def send_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Sends a message to Slack using the configured webhook URL."""
        if not self.webhook_url:
            Logger.error("Slack webhook URL is not configured.")
            return {"status": False, "description": "Slack webhook URL is not configured."}
        
        try:
            Logger.info(f"Sending message to Slack: {json.dumps(payload)}")

            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10  # seconds
            )

            if response.status_code == 200:
                Logger.info("Message sent successfully to Slack.")
                return {"status": True, "description": f"Message sent successfully to the channel {self.channel_name}."}
            else:
                error_message = f"Error sending message: {response.status_code} {response.text}"
                Logger.error(error_message)
                return {"status": False, "description": error_message}

        except requests.exceptions.RequestException as e:
            Logger.error(f"Error sending message to Slack: {e}")
            return {"status": False, "description": f"An error occurred: {e}"}
        except Exception as e:
            Logger.error(f"An unexpected error occurred when sending message to Slack channel {self.channel_name}: {e}")
            return {"status": False, "description": f"An unexpected error occurred while sending message to Slack channel {self.channel_name}: {str(e)}"}