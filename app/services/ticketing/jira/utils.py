from pltfrm import PropX, Logger2 as Logger, MongoDBManager, AIManager, ElasticsearchManager
from typing import List, Dict, Any
import json
import secrets
import string
import requests
import json
from jira import JIRA

class JiraUtils:
    """Utility class for Jira operations."""

    def __init__(self, intcid: str):
        """Initializes the JiraUtils class."""
        Logger.info(f"Initializing JiraUtils for intcid {intcid}")
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
                "type": "ticketing",
                "vendor": "jira",
                "recordType": "investigation",
            },
        )
        self.api_token = config.get("api_token", "")
        self.email = config.get("email", "")
        self.jira_url = config.get("url", "")
        self.project_key = config.get("project_key", "")
        if not self.api_token or not self.email or not self.jira_url or not self.project_key:
            Logger.error("Jira API token, email, URL, or project key is not configured.")
            raise ValueError("Jira configuration is incomplete.")
        
        self.jira = None  # Initialize jira attribute

    def get_jira_client(self):
        try:
            self.jira = JIRA(server=self.jira_url, basic_auth=(self.email, self.api_token))
            Logger.info("Successfully connected to Jira.")
            return self.jira
        except Exception as e:
            Logger.error(f"Failed to connect to Jira: {e}")
            exit()

    def create_issue(self, issue_dict: Dict[str, Any]) -> None:
        try:
            jira = self.get_jira_client()
            if not jira:
                return {
                    "status": False,
                    "description": "Failed to connect to Jira. Check your configuration."
                }
           
            new_issue = jira.create_issue(fields=issue_dict)
            Logger.info(f"Successfully created issue {new_issue.key}")
            Logger.info(f"URL: {new_issue.permalink()}")
            
            description = f"Jira issue created successfully: {new_issue.key} - {new_issue.permalink()}"
            
            return {
                "status": True,
                "description": description,
            }
        except Exception as e:
            Logger.error(f"Failed to create issue: {e}")
            return {
                "status": False,
                "description": f"Failed to create issue: {str(e)}"
            }