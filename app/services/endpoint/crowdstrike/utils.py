

from pltfrm import PropX, Logger2 as Logger, MongoDBManager, AIManager, ElasticsearchManager
from typing import List, Dict, Any

from falconpy import Hosts
class CrowdStrikeUtils:
    """Utility class for CrowdStrike operations."""

    def __init__(self, intcid: str):
        """Initializes the SumologicUtils class."""
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
                "type": "endpoint",
                "vendor": "crowdstrike",
                "recordType": "investigation",
            },
        )
        self.client_id = config.get("client_id", None)
        self.secret_key = config.get("secret_key", None)
    
    def authenticate(self):
        """Authenticate with CrowdStrike API."""
        if not self.client_id or not self.secret_key:
            Logger.error("CrowdStrike client_id or secret_key is not set.")
            return None
        
        falcon = Hosts(client_id=self.client_id, client_secret=self.secret_key)
        return falcon