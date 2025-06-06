"""Sumologic Utils"""

from pltfrm import PropX, Logger2 as Logger, MongoDBManager, RedisManager



class SumoLogicUtils:
    """
    Utility class for SumoLogic operations.
    """
    def __init__(self, intcid: str):
        """Initializes the SumologicUtils class."""
        self.intcid = intcid
        self.main_db = PropX.get_property("module.integration.config.db")
        self.integration_db = PropX.get_property("module.integration.config.collection")
        self.toolsmetadata_db = PropX.get_property(
            "module.integration.metadata.collection"
        )
        self.templates_db = PropX.get_property("module.templates.collection")
        config = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration_db,
            {
                "intcid": self.intcid,
                "type": "siem",
                "vendor": "sumologic",
                "recordType": "investigation",
            },
        )
        self.access_id = config.get("access_id", None)
        self.access_key = config.get("access_key", None)
        self.api_endpoint = "https://api.sumologic.com/api/v1"
        self.partition_url = f"{self.api_endpoint}/partitions"
        
    def get_access_key(self) -> str:
        """
        Get the SumoLogic access key for the current integration.

        Returns:
            str: The access key.
        """
        if not self.access_key:
            Logger.error("Access key is not set for this integration.")
            raise ValueError("Access key is not set for this integration.")
        return self.access_key
    
    def get_access_id(self) -> str:
        """
        Get the SumoLogic access ID for the current integration.

        Returns:
            str: The access ID.
        """
        if not self.access_id:
            Logger.error("Access ID is not set for this integration.")
            raise ValueError("Access ID is not set for this integration.")
        return self.access_id
    
    