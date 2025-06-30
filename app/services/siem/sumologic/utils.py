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
        self.collectors_url = f"{self.api_endpoint}/collectors"

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
    
    def extract_field_names(self, record, prefix=""):
        """
        Recursively extract all unique field names from a dict (including nested).
        """
        fields = set()
        if isinstance(record, dict):
            for k, v in record.items():
                full_key = f"{prefix}.{k}" if prefix else k
                fields.add(full_key)
                if isinstance(v, dict):
                    fields.update(self.extract_field_names(v, full_key))
                elif isinstance(v, list):
                    for item in v:
                        fields.update(self.extract_field_names(item, full_key))
        return fields
    
    def transform_alert_context(self, input_data: dict) -> dict:
        """Transforms the alert context structure.

        Converts the 'extracted_fields' list into a dictionary keyed by the 'id'
        of each field, removing the 'id' key from the nested dictionaries.

        Args:
            input_data: The dictionary containing the alert context, potentially
                        nested under the 'alert_context' key.

        Returns:
            The transformed dictionary.
        """
        if "alert_context" not in input_data:
            Logger.warn("transform_alert_context: 'alert_context' key not found in input.")
            return input_data  # Return original if structure is unexpected

        alert_context_data = input_data["alert_context"]

        if "extracted_fields" not in alert_context_data or not isinstance(
            alert_context_data["extracted_fields"], list
        ):
            Logger.warn(
                "transform_alert_context: 'extracted_fields' is not a list or not found."
            )
            # Return the structure as is if extracted_fields is missing or not a list
            return input_data

        original_fields = alert_context_data.get("extracted_fields", [])
        transformed_fields = {}

        for field in original_fields:
            if isinstance(field, dict) and "id" in field:
                field_id = field.get("id")
                if field_id:  # Ensure id is not empty or None
                    field_copy = field.copy()
                    del field_copy["id"]  # Remove the id key
                    transformed_fields[field_id] = field_copy
                else:
                    Logger.warn(
                        f"transform_alert_context: Found field with missing/empty id: {field}"
                    )
            else:
                Logger.warn(
                    f"transform_alert_context: Skipping invalid field format: {field}"
                )

        # Replace the list with the new dictionary structure within the nested alert_context
        alert_context_data["extracted_fields"] = transformed_fields

        # Return the modified top-level structure
        return input_data["alert_context"]