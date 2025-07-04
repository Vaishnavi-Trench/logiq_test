"""This module contains utility functions for Spycloud agent."""

import re
import json
import traceback

import requests

from pltfrm import Logger2 as Logger
from pltfrm import PropX, AIManager
from app.services.intelligence.spycloud import models as spycloud_models


def transform_alert_context(input_data: dict) -> dict:
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
                "[sumologic] transform_alert_context: 'extracted_fields' is not a list or not found."
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
                        f"[sumologic] transform_alert_context: Found field with missing/empty id: {field}"
                    )
            else:
                Logger.warn(
                    f"[sumologic] transform_alert_context: Skipping invalid field format: {field}"
                )

        # Replace the list with the new dictionary structure within the nested alert_context
        alert_context_data["extracted_fields"] = transformed_fields

        # Return the modified top-level structure
        return input_data["alert_context"]
    


def extract_alert_context(intcid:str, task: str, alert: dict, aid: str) -> dict:
    try:
        env = "unknown"
        alert_context = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="SPYCLOUD_ALERT_CONTEXT_EXTRACTION_PROMPT",
            prompt_params={
                "alert": json.dumps(
                    alert
                ),  # This now contains either the original alert/incident or the list of fetched alerts
                "env": env,
                "requirement": task,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=spycloud_models.AlertContextResponse,
            history_params={
                "aid": aid,
                "subtype": "alert_context",
            },
            type="triage",
            system_prompt="You are an expert in understanding Sumologic Alerts. Your task is to extract context parameters from given input which included received alert.",
        )

        
        Logger.info(f"AI response for context extraction: {alert_context}")
        alert_context = transform_alert_context(
            input_data=alert_context
        )
        alert_context["env"] = env  # Ensure env is included
        return alert_context

    except Exception as e:
        Logger.error(f"Error fetching alert context: {str(e)}")
        Logger.error(traceback.format_exc())
        return {"error": "alert_context_fetch_error", "message": str(e)}


