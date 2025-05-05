"""GCP Tools Module"""

import json
from datetime import datetime, timedelta

from google.cloud import logging_v2

from pltfrm import Logger2 as Logger


def generate_gcp_logging_query(intcid: str, project_id: str, query: str) -> dict:
    """
    Fetches logs from GCP Audit Logs using the generated query for a given project ID.
    """
    Logger.debug(f"tool:generate_gcp_logging_query: intcid: {intcid}, query: {query}, project_id: {project_id}")
    if not query or not project_id:
        return json.dumps({"error": "Query or project_id is missing"})

    client = logging_v2.Client()

    # Define the last 30 days as the time range
    start_time = (datetime.utcnow() - timedelta(days=100)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    Logger.debug(start_time)
    # Construct the query with timestamp filtering
    full_query = f'{query} AND timestamp >= "{start_time}"'

    # Specify project scope correctly
    parent = f"projects/{project_id}"

    log_events = []
    entries = client.list_entries(filter_=full_query, resource_names=[parent])

    for entry in entries:
        log_events.append(
            {
                "timestamp": entry.timestamp.isoformat(),
                "log_name": entry.log_name,
                "method_name": (
                    entry.payload.get("methodName", "Unknown")
                    if hasattr(entry, "payload")
                    else "Unknown"
                ),
            }
        )

    return {"events": json.dumps(log_events, indent=2)}
