import requests
import json
import traceback
from langchain_core.prompts import PromptTemplate
from typing import Optional  # Only import Optional, remove unused imports
import time
from datetime import datetime, timedelta
# Import platform components
from pltfrm import (
    Logger2 as Logger,
)

from app.services.siem.sumologic.utils import (
    SumoLogicUtils
)

async def get_available_indices(intcid: str, task:str) -> dict:
    """
    Get all available indices in SumoLogic using the Partitions API.
    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging

    Returns:
        List of index names
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info("Fetching available indices using the Partitions API")
    
    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    access_id = sumo_logic_utils.get_access_id()
    access_key = sumo_logic_utils.get_access_key()
    
    
    auth = (access_id, access_key)
    partition_url = sumo_logic_utils.partition_url
    
    try:
        response = requests.get(partition_url, auth=auth)
        response.raise_for_status()  # Raise an error for bad responses
        Logger.info(f"Response: {response}")
        partitions_data = response.json()
        indices = []
        for partition in partitions_data.get("data", []):
            name = partition.get("name")
            if name:
                indices.append(name)

        Logger.info(f"Found {len(indices)} indices")
        Logger.info(f"Available indices: {indices}")
        return {"indices": indices}
    except requests.exceptions.RequestException as e:
        Logger.error(f"Error fetching indices: {e}")
        Logger.error(traceback.format_exc())
        return {"error": "indices_fetch_error", "message": str(e)}
    
    
async def run_sumo_query(
    intcid: str,
    task: str,
    query: str,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    timezone: str = "UTC",
    wait_time: int = 5,
    max_wait_iterations: int = 60,
) -> Optional[dict]:
    """
    Run a query against the SumoLogic API and return the complete job status.

    Args:
        intcid (str): Integration ID
        query (str): The SumoLogic query to execute
        from_time (str, optional): Start time in ISO-8601 format (default: 24 hours ago)
        to_time (str, optional): End time in ISO-8601 format (default: now)
        timezone (str, optional): Timezone for the query (default: UTC)
        wait_time (int, optional): Seconds to wait between job status checks
        max_wait_iterations (int, optional): Maximum number of status checks before timing out

    Returns:
        dict: Complete job status object including fields and metadata or None if query failed
    """
    

    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Running query: {query}")
    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    access_id = sumo_logic_utils.get_access_id()
    access_key = sumo_logic_utils.get_access_key()
    api_endpoint = sumo_logic_utils.api_endpoint

    # Set default time range
    current_time = datetime.utcnow()
    if not from_time:
        from_time = (current_time - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not to_time:
        to_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    Logger.info(f"Query time range: {from_time} to {to_time}")
    auth = (access_id, access_key)
    Logger.info(f"API Endpoint: {api_endpoint}")

    try:
        session = requests.Session()
        session.auth = auth
        # 1. Create search job using the session
        search_job_url = f"{api_endpoint}/search/jobs"
        payload = {
            "query": query,
            "from": from_time,
            "to": to_time,
            "timeZone": timezone,
        }
        Logger.info(f"Submitting SumoLogic search job: {payload}")
        # Use session.post instead of requests.post
        response = session.post(search_job_url, json=payload)
        response.raise_for_status()
        job_id = response.json().get("id")

        if not job_id:
            Logger.error("Failed to get job ID from SumoLogic response")
            return None
        Logger.info(f"Search job created with ID: {job_id}")

        # 2. Poll for job completion using the same session
        status_url = f"{api_endpoint}/search/jobs/{job_id}"
        Logger.info(f"Polling job status at: {status_url}")
        iterations = 0
        while iterations < max_wait_iterations:
            # The small sleep is important to not hit rate limits and to be a good API citizen
            time.sleep(wait_time)
            iterations += 1
            try:
                # Use session.get instead of requests.get
                status_response = session.get(status_url)

                # With a session, a 404 is now less likely to be a transient issue and more likely
                # to be a real problem, but we'll still handle it gracefully.
                if status_response.status_code == 404:
                    Logger.warn(f"Job {job_id} not found (404). This might happen if the job was cancelled. Retrying...")
                    continue

                status_response.raise_for_status()
                job_status = status_response.json()
                state = job_status.get("state", "")
                Logger.info(f"Job status: {state} (check {iterations}/{max_wait_iterations})")

                if state == "DONE GATHERING RESULTS":
                    Logger.info("Job completed. Now fetching results...")
                    result_count = job_status.get("messageCount", 0)
                    if result_count == 0:
                        Logger.info("Query returned no results.")
                        return []

                    all_parsed_results = []
                    # Use a bigger limit to be more efficient. Max is 10000.
                    limit = 1000
                    results_url = f"{api_endpoint}/search/jobs/{job_id}/messages"

                    for offset in range(0, result_count, limit):
                        results_params = {"offset": offset, "limit": limit}
                        results_response = session.get(results_url, params=results_params)
                        results_response.raise_for_status()
                        results_data = results_response.json().get('messages', [])

                        # Process ONLY the messages received in THIS batch
                        for message in results_data:
                            raw_log_string = message.get('map', {}).get('_raw')
                            if raw_log_string:
                                try:
                                    parsed_log_data = json.loads(raw_log_string)
                                    all_parsed_results.append(parsed_log_data)
                                except json.JSONDecodeError:
                                    # Handle cases where _raw is not a valid JSON string
                                    all_parsed_results.append({"_raw": raw_log_string})

                    Logger.info(f"Successfully retrieved and parsed all {len(all_parsed_results)} results.")
                    # Return the list of parsed JSON objects
                    return {"query_results": all_parsed_results}

                elif state in ["CANCELLED", "FORCE CANCELLED", "FAILED"]:
                    messages = job_status.get("messages", [])
                    Logger.error(f"Job failed or was cancelled: {messages}")
                    # You might want to delete the job here if it exists
                    # session.delete(status_url)
                    return None

            except requests.exceptions.RequestException as e:
                Logger.error(f"Error during polling loop: {str(e)}")
                if iterations > 5: # Stop if we get repeated errors
                    return None

        Logger.error(f"Job timed out after {iterations} status checks")
        # Clean up the timed-out job on the server
        Logger.info(f"Cancelling job {job_id} due to timeout.")
        session.delete(status_url)
        return None

    except requests.exceptions.RequestException as e:
        Logger.error(f"Request failed: {str(e)}")
        if hasattr(e, "response") and e.response:
            Logger.error(f"Response status: {e.response.status_code}")
            Logger.error(f"Response body: {e.response.text}")
        return None
    except Exception as e:
        Logger.error(f"Unexpected error running query: {str(e)}")
        return None
    
    
async def get_system_alerts(
    intcid: str,
    task: str,
    start_time: str = None,
    end_time: str = None
) -> dict:
    """
    Fetch system alerts from SumoLogic using a specific query.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        start_time (str, optional): Start time in ISO-8601 format
        end_time (str, optional): End time in ISO-8601 format

    Returns:
        dict: {"alerts_created": [...]}
    """
    # Set default time range to 1 month if not provided
    now = datetime.utcnow()
    if not end_time:
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not start_time:
        start_time = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = '_index=sumologic_system_events AND _sourcename = "AlertSystemInfo"'
    results = await run_sumo_query(
        intcid=intcid,
        task=task,
        query=query,
        from_time=start_time,
        to_time=end_time
    )
    alerts = results.get("query_results", []) if results else []

    alerts_created = [a for a in alerts if a.get("details", {}).get("name") == "AlertCreated"]

    return {
        "alerts_created": alerts_created
    }
