import requests
import json
import traceback
from langchain_core.prompts import PromptTemplate
from typing import Optional  # Only import Optional, remove unused imports
import time
from datetime import datetime, timedelta
import fnmatch
import re
# Import platform components
from pltfrm import (
    PropX,
    AIManager,
    Logger2 as Logger,
    MongoDBManager
)

from app.services.siem.sumologic.utils import (
    SumoLogicUtils
)

from app.services.siem.sumologic import models as sumologic_models




def is_ignored_index(intcid: str, index_name: str) -> bool:
    """
    Check if an index should be ignored based on the ignorance list (regex patterns) from MongoDB.
    """
    ignorance_list_doc = MongoDBManager.get_record_by_multiple_fields(
        PropX.get_property("module.integration.config.db"),
        PropX.get_property("module.integration.config.collection"),
        {
            "intcid": intcid,
            "type": "integration",
            "subtype": "indices_list",
        }
    )
    ignorance_list = ignorance_list_doc.get("ignorance_list", [])
    return any(re.match(pattern, index_name) for pattern in ignorance_list)

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
    collectors_url = sumo_logic_utils.collectors_url
    
    try:
        # response = requests.get(partition_url, auth=auth)
        response = requests.get(collectors_url, auth=auth)
        response.raise_for_status()  # Raise an error for bad responses
        Logger.info(f"Response: {response}")
        # partitions_data = response.json()
        collectors_data = response.json()
        indices = []
        # for partition in partitions_data.get("data", []):
        #     name = partition.get("name")
        for collector in collectors_data.get("collectors", []):
            name = collector.get("name")
            isAlive = collector.get("alive", False)
            if name and isAlive:
                indices.append(name)  # Collect only the collector names

        # Filter indices using the ignorance list
        filtered_indices = [i for i in indices if not is_ignored_index(intcid, i)]

        Logger.info(f"Found {len(filtered_indices)} indices")
        Logger.info(f"Available indices: {filtered_indices}")
        
        
        
        return {"indices": filtered_indices}
    except requests.exceptions.RequestException as e:
        Logger.error(f"Error fetching indices: {e}")
        Logger.error(traceback.format_exc())
        return {"error": "indices_fetch_error", "message": str(e)}
    
async def get_available_fields(intcid: str, task: str, index_name: str) -> dict:
    """
    Get all available fields in SumoLogic using the Fields API.
    
    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging

    Returns:
        dict: List of field names and a sample record
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info("Fetching available fields using the Fields API")
    
    # query = f"_index={index_name} | limit 1"
    query = f"_collector=\"{index_name}\" | limit 1"  # Use collector name for query
    sumo_logic_utils = SumoLogicUtils(intcid=intcid)
    try:
        response = await sumologic_run_sql_query(
            intcid=intcid,
            task=task,
            query=query,
            from_time=None,  # Use default time range
            to_time=None,    # Use default time range
            timezone="UTC",
            wait_time=5,
            max_wait_iterations=60
        )
        
        if not response or "query_results" not in response:
            Logger.error("No results returned from SumoLogic query")
            return {"error": "no_results", "message": "No fields found"}

        results = response.get("query_results", [])
        if not results:
            Logger.error("Query results are empty")
            return {"error": "no_results", "message": "No fields found"}

        sample_record = results[0]
        fields = sumo_logic_utils.extract_field_names(sample_record)

        Logger.info(f"Found {len(fields)} fields in index {index_name}")
        return {
            "fields": list(fields),
            "sample_record": sample_record
        }
    except Exception as e:
        Logger.error(f"Error fetching fields: {str(e)}")
        Logger.error(traceback.format_exc())
        return {"error": "fields_fetch_error", "message": str(e)}

async def sumologic_run_sql_query(
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
        from_time = (current_time - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
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

                # Log the raw response at every state
                Logger.info(f"Raw job status response: {status_response.text}")

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
                        return {"query_results": []}

                    all_parsed_results = []
                    # Use a bigger limit to be more efficient. Max is 10000.
                    limit = 1000
                    results_url = f"{api_endpoint}/search/jobs/{job_id}/messages"

                    for offset in range(0, result_count, limit):
                        results_params = {"offset": offset, "limit": limit}
                        results_response = session.get(results_url, params=results_params)
                        # Log the raw response for results as well
                        Logger.info(f"Raw results response (offset {offset}): {results_response.text}")
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
                    return {"error": str(e)}

        Logger.error(f"Job timed out after {iterations} status checks")
        # Clean up the timed-out job on the server
        Logger.info(f"Cancelling job {job_id} due to timeout.")
        session.delete(status_url)
        return {"error": "job_timed_out"}

    except requests.exceptions.RequestException as e:
        Logger.error(f"Request failed: {str(e)}")
        if hasattr(e, "response") and e.response:
            Logger.error(f"Response status: {e.response.status_code}")
            Logger.error(f"Response body: {e.response.text}")
        return None
    except Exception as e:
        Logger.error(f"Unexpected error running query: {str(e)}")
        return None
    
async def fetch_security_alerts(
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
    results = await sumologic_run_sql_query(
        intcid=intcid,
        task=task,
        query=query,
        from_time=start_time,
        to_time=end_time
    )
    alerts = results.get("query_results", []) if results else []

    alerts_created = [a for a in alerts if a.get("details", {}).get("name") == "AlertCreated"]

    return {
        "security_alerts_data": alerts_created
    }

async def sumologic_get_alert_context(
    intcid: str,
    task: str,
    aid: str,
    alert: dict
):
    """
    Get context for a specific alert by its ID.

    Args:
        intcid (str): Integration ID
        task (str): Task identifier for logging
        aid (str): Alert ID
        alert (dict): Alert data

    Returns:
        dict: Context information for the alert
    """
    Logger.info(f"Task: {task} - Integration ID: {intcid}")
    Logger.info(f"Fetching context for alert ID: {aid}")

    try:
        env = "unknown"
        alert_context = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="SUMOLOGIC_ALERT_CONTEXT_EXTRACTION_PROMPT",
            prompt_params={
                "alert": json.dumps(alert),  # This now contains either the original alert/incident or the list of fetched alerts
                "env": env,
                "requirement": task,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sumologic_models.AlertContextResponse,
            history_params={
                "aid": aid,
                "subtype": "alert_context",
            },
            type="triage",
            system_prompt="You are an expert in understanding Sumologic Alerts. Your task is to extract context parameters from given input which included received alert.",
        )

        Logger.info(f"AI response for context extraction: {alert_context}")
        sumo_logic_utils = SumoLogicUtils(intcid=intcid)
        alert_context = sumo_logic_utils.transform_alert_context(input_data=alert_context)
        alert_context["env"] = env  # Ensure env is included
        return alert_context
        
    except Exception as e:
        Logger.error(f"Error fetching alert context: {str(e)}")
        Logger.error(traceback.format_exc())
        return {"error": "alert_context_fetch_error", "message": str(e)}