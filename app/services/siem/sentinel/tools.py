import json
import traceback
import requests
import datetime
from datetime import timezone
from langchain_core.prompts import PromptTemplate
from typing import Optional
from typing import Dict, Any, List
# Import platform components
from pltfrm import (
    Logger2 as Logger,
    PromptManager,
    AIManager,
    PropX,
    MongoDBManager,
)

from app.services.siem.sentinel import models as sentinel_models

# Import Sentinel specific utils and functions
from app.services.siem.sentinel.utils.utils import (
    SentinelUtils,
    DEFAULT_QUERY_TIME_RANGE,
)

from app.services.siem.sentinel.utils.alert_context_enrichment_util import run_kql_and_collect, get_matching_tables_for_username, get_matching_tables_for_ip, build_final_ans_dict, group_tables   

async def sentinel_choose_table(
    intcid: str,
    task: str,
    aid: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: any
) -> dict:
    """Selects the appropriate Sentinel table using AI based on triage context and alert.

    Fetches available tables with schemas, checks cache, uses AI for selection
    if needed, caches the result, and stores it in MongoDB.

    Args:
        intcid: The customer integration ID.
        tid: The triage ID.
        question_id: The specific question ID within the triage process.
        triage_question: The text of the triage question being addressed.
        alert: The relevant alert/event content (dict or JSON string).

    Returns:
        A dictionary containing the chosen 'table_name' and 'env'.
        Returns an error dictionary if table fetching or selection fails.
        Example success: {'table_name': 'SecurityEvent', 'env': 'Production'}
        Example error: {'error': 'No suitable Sentinel tables found.'}
    """
    Logger.info(
        f"tool:sentinel_choose_table: Starting for {intcid}, AID: {aid}, TID: {tid}, QID: {question_id}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)
    model_name = PropX.get_property("module.llm.model")

    if not model_name:
        Logger.error("Model name not found in configuration.")
        return {"error": "Model name not found in configuration."}

    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    alert_str = (
        json.dumps(alert_context)
        if isinstance(alert_context, dict)
        else str(alert_context)
    )

    # --- Determine Environment ---
    env = alert_context.get("env", "unknown").lower()
    
    # --- Get Available Tables ---

    query = {"intcid": intcid, "vendor": "sentinel", "subtype": "index_list"}

    table_metadata = MongoDBManager.get_record_by_multiple_fields(
        sentinel_utils.main_db, sentinel_utils.toolsmetadata_db, query
    )
    if table_metadata is not None:
        customer_tables_with_schema = table_metadata.get("indices")

    else:
        return {"error": "Failed to retrieve Sentinel tables. No metadata found."}

    try:
        table_name = sentinel_utils.get_table_name_from_mongo(
            intcid, "sentinel", env, tid, question_id, step_id
        )
        reason = "Table name found in MongoDB template."
    except Exception as mongo_e:
        Logger.warn(f"Failed to push AI-selected table name to MongoDB: {mongo_e}")

    if not table_name:
        try:
            tables_list = sentinel_utils.get_top_matching_tables(intcid, tid)
            Logger.info(
                f"Top matching tables for {intcid} and TID {tid}: {tables_list}"
            )
            table_name_to_desc = {
                entry["index"]: entry["desc"] for entry in customer_tables_with_schema
            }
            tables_name_and_description_list = [
                {"index": table, "desc": table_name_to_desc.get(table, "")}
                for table in tables_list
            ]
            tables_name_and_description = sentinel_utils.parse_indices(
                tables_name_and_description_list
            )

            response_data = AIManager.run_prompt_with_structured_output(
                intcid=intcid,
                prompt_template_name="KQL_QUERY_TABLE_SELECTION_PROMPT",
                prompt_params={
                    "alert": alert_str,
                    "requirement": task,
                    "triage_question": triage_question,
                    "alert_context": alert_str,
                    "tables_list": tables_name_and_description,
                },
                model_name=model_name,
                model_class=sentinel_models.TableName,
                history_params={
                    "aid": aid,
                    "tid": tid,
                    "qid": question_id,
                    "step_id": step_id,
                    "subtype": "table_selection",
                },
                type="triage",
                system_prompt="You are an expert in Microsoft Sentinel and KQL. Your task is to select the most appropriate table for the given requirement based on the available tables and their schemas. Provide only the table name in your response.",
            )

            Logger.debug(f"AI response for table selection: {response_data}")
            if response_data is None:
                Logger.error("Failed to parse AI response during table selection.")
                return {"error": "Failed to parse AI response during table selection."}

            table_name = response_data.get("table_name")
            Logger.debug(
                f"AI selected table name: {table_name}, available tables: {customer_tables_with_schema}"
            )
            if not table_name:
                Logger.error(
                    f"AI selected an invalid or unavailable table: '{table_name}'. Response: {response_data}"
                )
                return {
                    "error": f"AI failed to select a valid table. Selection: '{table_name}'"
                }

            try:
                sentinel_utils.push_table_name_to_mongo(
                    intcid,
                    "sentinel",
                    env,
                    tid,
                    question_id,
                    step_id,
                    triage_question,
                    table_name,
                )
            except Exception as mongo_e:
                Logger.warn(
                    f"Failed to push AI-selected table name to MongoDB: {mongo_e}"
                )

            Logger.info(f"Sentinel table chosen by AI: {table_name}")
            reason = "Table name selected by AI based on context and available tables."
        except Exception as e:
            Logger.error(
                f"Error during Sentinel table selection: {e}\n{traceback.format_exc()}"
            )
            return {
                "error": f"An unexpected error occurred during table name selection: {e}"
            }
        
    table_status = sentinel_utils.check_table(intcid, table_name)
    if table_status:
        Logger.info(f"Table {table_name} is available in Sentinel.")
        return {"table_name": table_name, "env": env}
    else:
        Logger.error(
            f"Table {table_name} is not available in Sentinel. Please check the table name."
        )
        return {
            "error": f"{reason} failed"
        }


async def get_detection_rules(intcid: str, task: str) -> dict:
    """Fetches detection rules from Sentinel."""
    Logger.info(f"tool:get_detection_rules: Starting for {intcid} {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    status, response = sentinel_utils.list_all_rules()
    if not status:
        Logger.error("Failed to list rules from Azure Management API.")
        return {
            "status": False,
            "rules": [],
            "error": response,
        }

    return {"status": True, "rules": response}


async def get_sentinel_tables_with_schema(intcid: str, task: str) -> dict:
    """Fetches Sentinel Log Management tables that contain data, along with their schemas.

    Authenticates using SentinelUtils, retrieves the workspace ID, and lists all
    tables via the Azure Management API. It checks if tables contain *any* data
    by querying its count. If a table has data (count > 0), its schema
    (column names) is fetched and added to the result.

    Args:
        intcid: Integration/Customer ID (used for configuration and logging).
        task: Description of the task requesting the tables (used for logging).

    Returns:
        A dictionary with table names containing data as keys and lists of their
        column names (schema) as values, under the key 'tables_with_schema'.
        Example: {'tables_with_schema': {'Syslog': ['TimeGenerated', ...], ...}}
        Returns an error dictionary on failure.
        Example: {'error': 'Authentication failed.'}
    """
    Logger.info(f"tool:get_sentinel_tables_with_schema: Starting for {intcid} {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    all_tables_with_schema = sentinel_utils.list_all_tables_with_columns()
    if not all_tables_with_schema:
        Logger.error("Failed to list tables from Azure Management API.")
        return {
            "status": False,
            "all_tables": all_tables_with_schema,
            "error": "Failed to list tables.",
        }

    return {"status": True, "tables_with_schema": all_tables_with_schema}


async def get_sentinel_table_row_count(intcid: str, task: str, table_name: str) -> dict:
    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    status, count, error = sentinel_utils.get_table_row_count(table_name)
    return {"status": status, "count": count, "error": str(error)}


async def get_sentinel_table_schema(intcid: str, task: str, table_name: str) -> dict:
    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    success, response = sentinel_utils.get_table_schema(table_name)
    if success:
        return {"status": success, "columns": response}
    else:
        return {
            "status": success,
            "error": response,
        }


async def fetch_security_alerts_with_query(
    intcid: str,
    task: str,
    query: str,
    time_field: str,
    start_time: str = None,
    end_time: str = None,
) -> dict:
    """Fetches recent security alerts from the Sentinel SecurityAlert table.

    Authenticates, retrieves workspace ID, and queries the SecurityAlert table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security alert records under the key
        'security_alerts_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_alerts_data': [{'tableName': 'SecurityAlert', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_alerts_with_query: Starting for {intcid} {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        time_filter = f"| where {time_field} between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where {time_field} > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    kql_query = f"{query} {time_filter}"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found for query '{kql_query}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for query:'{kql_query}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for query: '{kql_query}'.")
        return {"security_alerts_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Error querying data for query '{kql_query}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_alerts_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for query '{kql_query}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {kql_query}."}

    Logger.info(
        f"Finished querying:{kql_query} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"alert_query_results": all_records}


async def fetch_security_alerts(
    intcid: str, task: str, start_time: str = None, end_time: str = None
) -> dict:
    """Fetches recent security alerts from the Sentinel SecurityAlert table.

    Authenticates, retrieves workspace ID, and queries the SecurityAlert table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security alert records under the key
        'security_alerts_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_alerts_data': [{'tableName': 'SecurityAlert', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_alerts: Starting for {intcid} {task}")
    table_name = "SecurityAlert"

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        time_filter = f"| where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where TimeGenerated > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    Logger.info(f"Querying {table_name}. {time_filter_log_message}")

    kql_query = f"{table_name} {time_filter}"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records in '{table_name}'.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    record_dict["tableName"] = table_name
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found in '{table_name}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for '{table_name}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for table '{table_name}'.")
        return {"security_alerts_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Could not query data for table '{table_name}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_alerts_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for table '{table_name}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {table_name}."}

    Logger.info(
        f"Finished querying {table_name} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"security_alerts_data": all_records}


async def fetch_security_incidents(
    intcid: str, task: str, start_time: str = None, end_time: str = None
) -> dict:
    """Fetches recent security incidents from the Sentinel SecurityIncident table.

    Authenticates, retrieves workspace ID, and queries the SecurityIncident table
    using the Log Analytics API for records within a specified time range.

    Args:
        intcid: Integration/Customer ID.
        task: Specific task description (for logging).
        start_time: Optional start time string (ISO 8601 format).
        end_time: Optional end time string (ISO 8601 format). If None, uses
                  `DEFAULT_QUERY_TIME_RANGE`.

    Returns:
        A dictionary containing a list of security incident records under the key
        'security_incidents_data'. Each record includes a 'tableName' key.
        Returns an empty list if no data is found. Returns an error dictionary
        on failure.
        Example success: {'security_incidents_data': [{'tableName': 'SecurityIncident', ...}]}
        Example error: {'error': 'Failed to retrieve Workspace ID.'}
    """
    Logger.info(f"tool:fetch_security_incidents: Starting for {intcid} {task}")
    table_name = "SecurityIncident"

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }

    time_filter_log_message = ""
    if start_time and end_time:
        # Assuming TimeGenerated exists; adjust if CreatedTime or LastModifiedTime is needed
        time_filter = f"| where CreatedTime between (datetime({start_time}) .. datetime({end_time}))"
        time_filter_log_message = f"Using time range: {start_time} to {end_time}"
    else:
        default_time_range = DEFAULT_QUERY_TIME_RANGE
        time_filter = f"| where CreatedTime > ago({default_time_range})"
        time_filter_log_message = f"Using default time range: last {default_time_range}"

    Logger.info(f"Querying {table_name}. {time_filter_log_message}")

    kql_query = f"{table_name} {time_filter}| where Status == 'New'"
    query_payload = json.dumps({"query": kql_query})
    Logger.debug(f"KQL Query: {kql_query}")

    all_records = []
    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=30
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            table_data = query_result["tables"][0]
            columns = [col["name"] for col in table_data.get("columns", [])]
            rows = table_data.get("rows", [])
            if rows:
                Logger.debug(f"Found {len(rows)} records in '{table_name}'.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    record_dict["tableName"] = table_name
                    all_records.append(record_dict)
            else:
                Logger.debug(f"No records found in '{table_name}'.")
        else:
            Logger.debug(
                f"No data structure found in query response for '{table_name}'."
            )

    except requests.exceptions.Timeout:
        Logger.warn(f"Timeout occurred while querying data for table '{table_name}'.")
        return {"security_incidents_data": []}
    except requests.exceptions.RequestException as qe:
        Logger.warn(f"Could not query data for table '{table_name}'. Error: {qe}")
        if hasattr(qe, "response") and qe.response is not None:
            try:
                Logger.warn(f"Query Error Details: {qe.response.json()}")
            except ValueError:
                Logger.warn(f"Query Error Details: {qe.response.text}")
        return {"security_incidents_data": []}
    except Exception as qe_other:
        Logger.error(
            f"An unexpected error occurred querying data for table '{table_name}': {qe_other}\n{traceback.format_exc()}"
        )
        return {"error": f"Unexpected error querying {table_name}."}

    Logger.info(
        f"Finished querying {table_name} ({time_filter_log_message}). Found {len(all_records)} records."
    )
    return {"security_incidents_data": all_records}


async def sentinel_generate_kql_query(
    intcid: str,
    task: str,
    aid: str,
    table_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: dict,  # Accept dict or string
) -> dict:
    """Generates a Sentinel KQL query for a specific task and context using AI.

    Handles template generation, placeholder replacement (time, fields),
    validation, and retries.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed (requirement).
        table_name: The name of the target Sentinel table.
        tid: Triage ID for caching/persistence.
        question_id: The specific question ID within the triage process.
        triage_question: The text of the triage question being addressed.
        alert: The relevant alert/event content (dict or JSON string).
        env: Environment identifier.

    Returns:
        A dictionary containing the generated KQL query under the key 'query'.
        Returns an error dictionary if generation fails after retries.
        Example success: {'query': 'SecurityEvent | where ...'}
        Example error: {'error': 'Failed to generate valid KQL...'}
    """
    Logger.info(
        f"tool:sentinel_generate_kql_query: Starting for {intcid}, aid: {aid}, Table: {table_name}, Task: {task}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    schema = sentinel_utils.get_table_metadata(intcid, table_name)

    if not schema or len(schema) < 0:
        schema_query = f"{table_name} | getschema"
        schema = await sentinel_run_kql_query(
            intcid, "Get schema for table", schema_query
        )
        schema = schema.get("query_results")
        if not schema or len(schema) < 0:
            Logger.error(
                f"Could not retrieve schema for table '{table_name}'. Cannot generate query."
            )
            return {"error": f"Failed to get schema for table {table_name}."}

    max_retries = 5
    last_error_msg = ""
    for attempt in range(max_retries):
        query_template = None
        final_kql_query = None

        env = alert_context.get("env", "UNKNOWN").lower()
        try:
            query_template_resp = await sentinel_generate_kql_query_template(
                intcid=intcid,
                aid=aid,
                tid=tid,
                question_id=question_id,
                step_id=step_id,
                task=task,
                tables=[table_name],
                alert_context=alert_context,
                triage_question=triage_question,
            )
            if "error" in query_template_resp:
                last_error_msg = query_template_resp["error"]
                Logger.warn(
                    f"Attempt {attempt+1}: Failed to generate query template: {last_error_msg}"
                )
                continue
            query_template = query_template_resp.get("query_templates")[0]
            Logger.info(f"Query Template: {query_template}")

            final_kql_query_resp = await sentinel_prepare_kql_query(
                intcid=intcid,
                task=task,
                aid=aid,
                table_name=table_name,
                tid=tid,
                question_id=question_id,
                step_id=step_id,
                triage_question=triage_question,
                alert_context=alert_context,
                query_templates=[query_template],
            )
            if "error" in final_kql_query_resp:
                last_error_msg = final_kql_query_resp["error"]
                Logger.warn(
                    f"Attempt {attempt+1}: Failed to prepare final query: {last_error_msg}"
                )
                continue
            final_kql_query = final_kql_query_resp.get("queries")[0]
            Logger.info(f"Final KQL Query: {final_kql_query}")

            isValid, msg = sentinel_utils.validate_sentinel_kql(final_kql_query, intcid)
            if isValid:
                # --- Persistence Hook ---
                if query_template and final_kql_query:
                    try:
                        sentinel_utils.push_kql_template_data_to_mongo(
                            intcid=intcid,
                            siem_type="sentinel",
                            env=env,
                            tid=tid,
                            question_id=question_id,
                            step_id=step_id,
                            triage_question=triage_question,
                            requirement=task,
                            table_name=table_name,
                            query_template=query_template,
                            final_query=final_kql_query,
                        )
                    except Exception as persist_e:
                        Logger.warn(
                            f"Failed to persist KQL template/query: {persist_e}"
                        )

                Logger.info(
                    f"Successfully generated and validated KQL query for task: {task}"
                )
                Logger.debug(f"Final KQL query: {final_kql_query}")
                # Sanitize KQL query
                final_kql_query = final_kql_query.replace("\\n", "\n")
                # Add limit 10 to the final KQL query if not already present
                if "| limit" not in final_kql_query.lower():
                    final_kql_query = f"{final_kql_query.strip()}\n| limit 10"

                return {"query": final_kql_query}
            else:
                last_error_msg = msg
                Logger.warn(
                    f"Attempt {attempt+1}: Generated KQL failed validation: {msg}"
                )
        except Exception as e:
            last_error_msg = str(e)
            Logger.error(f"Attempt {attempt+1}: Exception during query generation: {e}")

    Logger.error(
        f"Failed to generate a valid KQL query after {max_retries} attempts for task: {task}"
    )
    return {
        "error": f"Failed to generate valid KQL after {max_retries} attempts. Last error: {last_error_msg}"
    }


async def sentinel_prepare_kql_query(
    intcid: str,
    task: str,
    aid: str,
    table_name: str,
    tid: str,
    question_id: str,
    step_id: str,
    triage_question: str,
    alert_context: dict,
    query_templates: list,
) -> dict:
    """Test the sentinel generate kql query."""
    Logger.info(
        f"tool:test_sentinel_generate_kql_query: Starting for {intcid}, Task: {task}"
    )
    queries = []
    for query_template in query_templates:
        Logger.info(f"Query Template: {query_template}")
        sentinel_utils = SentinelUtils(intcid=intcid)

        fields_list = sentinel_utils.extract_field_placeholders(query_template)
        fields_metadata = sentinel_utils.get_table_metadata(intcid, table_name)
        field_values_list = []
        for field in fields_list:
            # Find the metadata dict for this field
            field_meta = next(
                (f for f in fields_metadata if f.get("field") == field), None
            )
            if field_meta:
                field_value_dict = {
                    "field": field_meta.get("field", ""),
                    "description": field_meta.get("desc", ""),
                    "field_values": field_meta.get("field_values", []),
                }
            else:
                # If not found, send empty/defaults
                field_value_dict = {
                    "field": field,
                    "description": "",
                    "field_values": [],
                }
            field_values_list.append(field_value_dict)

        query = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="KQL_FIELD_VALUE_REPLACEMENT_PROMPT",
            prompt_params={
                "requirement": task,
                "query_template": query_template,
                "alert": alert_context,
                "field_values_list": field_values_list,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sentinel_models.FinalQuery,
            history_params={
                "aid": aid,
                "tid": tid,
                "qid": question_id,
                "step_id": step_id,
                "subtype": "prepare_query",
            },
            type="triage",
            system_prompt="You are an expert in Microsoft Sentinel and KQL. Your task is to replace field placeholders in the provided KQL query template with actual values based on the alert context. The output should be a valid KQL query that can be executed against the specified table.",
        )

        query = query.get("final_query")
        queries.append(query)
        Logger.info(f"Query: {query}")
    return {"queries": queries}


async def standalone_sentinel_prepare_kql_query(
    intcid: str,
    task: str,
    alert_context: dict,
    query_template: str,
    question_id: Optional[str] = None,
    step_id: Optional[str] = None,
    tid: Optional[str] = None,
    aid: Optional[str] = None,
):
    """Prepares a KQL query by replacing field placeholders with actual values.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed (requirement).
        alert_context: The alert context.
        query_template: The KQL query template with placeholders.

    Returns:
        A dictionary containing the final KQL query under the key 'query'.
        Returns an error dictionary if preparation fails.
        Example success: {'query': 'SecurityEvent | where ...'}
        Example error: {'error': 'Failed to prepare KQL query.'}
    """
    Logger.info(
        f"tool:standalone_sentinel_prepare_kql_query: Starting for {intcid}, Task: {task}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_template_response = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="VALIDATE_KQL_QUERY_TEMPLATE_PROMPT",
        prompt_params={
            "requirement": task,
            "alert_context": alert_context,
            "query_template": query_template,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=sentinel_models.QueryTemplate,
        history_params={
            "aid": aid,
            "tid": tid,
            "qid": question_id,
            "step_id": step_id,
            "subtype": "prepare_query_template",
        },
        type="triage",
        system_prompt="You are an expert in Microsoft Sentinel and KQL. Your task is to generate a KQL query template based on the provided requirement and alert context. The output should be a valid KQL query template that can be executed against the specified table.",
    )
    
    query_template_final = query_template_response.get("query_template")
    Logger.info(f"Query Template after Validation: {query_template_final}")
    if query_template_final:
        query_template = query_template_final

    query = AIManager.run_prompt_with_structured_output(
        intcid=intcid,
        prompt_template_name="KQL_TEMPLATE_FIELD_VALUE_REPLACEMENT_PROMPT",
        prompt_params={
            "requirement": task,
            "query_template": query_template,
            "alert": alert_context,
        },
        model_name=PropX.get_property("module.llm.model"),
        model_class=sentinel_models.FinalQuery,
        history_params={
            "aid": aid,
            "tid": tid,
            "qid": question_id,
            "step_id": step_id,
            "subtype": "prepare_query",
        },
        type="triage",
        system_prompt="You are an expert in Microsoft Sentinel and KQL. Your task is to replace field placeholders in the provided KQL query template with actual values based on the alert context. The output should be a valid KQL query that can be executed against the specified table.",
    )

    query = query.get("final_query")
    if not query:
        return {"error": "Failed to prepare KQL query. No final query generated."}
    Logger.info(f"Final KQL Query: {query}")
    isValid, msg = sentinel_utils.validate_sentinel_kql(query, intcid)
    if not isValid:
        return {"error": f"Prepared KQL query is invalid: {msg}"}
    # Sanitize KQL query
    query = query.replace("\\n", "\n")
    # Add limit 10 to the final KQL query if not already present
    if "| limit" not in query.lower():
        query = f"{query.strip()}\n| limit 10"
    return {"query": query}


async def sentinel_generate_kql_query_template(
    intcid: str,
    aid: str,
    tid: str,
    question_id: str,
    step_id: str,
    task: str,
    tables: list,
    alert_context: dict,
    triage_question: str,
) -> dict:
    """Generates a KQL query template for a given task and context using AI.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed (requirement).
        tables: The list of tables to generate a query template for.
        alert_context: The alert context.

    Returns:
        A dictionary containing the generated KQL query template under the key 'query_template'.
        Returns an error dictionary if generation fails.
        Example success: {'query_template': 'SecurityEvent | where ...'}
        Example error: {'error': 'Failed to generate valid KQL query template...'}
    """

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    try:
        _query_template = sentinel_utils.get_kql_template_data_from_mongo(
            intcid=intcid,
            env=alert_context["env"],
            tid=tid,
            question_id=question_id,
            step_id=step_id,
        )

        if _query_template and _query_template != "":
            Logger.info(f"Using cached KQL template for {intcid}, table: {tables}")
            return {"query_templates": [_query_template]}
    except Exception as e:
        Logger.error(f"Error getting KQL template from MongoDB: {e}")
        pass

    query_templates = []
    for table in tables:
        schema_query = f"{table} | getschema"
        schema = await sentinel_run_kql_query(
            intcid, "Get schema for table", schema_query
        )
        schema = schema.get("query_results")
        
        schema = sentinel_utils.format_schema_to_string(schema)
        
        if not schema or len(schema) < 0:
            Logger.error(
                f"Could not retrieve schema for table '{table}'. Cannot generate query."
            )
            return {"error": f"Failed to get schema for table {table}."}

        # sample_records = await fetch_sample_records(intcid, table)
        sample_records_query = sentinel_utils.get_sample_records(intcid, table, schema, task, aid, tid, question_id, step_id)
        
        if sample_records_query is None:
            sample_records_query = f"{table} | take 3"
        
        else:
            sample_records = await sentinel_run_kql_query(
                intcid=intcid,
                task=task,
                kql_query=sample_records_query,
            )
            if "error" in sample_records:
                sample_records = await sentinel_run_kql_query(
                intcid=intcid,
                task=task,
                kql_query=f"{table} | take 3",
            )
            else:
                sample_records = sample_records.get("query_results")

        Logger.info(f"Fetched {len(sample_records)} sample records for {table}")
        Logger.debug(f"Sample Records: {sample_records}")

        query_template = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="KQL_QUERY_TEMPLATE_PROMPT",
            prompt_params={
                "requirement": task,
                "triage_question": triage_question,
                "alert": alert_context,
                "table_name": table,
                "schema": schema,
                "sample_records": sample_records,
                "env": alert_context["env"],
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sentinel_models.QueryTemplateOutput,
            history_params={
                "aid": aid,
                "tid": tid,
                "qid": question_id,
                "step_id": step_id,
                "subtype": "query",
            },
            type="triage",
            system_prompt="You are an expert in Microsoft Sentinel and KQL. Your task is to generate a KQL query template based on the provided requirement, alert context, table name, and schema. The output should be a valid KQL query template that can be used to fetch relevant data from the specified table.",
        )

        query_template = query_template.get("query_template")
        Logger.info(f"Query Template: {query_template}")
        query_templates.append(query_template)

    return {"query_templates": query_templates}


async def sentinel_run_kql_query(intcid: str, task: str, kql_query: str) -> dict:
    """Executes a given KQL query against the Sentinel Log Analytics workspace.

    Authenticates, gets workspace ID, and runs the query using the Log Analytics API.

    Args:
        intcid: Integration/Customer ID.
        task: Description of the task executing the query.
        kql_query: The KQL query string to execute.

    Returns:
        A dictionary containing the query results under the key 'query_results'.
        Each result is a dictionary representing a row. Returns an empty list
        if no data is found. Returns an error dictionary on failure.
        Example success: {'query_results': [{'TimeGenerated': '...', ...}]}
        Example error: {'error': 'Authentication failed.'}
    """
    Logger.info(f"tool:sentinel_run_kql_query: Starting for {intcid}, Task: {task}")
    Logger.debug(f"Executing KQL: {kql_query}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    query_api_version = "v1"
    query_url = f"https://api.loganalytics.io/{query_api_version}/workspaces/{workspace_id}/query"
    la_headers = {
        "Authorization": f"Bearer {sentinel_utils.la_access_token.token}",
        "Content-Type": "application/json",
    }
    
    if not kql_query:
        Logger.error("KQL query is empty. Cannot execute.")
        return {"error": "KQL query is empty. Cannot execute."}
    query_payload = json.dumps({"query": kql_query})

    all_records = []

    try:
        query_response = requests.post(
            query_url, headers=la_headers, data=query_payload, timeout=60
        )
        query_response.raise_for_status()
        query_result = query_response.json()

        Logger.debug(f"Query response: {query_result}")
        if (
            query_result.get("tables")
            and len(query_result["tables"]) > 0
            and query_result["tables"][0].get("rows")
        ):
            primary_table = query_result["tables"][0]
            columns = [col["name"] for col in primary_table.get("columns", [])]
            rows = primary_table.get("rows", [])
            if rows:
                Logger.info(f"Query returned {len(rows)} records.")
                for row in rows:
                    record_dict = dict(zip(columns, row))
                    all_records.append(record_dict)
            else:
                Logger.info("Query executed successfully but returned no records.")
        else:
            Logger.info(
                "Query executed successfully but the response structure had no primary table data."
            )

    except requests.exceptions.Timeout:
        Logger.warn(
            f"Timeout occurred while executing KQL query for task '{task}'. Query: {kql_query}"
        )
        return {"error": "Query execution timed out."}
    except requests.exceptions.HTTPError as http_err:
        Logger.error(
            f"HTTP error occurred while executing KQL query {kql_query}: {http_err}"
        )
        error_details = ""
        try:
            error_content = http_err.response.json()
            error_details = error_content.get("error", {}).get(
                "message", http_err.response.text
            )
            Logger.error(f"Query Error Details: {error_content}")

        except ValueError:
            error_details = http_err.response.text
            Logger.error(f"Query Error Details (non-JSON): {error_details}")
        return {
            "error": f"Query execution failed with HTTP status {http_err.response.status_code}. Details: {error_details}"
        }
    except requests.exceptions.RequestException as req_err:
        Logger.error(f"Request error occurred while executing KQL query: {req_err}")
        return {"error": f"Network or request error during query execution: {req_err}"}
    except Exception as e:
        Logger.error(
            f"An unexpected error occurred executing KQL query: {e}\n{traceback.format_exc()}"
        )
        return {"error": f"An unexpected error occurred during query execution: {e}"}

    Logger.info(
        f"Finished executing KQL query for task: {task}. Found {len(all_records)} records."
    )

    return {"query_results": all_records}


async def sentinel_get_single_matching_record(
    intcid: str, task: str, table_name: str, kql_query: str
) -> dict:
    """Fetches a single record matching a specific KQL query from a Sentinel table.

    Uses the `get_single_matching_record` method from `SentinelUtils`, which
    handles authentication and query execution, ensuring only one record is fetched.

    Args:
        intcid: The customer integration ID.
        task: A description of the task requesting the record (for logging).
        table_name: The name of the Sentinel table targeted by the query.
        kql_query: The KQL query string expected to return a single record.

    Returns:
        A dictionary containing the table name, query, and the matching record
        under the key 'result'. Returns an error dictionary if fetching fails or
        no record is found by the query.
        Example success: {'table_name': 'SecurityEvent', 'kql_query': '...', 'result': {...}}
    """
    Logger.info(
        f"tool:sentinel_get_single_matching_record: Starting for {intcid}, Task: {task}, Table: {table_name}"
    )
    Logger.debug(f"Executing KQL to get single record: {kql_query}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    execution_result = sentinel_utils.get_single_matching_record(
        intcid, table_name, kql_query
    )

    if "error" in execution_result:
        Logger.error(
            f"Error executing KQL for single record: {execution_result['error']}"
        )
        # Propagate the specific error from the utility function
        return {"error": execution_result}

    # The utility function returns {"matching_record": {}} if no record is found
    matching_record = execution_result.get("matching_record", {})

    if not matching_record:
        Logger.warn(
            f"Query for single record executed successfully but returned no results. Query: {kql_query}"
        )
    else:
        Logger.info(f"Successfully fetched single matching record from {table_name}.")

    return {
        "table_name": table_name,
        "query": kql_query,
        "result": matching_record,
    }


async def sentinel_get_alert_context(
    intcid: str, task: str, aid: str, alert: any, alert_name: str = ""
) -> dict:
    """Retrieves context for a given Sentinel alert/event using AI.

    If the input is a SecurityIncident, it attempts to fetch the underlying
    SecurityAlerts. It then determines the relevant environment, fetches sample
    matching records and table schema for the relevant table (Incident or Alert),
    and uses AI to extract context relevant to the specified task and alert/event data.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed from the alert context.
        alert: The Sentinel alert/event content (dict or JSON string).

    Returns:
        A dictionary containing the extracted alert context under the key
        'alert_context', including the environment ('env'). Returns an error
        dictionary if context extraction fails.
        Example success: {'alert_context': {'field1': 'val1', 'env': 'Prod'}}
        Example error: {'error': 'Failed to determine environment.'}
    """
    Logger.info(f"tool:sentinel_get_alert_context: Starting for {intcid}, Task: {task}")

    try:
        alert_dict = json.loads(alert) if isinstance(alert, str) else alert
        if not isinstance(alert_dict, dict):
            raise ValueError("Parsed alert is not a dictionary.")
    except (json.JSONDecodeError, ValueError) as e:
        Logger.error(f"Failed to parse input alert: {e}. Alert data: {alert}")
        return {"error": "Invalid alert format provided."}

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    # Initialize context data and target table name
    context_data = alert_dict
    target_table_name = alert_dict.get("tableName") or alert_dict.get("Type")
    original_alert_type = target_table_name
    Logger.debug(f"Initial context type: {original_alert_type}")

    # --- Check if it's a SecurityIncident and fetch related alerts ---
    if original_alert_type == "SecurityIncident":
        Logger.info("Input is a SecurityIncident. Attempting to fetch related alerts.")
        alert_ids_str = alert_dict.get("AlertIds", "[]")
        try:
            alert_id_list = json.loads(alert_ids_str)
            if isinstance(alert_id_list, list) and alert_id_list:
                # Construct KQL query for SecurityAlert
                alert_id_filter = ",".join([f"'{id}'" for id in alert_id_list])
                kql_query = (
                    f"SecurityAlert | where SystemAlertId in ({alert_id_filter})"
                )
                Logger.debug(f"Fetching related alerts with KQL: {kql_query}")

                # Use sentinel_run_kql_query to fetch alerts
                fetched_alerts_result = await sentinel_run_kql_query(
                    intcid,
                    f"fetch related alerts for incident {alert_dict.get('IncidentNumber', '')}",
                    kql_query,
                )

                if "error" in fetched_alerts_result:
                    Logger.warn(
                        f"Failed to fetch related SecurityAlerts: {fetched_alerts_result['error']}. Proceeding with Incident data."
                    )
                elif fetched_alerts_result.get("query_results"):
                    context_data = fetched_alerts_result["query_results"]
                    target_table_name = "SecurityAlert"  # Update target table
                    Logger.info(
                        f"Successfully fetched {len(context_data)} related SecurityAlerts. Using alerts as context."
                    )
                else:
                    Logger.warn(
                        "Fetching related SecurityAlerts returned no results. Proceeding with Incident data."
                    )
            else:
                Logger.warn(
                    "No AlertIds found or invalid format in SecurityIncident. Proceeding with Incident data."
                )
        except json.JSONDecodeError:
            Logger.warn(
                "Failed to parse AlertIds JSON string. Proceeding with Incident data."
            )
        except Exception as e:
            Logger.warn(
                f"Error fetching related alerts: {e}. Proceeding with Incident data."
            )

    # Prepare alert string from the final context_data (could be incident or list of alerts)
    alert_str = json.dumps(context_data)

    # --- Step 1: Determine Environment ---
    env = None
    try:
        # system_prompt = "You are an expert in Microsoft Sentinel and KQL. Your task is to determine the environment (e.g., Production, Staging, Development) based on the provided alert context. The output should be a single word representing the environment."

        # env_response = AIManager.run_prompt_with_structured_output(
        #     intcid=intcid,
        #     prompt_template_name="SENTINEL_ENVIRONMENT_SELECTION_PROMPT",
        #     prompt_params={"alert": alert_str},
        #     model_name=PropX.get_property("module.llm.model"),
        #     model_class=sentinel_models.Environment,
        #     history_params={
        #         "aid": aid,
        #         "subtype": "alert_context",
        #     },
        #     type="triage",
        #     system_prompt="You are an expert in understanding Microsoft Sentinel Alerts. Your task is to detemine envinronment based on the provided alert.",
        # )
        # Logger.debug(f"AI response for environment selection: {env_response}")
        # env = env_response.get("env", "unknown").lower()
        env = "unknown"

        if not env:
            Logger.warn(f"Could not determine environment from AI response: {env}")
            return {"error": "Failed to determine environment."}
        Logger.info(f"Determined environment: {env}")
    except Exception as e:
        Logger.error(f"Error determining environment: {e}\n{traceback.format_exc()}")
        # Allow proceeding without env
        env = "unknown"
        Logger.warn(f"Failed to determine environment: {e}. Setting to 'Unknown'.")

    # --- Step 2: Get Schema for the target table ---
    schema = None
    schema_str = "{}"
    if target_table_name:
        status, schema = sentinel_utils.get_table_schema(target_table_name)
        if not schema:
            Logger.warn(
                f"Could not retrieve schema for determined table '{target_table_name}'."
            )
        else:
            schema_str = json.dumps(schema)
            Logger.info(f"Successfully retrieved schema for table: {target_table_name}")
    else:
        Logger.warn("Target table name could not be determined. Cannot fetch schema.")

    try:
        alert_context = AIManager.run_prompt_with_structured_output(
            intcid=intcid,
            prompt_template_name="TEST_ALERT_CONTEXT_EXTRACTION_PROMPT",
            prompt_params={
                "alert": alert_str,  # This now contains either the original alert/incident or the list of fetched alerts
                "env": env,
                "requirement": task,
                "table_name": target_table_name
                or "Unknown",  # Pass the determined table name
                "table_schema_details": schema_str,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=sentinel_models.AlertContextResponse,
            history_params={
                "aid": aid,
                "subtype": "alert_context",
            },
            type="triage",
            system_prompt="You are an expert in understanding Microsoft Sentinel Alerts. Your task is to extract context parameters from given input which included received alert.",
        )

        Logger.info(f"AI response for context extraction: {alert_context}")
        alert_context = transform_alert_context(alert_context)
        alert_context["env"] = env  # Ensure env is included
        alert_context["alert_type"] = original_alert_type
        Logger.info(f"Successfully extracted alert context for task: {task}")

        user_name_value = (
            alert_context.get("extracted_fields", {}).get("user_name", {}).get("value")
        )

        final_enriched_alert_context = None


        rag_enriched_alert_context = await enrich_alert_context_using_rag(intcid, aid, alert, alert_context, alert_name)
        Logger.info(f"RAG Enriched Alert Context: {rag_enriched_alert_context}")
        if user_name_value:
            # Always extract the username before '@'
            Logger.info(f"Extracting user name from value: {user_name_value}")
            if isinstance(user_name_value, list):
                username = user_name_value[0].split("@")[0]
            else:
                username = user_name_value.split("@")[0]
            user_email = sentinel_utils.user_lookup(intcid, username)
            alert_context["extracted_fields"]["user_name"]["value"] = [username, user_email] if user_email else [username]
            Logger.info(f"Alert Context: {alert_context}")
            final_enriched_alert_context = await enrich_alert_context(intcid, rag_enriched_alert_context, aid)

        if final_enriched_alert_context:
            Logger.info("Successfully enriched alert context with user details.")
            return final_enriched_alert_context
        else:
            Logger.info("No user enrichment performed. Returning basic alert context.")
            return final_enriched_alert_context
    except Exception as e:
        Logger.error(
            f"Error during Sentinel context extraction: {e}\n{traceback.format_exc()}"
        )
        return {"error": f"An unexpected error occurred during context extraction: {e}"}


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


async def fetch_sample_records(intcid: str, table_name: str, limit: int = 3) -> dict:
    """
    Fetches sample records from the specified table using SentinelUtils.

    Args:
        intcid (str): The integration/customer ID.
        table_name (str): The name of the table to fetch records from.
        limit (int): The number of sample records to fetch (default is 3).

    Returns:
        dict: A dictionary containing the sample records or an error message.
    """
    Logger.info(
        f"Fetching {limit} sample records from table: {table_name} for intcid: {intcid}"
    )

    sentinel_utils = SentinelUtils(intcid=intcid)

    # Authenticate with Sentinel
    if not sentinel_utils.authenticate():
        Logger.error("Failed to authenticate with Sentinel.")
        return {"error": "Authentication failed. Check configuration and credentials."}

    # Fetch sample records using the utility function
    kql_query = f"{table_name} | take {limit}"
    result = sentinel_utils.get_matching_records(intcid, table_name, kql_query, limit)

    if "error" in result:
        Logger.error(f"Error fetching sample records: {result['error']}")
        return {"error": result["error"]}

    Logger.info(f"Successfully fetched sample records from table: {table_name}")
    return {"sample_records": result.get("matching_records", [])}


async def sentinel_functions(intcid: str, task: str) -> dict:
    """Retrieves KQL functions from Sentinel's Log Analytics workspace.

    Args:
        intcid: The customer integration ID.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the list of KQL functions found in the workspace.
    """
    Logger.info(f"tool:sentinel_functions: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    workspace_id = sentinel_utils.get_workspace_id()
    if not workspace_id:
        return {"error": "Failed to retrieve Workspace ID. Check configuration."}

    try:
        functions = sentinel_utils.get_sentinel_functions()
        if not functions:
            Logger.info("No KQL functions found in the workspace.")
            return {"functions": []}
        Logger.info(f"Found {len(functions)} KQL functions in the workspace.")
        return {"functions": functions}

    except Exception as e:
        Logger.error(f"Error retrieving KQL functions: {e}")
        return {"error": f"An error occurred while retrieving KQL functions: {e}"}


async def get_top_matching_tables(intcid: str, tags: str, task: str) -> dict:
    """Retrieves the top matching tables based on provided tags.

    Args:
        intcid: The customer integration ID.
        tags: A comma-separated string of tags to match against table metadata.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the list of matching tables.
    """
    Logger.info(f"tool:get_top_matching_tables: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    try:
        # matching_tables = sentinel_utils.get_top_matching_tables_using_tags(intcid, tags)
        matching_tables = sentinel_utils.get_relevant_sentinel_tables(intcid, tags)
        if "error" in matching_tables:
            Logger.error(
                f"Error retrieving matching tables: {matching_tables['error']}"
            )
            Logger.info("No matching tables found for the provided tags.")
            return {"tables": []}
        matching_tables = matching_tables.get("matching_tables")
        Logger.info(f"Found {len(matching_tables)} matching tables.")
        return {"tables": matching_tables}

    except Exception as e:
        Logger.error(f"Error retrieving matching tables: {e}")
        return {"error": f"An error occurred while retrieving matching tables: {e}"}


async def get_user_auth_details(intcid: str, alert_context: dict, task: str) -> dict:
    """Retrieves user authentication details for the specified integration ID.

    Args:
        intcid: The customer integration ID.
        alert_context: The context of the alert, which may include user information.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the user authentication details.
    """
    Logger.info(f"tool:get_user_auth_details: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    try:
        template_name = "auth_lookup"
        query_template = sentinel_utils.get_sentinel_template(intcid, template_name)
        user_details = []
        if not query_template:
            Logger.info("No user authentication details found.")
            return {"user_auth_details": {}}
        if isinstance(query_template, str):
            try:
                kql_query = await standalone_sentinel_prepare_kql_query(intcid, task, alert_context, query_template)
                if "error" in kql_query:
                    Logger.info("No KQL query generated.")
                    return {"user_auth_details": {}}
                kql_query = kql_query.get("query", "")
                if not kql_query:
                    Logger.info("No KQL query generated.")
                    return {"user_auth_details": {}}
                query_result = await sentinel_run_kql_query(
                    intcid, task, kql_query
                )
                if "error" in query_result:
                    Logger.error(f"Error running KQL query: {query_result['error']}")
                    return {"user_auth_details": {}}
                user_details = query_result.get("query_results", [])
            except Exception as e:
                Logger.error(f"Error retrieving user authentication details: {e}")
                return {"error": f"Failed to retrieve user authentication details: {e}"}
        Logger.info("Successfully retrieved user authentication details.")
        return {"user_auth_details": user_details}

    except (ValueError, TypeError) as e:
        Logger.error(f"Error retrieving user authentication details: {e}")
        return {"error": f"An error occurred while retrieving user authentication details: {e}"}


async def get_user_role(intcid: str, alert_context: dict, task: str) -> dict:
    """Retrieves user role details for the specified integration ID.

    Args:
        intcid: The customer integration ID.
        alert_context: The context of the alert, which may include user information.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the user role details.
    """
    Logger.info(f"tool:get_user_role: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    query_template = sentinel_utils.get_sentinel_template(intcid, "role_lookup")
    if not query_template:
        Logger.info("No user role lookup template found.")
        return {"user_role_details": {}}

    try:
        kql_query = await standalone_sentinel_prepare_kql_query(
            intcid, task, alert_context, query_template
        )
        if "error" in kql_query:
            Logger.info("No KQL query generated.")
            return {"user_role_details": {}}
        kql_query = kql_query.get("query", "")
        if not kql_query:
            Logger.info("No KQL query generated.")
            return {"user_role_details": {}}

        query_result = await sentinel_run_kql_query(intcid, task, kql_query)
        if "error" in query_result:
            Logger.error(f"Error running KQL query: {query_result['error']}")
            return {"user_role_details": {}}

        user_roles = query_result.get("query_results", [])
        if not user_roles:
            Logger.info("No user role details found.")
            return {"user_role_details": {}}
        # user_roles is a list of dicts; take the first one
        role_info = user_roles[0] if isinstance(user_roles, list) and user_roles else user_roles
        is_admin = role_info.get("is_admin", False)
        role = "admin" if is_admin else "user"
        Logger.info("Successfully retrieved user role details.")
        return {"user_role_details": role}
    except (ValueError, TypeError) as e:
        Logger.error(f"Error retrieving user role details: {e}")
        return {"error": f"An error occurred while retrieving user role details: {e}"}
    
async def get_user_ip_details(intcid:str, alert_context: dict, task: str) -> dict:
    """Retrieves user IP details for the specified integration ID.

    Args:
        intcid: The customer integration ID.
        alert_context: The context of the alert, which may include user information.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the user IP details.
    """
    Logger.info(f"tool:get_user_ip_details: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    query_template = sentinel_utils.get_sentinel_template(intcid, "ip_lookup")
    if not query_template:
        Logger.info("No user IP lookup template found.")
        return {"user_ip_details": {}}

    try:
        kql_query = await standalone_sentinel_prepare_kql_query(
            intcid, task, alert_context, query_template
        )
        if "error" in kql_query:
            Logger.info("No KQL query generated.")
            return {"user_ip_details": {}}
        kql_query = kql_query.get("query", "")
        if not kql_query:
            Logger.info("No KQL query generated.")
            return {"user_ip_details": {}}

        query_result = await sentinel_run_kql_query(intcid, task, kql_query)
        if "error" in query_result:
            Logger.error(f"Error running KQL query: {query_result['error']}")
            return {"user_ip_details": {}}

        user_ips = query_result.get("query_results", [])
        if not user_ips:
            Logger.info("No user IP details found.")
            return {"user_ip_details": {}}
        
        # user_ips is a list of dicts; take the first one
        ip_info = user_ips
        Logger.info("Successfully retrieved user IP details.")
        return {"user_ip_details": ip_info}
    except (ValueError, TypeError) as e:
        Logger.error(f"Error retrieving user IP details: {e}")
        return {"error": f"An error occurred while retrieving user IP details: {e}"}
    
async def get_successful_login_details(intcid: str, alert_context: dict, task: str) -> dict:
    """Retrieves successful login details for the specified integration ID.

    Args:
        intcid: The customer integration ID.
        alert_context: The context of the alert, which may include user information.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the successful login details.
    """
    Logger.info(f"tool:get_successful_login_details: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    query_template = sentinel_utils.get_sentinel_template(intcid, "successful_login_lookup")
    if not query_template:
        Logger.info("No successful login lookup template found.")
        return {"successful_login_details": {}}

    try:
        kql_query = await standalone_sentinel_prepare_kql_query(
            intcid, task, alert_context, query_template
        )
        if "error" in kql_query:
            Logger.info("No KQL query generated.")
            return {"successful_login_details": {}}
        kql_query = kql_query.get("query", "")
        if not kql_query:
            Logger.info("No KQL query generated.")
            return {"successful_login_details": {}}

        query_result = await sentinel_run_kql_query(intcid, task, kql_query)
        if "error" in query_result:
            Logger.error(f"Error running KQL query: {query_result['error']}")
            return {"successful_login_details": {}}

        successful_logins = query_result.get("query_results", [])
        if not successful_logins:
            Logger.info("No successful login details found.")
            return {"successful_login_details": {}}
        
        # successful_logins is a list of dicts; take the first one
        login_info = successful_logins
        Logger.info("Successfully retrieved successful login details.")
        return {"successful_login_details": login_info}
    except (ValueError, TypeError) as e:
        Logger.error(f"Error retrieving successful login details: {e}")
        return {"error": f"An error occurred while retrieving successful login details: {e}"}
    
async def get_failed_login_details(intcid: str, alert_context: dict, task: str) -> dict:
    """Retrieves failed login details for the specified integration ID.

    Args:
        intcid: The customer integration ID.
        alert_context: The context of the alert, which may include user information.
        task: The specific task or information needed.

    Returns:
        A dictionary containing the failed login details.
    """
    Logger.info(f"tool:get_failed_login_details: Starting for {intcid}, Task: {task}")

    sentinel_utils = SentinelUtils(intcid=intcid)
    if not sentinel_utils.authenticate():
        return {"error": "Authentication failed. Check configuration and credentials."}

    query_template = sentinel_utils.get_sentinel_template(intcid, "failed_login_lookup")
    if not query_template:
        Logger.info("No failed login lookup template found.")
        return {"failed_login_details": {}}

    try:
        kql_query = await standalone_sentinel_prepare_kql_query(
            intcid, task, alert_context, query_template
        )
        if "error" in kql_query:
            Logger.info("No KQL query generated.")
            return {"failed_login_details": {}}
        kql_query = kql_query.get("query", "")
        if not kql_query:
            Logger.info("No KQL query generated.")
            return {"failed_login_details": {}}

        query_result = await sentinel_run_kql_query(intcid, task, kql_query)
        if "error" in query_result:
            Logger.error(f"Error running KQL query: {query_result['error']}")
            return {"failed_login_details": {}}

        failed_logins = query_result.get("query_results", [])
        if not failed_logins:
            Logger.info("No failed login details found.")
            return {"failed_login_details": {}}
        
        # failed_logins is a list of dicts; take the first one
        login_info = failed_logins
        Logger.info("Successfully retrieved failed login details.")
        return {"failed_login_details": login_info}
    except (ValueError, TypeError) as e:
        Logger.error(f"Error retrieving failed login details: {e}")
        return {"error": f"An error occurred while retrieving failed login details: {e}"}
    

async def enrich_alert_context_using_rag(intcid, aid, alert, alert_context, sanitized_alert_name="") -> Dict: 
    Logger.info("[NODE] Executing node: enrich_alert_context_using_rag")

    extracted_fields = alert_context.get('extracted_fields', {}) if isinstance(alert_context, dict) else {}
    username_present = bool(extracted_fields.get('user_name', {}).get('value'))
    source_ip_present = bool(extracted_fields.get('source_ip', {}).get('value'))
    target_ip_present = bool(extracted_fields.get('target_ip', {}).get('value'))
    ip_present = source_ip_present or target_ip_present
    if username_present and ip_present:
        Logger.info("Both username and (source_ip or target_ip) are present in alert context. Skipping enrichment.")
        return alert_context
    
    # Check MongoDB first if sanitized_alert_name is provided
    final_ans_dict = None
    main_db = PropX.get_property("module.integration.config.db")
    if not main_db:
        main_db = "main_db"

    query_templates_collection = PropX.get_property("module.query.template.cache.collection")

    if sanitized_alert_name:
        try:

            
            mongo_filter = {
                "type": "alert_context_enrichment_template",
                "intcid": intcid,
                "alert_name": sanitized_alert_name
            }
            cached_template = MongoDBManager.get_record_by_multiple_fields(
                main_db, query_templates_collection, mongo_filter
            )
            
            if cached_template:
                Logger.info(f"Found cached final_ans_dict for alert: {sanitized_alert_name}")
                final_ans_dict = cached_template.get("matching_indices_and_fields", {})
                if final_ans_dict:
                    Logger.info("Using cached final_ans_dict for enrichment")
                    grouped_by_index = cached_template.get("index_groups", {})
                    
                    enriched_alert_context = alert_context
                    
                    if username_present and not ip_present:
                        Logger.info("Username present in alert context. Enriching with user-based KQL queries using cached data.")
                        enriched_alert_context = await run_kql_and_collect(
                            final_ans_dict, grouped_by_index, alert, aid, alert_context, intcid, use_user_kql=True
                        )
                    elif ip_present and not username_present:
                        Logger.info("IP address present in alert context. Enriching with IP-based KQL queries using cached data.")
                        enriched_alert_context = await run_kql_and_collect(
                            final_ans_dict, grouped_by_index, alert, aid, alert_context, intcid, use_user_kql=False
                        )
                    
                    Logger.info("RAG enrichment completed successfully using cached data.")
                    return enriched_alert_context
        except Exception as e:
            Logger.error(f"Error checking MongoDB for cached template: {e}")
    
    # If not found in cache, proceed with original logic
    table_index_name = PropX.get_property("elasticsearch.table.index.name")
    if not table_index_name:
        table_index_name = "tables_index"
    username_matching_tables = get_matching_tables_for_username(intcid)
    ip_matching_tables = get_matching_tables_for_ip(intcid)
    username_grouped_by_index, ip_grouped_by_index, common_indices, grouped_by_index = group_tables(
        username_matching_tables, ip_matching_tables
    )
    final_ans_dict = build_final_ans_dict(common_indices, username_grouped_by_index, ip_grouped_by_index)

    enriched_alert_context = alert_context
    
    if username_present and not ip_present:
        Logger.info("Username present in alert context. Enriching with user-based KQL queries.")
        enriched_alert_context = await run_kql_and_collect(
            final_ans_dict, grouped_by_index, alert, aid, alert_context, intcid, use_user_kql=True
        )
    
    elif ip_present and not username_present:
        Logger.info("IP address present in alert context. Enriching with IP-based KQL queries.")
        enriched_alert_context = await run_kql_and_collect(
            final_ans_dict, grouped_by_index, alert, aid, alert_context, intcid, use_user_kql=False
        )
    
    else:
        Logger.info("Neither username nor IP present in alert context. No enrichment possible.")
        return alert_context

    # Store filtered final_ans_dict in MongoDB if sanitized_alert_name is provided
    if sanitized_alert_name and final_ans_dict and enriched_alert_context:
        try:
            # Get tables_with_discoveries from the enriched context
            tables_with_discoveries = enriched_alert_context.get("extracted_fields", {}).get("tables_with_discoveries", [])
            Logger.info(f"Tables with discoveries: {tables_with_discoveries}")
            
            # Filter final_ans_dict to only include indices and fields present in tables_with_discoveries
            filtered_final_ans_dict = {}
            filtered_grouped_by_index = {}
            
            for table_name in tables_with_discoveries:
                if table_name in final_ans_dict:
                    filtered_final_ans_dict[table_name] = final_ans_dict[table_name]
                if table_name in grouped_by_index:
                    filtered_grouped_by_index[table_name] = grouped_by_index[table_name]
            
            if filtered_final_ans_dict:              
                
                mongo_filter = {
                    "type": "alert_context_enrichment_template",
                    "intcid": intcid,
                    "alert_name": sanitized_alert_name
                }
                
                document = {
                    "type": "alert_context_enrichment_template",
                    "intcid": intcid,
                    "alert_name": sanitized_alert_name,
                    "matching_indices_and_fields": filtered_final_ans_dict,
                    "index_groups": filtered_grouped_by_index,
                    "created_at": datetime.datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.datetime.now(timezone.utc).isoformat()
                }
                
                MongoDBManager.insert_record(main_db, query_templates_collection, document)
                Logger.info(f"Stored filtered final_ans_dict in MongoDB for alert: {sanitized_alert_name} (tables: {list(filtered_final_ans_dict.keys())})")
            else:
                Logger.info(f"No data to store in MongoDB - no tables with discoveries found for alert: {sanitized_alert_name}")
        except Exception as e:
            Logger.error(f"Error storing filtered final_ans_dict in MongoDB: {e}")

    Logger.info("RAG enrichment completed successfully.")
    return enriched_alert_context


  
async def enrich_alert_context(intcid, alert_context, aid, ) -> dict:
    """
    Enrich alert context with additional data from external sources.
    """
    Logger.info("[NODE] Executing node: enrich_alert_context")
    try:
        if not alert_context or not isinstance(alert_context, dict):
            Logger.warn("No valid alert context found to enrich")
            return {
                "alert_context": alert_context,
                "context_enrichment_status": False
            }

        Logger.info(f"Enriching alert context for intcid: {intcid}, aid: {aid}")

        enriched_context = alert_context.copy()
        enriched_context["discovery"] = {}

        task = f"Enrich alert context for aid: {aid}"

        try:
            sentinel_utils = SentinelUtils(intcid=intcid)

            user_auth_result = await get_user_auth_details(intcid, alert_context, task)
            enriched_context["discovery"]["user_auth_details"] = user_auth_result

            Logger.info(f"Calling get_user_role_from_mongo for intcid: {intcid}, aid: {aid}")
            user_role_result = await sentinel_utils.get_user_role_from_mongo(intcid, alert_context, task)
            Logger.debug(f"User role result: {user_role_result}")
            enriched_context["discovery"]["user_role"] = user_role_result

            Logger.info(f"Calling get_user_ip_details for intcid: {intcid}, aid: {aid}")
            ip_details_result = await get_user_ip_details(intcid, alert_context, task)
            Logger.debug(f"IP details result: {ip_details_result}")
            enriched_context["discovery"]["ip_details"] = ip_details_result

            Logger.info(f"Calling get_ip_reputation_details for intcid: {intcid}, aid: {aid}")
            ip_reputation_result = await sentinel_utils.get_ip_reputation_details(intcid, enriched_context, task)
            Logger.debug(f"IP reputation result: {ip_reputation_result}")
            enriched_context["discovery"]["ip_reputation"] = ip_reputation_result

            Logger.info("Discovery field populated successfully")
        except Exception as e:
            Logger.error(f"Error populating discovery field: {str(e)}")
            Logger.error(traceback.format_exc())

        try:
            transformation_result = sentinel_utils.transform_discovery_to_extracted_fields(
                enriched_context.get("discovery", {})
            )
            
            discovery_fields = transformation_result.get("extracted_fields", {})
            should_remove_discovery = transformation_result.get("remove_discovery", False)
            
            if discovery_fields:
                # Merge discovery fields into existing extracted_fields
                if "extracted_fields" not in enriched_context:
                    enriched_context["extracted_fields"] = {}
                
                enriched_context["extracted_fields"].update(discovery_fields)
                Logger.info(f"Successfully merged {len(discovery_fields)} discovery fields into extracted_fields")
                Logger.debug(f"Added discovery field keys: {list(discovery_fields.keys())}")
                
                # Remove discovery dictionary if transformation was successful and flag is set
                if should_remove_discovery and "discovery" in enriched_context:
                    del enriched_context["discovery"]
                    Logger.info("Removed discovery dictionary from enriched context after successful transformation")
            else:
                Logger.info("No discovery fields to add to extracted_fields")
                
        except Exception as e:
            Logger.error(traceback.format_exc())
            # Continue processing even if transformation fails

        Logger.info("Alert context enrichment completed")
        Logger.info(f"Final enriched alert context for intcid: {intcid}, aid: {aid}: {enriched_context}")

        return enriched_context

    except ImportError as e:
        Logger.error(f"Failed to import utility functions: {str(e)}")
        return alert_context
    except Exception as e:
        Logger.error(f"[enrich_alert_context] Error: {str(e)}")
        Logger.error(traceback.format_exc())
        return alert_context
