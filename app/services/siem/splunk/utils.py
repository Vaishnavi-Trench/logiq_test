"""Splunk Utils"""

import re
import time
import xml.etree.ElementTree as ET

import splunklib.client as client
import splunklib.results as results

from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX, RedisManager


def get_indices_with_metadata(intcid):
    Logger.info(f"Fetching indices with metadata for intcid: {intcid}")
    index_list_query = {"intcid": intcid, "subtype": "index_list"}

    metadata_db = PropX.get_property("module.integration.config.db")
    metadata_collection = PropX.get_property("module.integration.metadata.collection")
    index_list_document = MongoDBManager.get_record_by_multiple_fields(
        metadata_db, metadata_collection, index_list_query
    )
    Logger.debug(f"Index List Document: {index_list_document}")

    result_string = ""
    if index_list_document:
        indices = index_list_document.get("indices", [])

        for index_entry in indices:
            index_name_full = index_entry.get("index")
            description = index_entry.get("desc", "No description available")

            index_name_list = index_name_full.split("|")
            index_name = index_name_list[0]
            source_type = None if index_name_list[1] == "*" else index_name_list[1]

            result_string += f"Index Name: {index_name}\n"
            result_string += f"Source Type: {source_type}\n"
            result_string += f"Description: {description}\n"
            result_string += "-" * 30 + "\n"
    else:
        result_string = "No document found matching the index list query.\n"
    Logger.info(f"Indices metadata fetched for intcid: {intcid}")
    Logger.info(f"Result: {result_string}")
    return result_string


def get_fields_with_metadata(intcid, index_name) -> str:
    Logger.info(f"Fetching fields with metadata for index: {index_name}")
    fields_list_query = {
        "intcid": intcid,
        "subtype": "field_list",
        "index_name": index_name,
    }
    Logger.debug(f"Field list query: {fields_list_query}")
    result_string = ""

    metadata_db = PropX.get_property("module.integration.config.db")
    metadata_collection = PropX.get_property("module.integration.metadata.collection")
    field_list_document = MongoDBManager.get_record_by_multiple_fields(
        metadata_db, metadata_collection, fields_list_query
    )
    if field_list_document is None:
        Logger.error(f"Field Metadata is not Found")
        return []
    description = field_list_document.get("desc", "No description available")
    index_name_list = index_name.split("|")
    index_name = index_name_list[0]
    source_type = None if index_name_list[1] == "*" else index_name_list[1]

    result_string += f"Index Name: {index_name}\n"
    result_string += f"Source Type: {source_type}\n"
    result_string += f"Description: {description}\n"

    metadata_found = False
    fields = field_list_document.get("fields", [])
    field_name_list = []
    if fields:
        metadata_found = True
        for field_entry in fields:
            field_name = field_entry.get("field", "Unknown")
            field_name_list.append(field_name)
            field_desc = field_entry.get("desc", "No description available")
            result_string += f"  Field: {field_name}\n"
            result_string += f"  Description: {field_desc}\n"
            result_string += "\n"

    if not metadata_found:
        result_string += "  No metadata available for this index.\n"

    result_string += "\n"
    Logger.info(f"Returning metadata")
    return field_name_list


def connect_to_splunk(intcid):
    Logger.info(f"Connecting to Splunk for intcid: {intcid}")

    splunk_data_query = {
        "intcid": intcid,
        "vendor": "splunk",
        "type": "siem",
        "recordType": "investigation",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, splunk_data_query
    )

    splunk_host = document.get("url")
    pattern = r"https?://([^/:]+):(\d+)"
    match = re.search(pattern, splunk_host)
    if match:
        splunk_host = match.group(1)
        splunk_port = match.group(2)
    else:
        Logger.error("No valid Splunk URL found")
        return None
    splunk_username = document.get("username")
    splunk_pass = document.get("password")
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username=splunk_username,
            password=splunk_pass,
        )
        Logger.info(f"Connected to Splunk for intcid: {intcid}")
        return service
    except Exception as e:
        Logger.error(f"Error connecting to Splunk: {e}")
        return None


def create_search_job(service, search_query):
    Logger.info(f"Creating search job for query: {search_query}")
    try:
        job = service.jobs.create(search_query, output_mode="json")
        Logger.info(f"Search job created with SID: {job['sid']}")
        return job
    except Exception as e:
        Logger.error(f"Error creating search job: {e}")
        return None


def check_job_status(job):
    Logger.info(f"Checking job status for SID: {job['sid']}")
    try:
        while not job.is_done():
            time.sleep(2)
        Logger.info(f"Job completed for SID: {job['sid']}")
        return True
    except Exception as e:
        Logger.error(f"Error checking job status: {e}")
        return False


def get_search_results(job):
    Logger.info(f"Fetching search results for SID: {job['sid']}")
    try:
        results_stream = job.results(output_mode="json")
        results_reader = results.JSONResultsReader(results_stream)
        result_list = [result for result in results_reader if isinstance(result, dict)]
        Logger.info(f"Search results fetched for SID: {job['sid']}")
        return result_list
    except Exception as e:
        Logger.error(f"Error fetching search results: {e}")
        return []


def parse_spl_validation_response(response_xml):
    Logger.info("Parsing SPL validation response")
    root = ET.fromstring(response_xml)
    validation_results = {}

    error_msg = root.find(".//messages")
    if error_msg is not None:
        return {"error": error_msg.text.strip()}

    for key in root.findall(".//key"):
        name = key.get("name")
        value = key.text.strip() if key.text else None
        validation_results[name] = value

    Logger.info("SPL validation response parsed")
    return validation_results


def validate_query_syntax(query, intcid):
    Logger.info(f"Validating SPL query syntax for intcid: {intcid}")
    try:
        service = connect_to_splunk(intcid)
        response = service.get("/services/search/parser", q=query, parse_only=True)

        content = response.body.read().decode("utf-8")

        if "error" in content.lower() or "message" in content.lower():
            Logger.info("SPL query is invalid.")
            return False
        else:
            Logger.info(f"SPL query syntax validation completed for intcid: {intcid}")
            return True
    except Exception as e:
        Logger.info(f"Error validating SPL query: {e}")
        return False


def validate_query_fields(query, fields_list):
    Logger.info("Validating SPL query fields")
    query_fields = re.findall(r"(\b\w+\b)(?=\s*=)", query)
    Logger.debug(f"Query fields: {query_fields}")
    for field in query_fields:
        if field not in fields_list and field!="index":
            Logger.error(f"Field '{field}' not found in fields list.")
            return False
    Logger.info("SPL query fields validation completed")
    return True


def execute_splunk_query(query, intcid):
    Logger.info(f"Executing SPL query for intcid: {intcid}")
    service = connect_to_splunk(intcid)
    if service:
        search_query = query
        job = create_search_job(service, search_query)
        if job and check_job_status(job):
            results = get_search_results(job)
            Logger.info(f"SPL query executed for intcid: {intcid}")
            return results

def validate_splunk_query(query, intcid):
    isvalid = validate_query_syntax(query, intcid)
    # isvalid = validate_query_fields(query, field_name_list)
    return isvalid


def redis_connection():
    Logger.info("Connecting to Redis")
    redis_client = RedisManager.get_instance().get_redis_client()
    if redis_client.ping():
        Logger.info("Connected to Redis")
        return redis_client
    else:
        Logger.error("Failed to connect to Redis")
        return None


def sanitize_input_string(input_string: str) -> str:
    Logger.info("Sanitizing input string")
    sanitized_string = input_string.strip().lower()
    sanitized_string = re.sub(r"[^a-z0-9_]", "", sanitized_string)
    sanitized_string = sanitized_string.replace(" ", "_")
    Logger.info("Input string sanitized")
    return sanitized_string

def push_template_data_to_mongo(requirement, intcid, vendor, splunk_query_template, splunk_query):
    document ={
        "step_question" : requirement,
        "intcid" : intcid,
        "vendor" : vendor,
        "query_template" : splunk_query_template,
        "query": splunk_query
    }
    MongoDBManager.insert_record("main_db", "query_templates", document)