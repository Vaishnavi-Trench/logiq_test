"""OpenSearch Utils"""

import re
import time
import json
from opensearchpy import OpenSearch, RequestsHttpConnection

from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX, RedisManager


def get_all_indices(intcid):
    """get all indices"""
    try:
        Logger.info(f"Requesting indices using OpenSearch client")
        client = connect_to_opensearch(intcid)
        # Get indices using the cat API
        try:
            if client is None:
                Logger.error("OpenSearch client is not initialized")
                return False, "Failed to connect to OpenSearch"

            indices_data = client.cat.indices(index="*", format="json")
        except Exception as e:
            if "404" in str(e):
                Logger.warn(f"Endpoint not found (404): _cat/indices")
                return (
                    False,
                    "Endpoint not found (404). Check if the URL is correct or if the indices endpoint exists.",
                )
            raise e

        Logger.debug(f"Response: {indices_data}")

        # Extract just the index names from the full response
        indices = [
            idx["index"]
            for idx in indices_data
            if isinstance(idx, dict) and "index" in idx
        ]

        Logger.info(f"Retrieved {len(indices)} indices")

        # Process indices to convert date-based patterns to wildcards
        processed_indices = []
        date_pattern1 = re.compile(
            r"(.+)-(\d{4})\.(\d{2})\.(\d{2})$"
        )  # matches pattern-YYYY.MM.DD
        date_pattern2 = re.compile(
            r"(.+)-(\d{4})-(\d{2})-(\d{2})$"
        )  # matches pattern-YYYY-MM-DD
        # New pattern for indices with date and suffix like YYYY.MM.DD-000002
        date_pattern3 = re.compile(
            r"(.+)-(\d{4})\.(\d{2})\.(\d{2})-\w+"
        )  # matches pattern-YYYY.MM.DD-suffix
        # New pattern for year and week format
        date_pattern4 = re.compile(
            r"(.+)-(\d{4})\.(\d{2})w"
        )  # matches pattern-YYYY.WWw (week format)
        # New pattern for year, month, day with hyphen separator and suffix
        date_pattern5 = re.compile(
            r"(.+)-(\d{4})-(\d{2})-(\d{2})-\w+"
        )  # matches pattern-YYYY-MM-DD-suffix

        for idx in indices:
            # Check for date patterns
            match1 = date_pattern1.match(idx)
            match2 = date_pattern2.match(idx)
            match3 = date_pattern3.match(idx)
            match4 = date_pattern4.match(idx)
            match5 = date_pattern5.match(idx)

            if match1 or match2 or match3 or match4 or match5:
                # Get the base name from whichever pattern matched
                base_name = None
                matched_pattern = None

                if match1:
                    base_name = match1.group(1)
                    matched_pattern = "YYYY.MM.DD"
                elif match2:
                    base_name = match2.group(1)
                    matched_pattern = "YYYY-MM-DD"
                elif match3:
                    base_name = match3.group(1)
                    matched_pattern = "YYYY.MM.DD-suffix"
                elif match4:
                    base_name = match4.group(1)
                    matched_pattern = "YYYY.WWw"
                elif match5:
                    base_name = match5.group(1)
                    matched_pattern = "YYYY-MM-DD-suffix"

                wildcard_name = f"{base_name}-*"
                processed_indices.append(wildcard_name)
                Logger.info(
                    f"Converted date-based index '{idx}' ({matched_pattern}) to wildcard pattern '{wildcard_name}'"
                )
            else:
                # Keep original name if no date pattern
                processed_indices.append(idx)

        # Remove duplicates that may have resulted from wildcard conversion
        processed_indices = list(set(processed_indices))

        Logger.info(
            f"After date pattern processing: {len(processed_indices)} unique indices/patterns"
        )

        # Count system indices (starting with .)
        system_indices = [idx for idx in processed_indices if idx.startswith(".")]
        Logger.info(
            f"Found {len(system_indices)} system indices (starting with .) that will be skipped for field extraction"
        )

        # Filter out system indices (starting with .)
        filtered_indices = [idx for idx in processed_indices if not idx.startswith(".")]
        Logger.info(
            f"After filtering system indices: {len(filtered_indices)} indices remain"
        )

        # Debug: Print first few index names
        if filtered_indices and len(filtered_indices) > 0:
            sample_indices = (
                filtered_indices[:3] if len(filtered_indices) >= 3 else filtered_indices
            )
            Logger.info(f"Sample index names after filtering: {sample_indices}")

        return True, filtered_indices

    except Exception as e:
        Logger.error(f"Error retrieving indices: {e}")
        return False, str(e)


def flatten_json(nested_json, prefix=""):
    """
    Flatten a nested JSON by concatenating nested keys with dots.
    """
    flattened_fields = []

    for key, value in nested_json.items():
        new_key = f"{prefix}.{key}" if prefix else key

        # If it's a nested object, recurse
        if isinstance(value, dict) and "properties" in value:
            # This is for OpenSearch mapping format
            flattened_fields.extend(flatten_json(value["properties"], new_key))
        elif isinstance(value, dict) and "type" in value:
            # This is a field with its type definition
            flattened_fields.append(new_key)
        elif isinstance(value, dict):
            # This is a nested field
            flattened_fields.extend(flatten_json(value, new_key))

    return flattened_fields


def get_available_fields(intcid, index_name):
    """get fields for index using OpenSearch mappings"""
    try:
        Logger.info(f"Requesting mapping for index: {index_name}")

        # Use the OpenSearch client instead of direct HTTP requests
        client = connect_to_opensearch(intcid)
        if client is None:
            Logger.error("OpenSearch client is not initialized")
            return False, "Failed to connect to OpenSearch"

        try:
            # Get mappings using the OpenSearch client
            mappings = client.indices.get_mapping(index=index_name)
            Logger.info(f"Retrieved mappings for index: {index_name}")
        except Exception as e:
            if "404" in str(e):
                Logger.warn(f"Index not found (404): {index_name}")
                return (
                    False,
                    f"Index '{index_name}' not found (404). Skipping to next index.",
                )
            raise e

        # Check if we're dealing with a wildcard pattern (multiple indices in response)
        if len(mappings) > 1 and "*" in index_name:
            Logger.info(
                f"Wildcard pattern detected: {index_name} matched {len(mappings)} indices"
            )

            # Extract date from index names to find most recent
            # Support all the same patterns as in get_all_indices
            date_pattern1 = re.compile(r"(.+)-(\d{4})\.(\d{2})\.(\d{2})$")  # YYYY.MM.DD
            date_pattern2 = re.compile(r"(.+)-(\d{4})-(\d{2})-(\d{2})$")  # YYYY-MM-DD
            date_pattern3 = re.compile(
                r"(.+)-(\d{4})\.(\d{2})\.(\d{2})-\w+"
            )  # YYYY.MM.DD-suffix
            date_pattern4 = re.compile(
                r"(.+)-(\d{4})\.(\d{2})w$"
            )  # YYYY.WWw (week format)
            date_pattern5 = re.compile(
                r"(.+)-(\d{4})-(\d{2})-(\d{2})-\w+"
            )  # YYYY-MM-DD-suffix

            dated_indices = []
            for idx in mappings.keys():
                match1 = date_pattern1.match(idx)
                match2 = date_pattern2.match(idx)
                match3 = date_pattern3.match(idx)
                match4 = date_pattern4.match(idx)
                match5 = date_pattern5.match(idx)

                if match1:
                    year, month, day = (
                        int(match1.group(2)),
                        int(match1.group(3)),
                        int(match1.group(4)),
                    )
                    dated_indices.append((idx, (year, month, day)))
                elif match2:
                    year, month, day = (
                        int(match2.group(2)),
                        int(match2.group(3)),
                        int(match2.group(4)),
                    )
                    dated_indices.append((idx, (year, month, day)))
                elif match3:
                    year, month, day = (
                        int(match3.group(2)),
                        int(match3.group(3)),
                        int(match3.group(4)),
                    )
                    dated_indices.append((idx, (year, month, day)))
                elif match4:
                    year, week = int(match4.group(2)), int(match4.group(3))
                    # Use week number as day to sort approximately (not exact but good enough for sorting)
                    dated_indices.append((idx, (year, 1, week * 7)))
                elif match5:
                    year, month, day = (
                        int(match5.group(2)),
                        int(match5.group(3)),
                        int(match5.group(4)),
                    )
                    dated_indices.append((idx, (year, month, day)))

            if dated_indices:
                # Sort by date (year, month, day) in descending order (newest first)
                dated_indices.sort(key=lambda x: x[1], reverse=True)
                newest_index = dated_indices[0][0]
                Logger.info(
                    f"Selected newest index: {newest_index} from wildcard pattern"
                )

                # Keep only the newest index in mappings
                newest_mapping = {newest_index: mappings[newest_index]}
                mappings = newest_mapping
            else:
                # If no dates found, take the first index alphabetically as fallback
                sorted_indices = sorted(list(mappings.keys()))
                first_index = sorted_indices[0]
                Logger.info(
                    f"No dates found in indices, using first index: {first_index}"
                )
                mappings = {first_index: mappings[first_index]}

        fields = []
        # Process each index in the response
        for index, index_data in mappings.items():
            Logger.info(f"Processing mappings for index key: {index}")
            if "mappings" in index_data and "properties" in index_data["mappings"]:
                # Extract and flatten fields from the mappings
                Logger.info(f"Found properties in mappings for index: {index}")
                index_fields = flatten_json(index_data["mappings"]["properties"])
                fields.extend(index_fields)
            else:
                Logger.warn(f"No properties found in mappings for index: {index}")

        # Remove duplicates
        fields = list(set(fields))
        Logger.debug(f"Fields extracted for index: {index_name}")
        Logger.info(
            f"Extracted {len(fields)} fields for index: {index_name}: fields: {fields}"
        )

        return True, fields

    except Exception as e:
        Logger.error(f"Error extracting fields for index '{index_name}': {e}")
        return False, str(e)


def get_single_matching_record(intcid, index_name, query):
    Logger.info(
        f"get_single_matching_record for intcid: {intcid}, index: {index_name}, query: {query}"
    )
    client = connect_to_opensearch(intcid)
    if client:
        try:
            # Try to parse query string as JSON
            try:
                query_body = json.loads(query)
            except json.JSONDecodeError:
                # If not valid JSON, treat as a query string
                query_body = {"query": {"query_string": {"query": query}}}

            # Explicitly set size to 1 to ensure only one record is returned
            query_body["size"] = 1

            # Execute the search directly
            response = client.search(body=query_body, index=index_name)

            # Format results
            result = {}
            result["matching_record"] = (
                response["hits"]["hits"][0]["_source"]
                if response["hits"]["hits"]
                else {}
            )

            Logger.info(f"OpenSearch query executed for intcid: {intcid}")
            return result
        except Exception as e:
            Logger.error(f"Error executing OpenSearch query: {e}")
            return {"error": str(e)}


def get_matching_records(intcid, index_name, query):
    Logger.info(
        f"get_matching_records for intcid: {intcid}, index: {index_name}, query: {query}"
    )
    client = connect_to_opensearch(intcid)
    if client:
        try:
            # Try to parse query string as JSON
            try:
                query_body = json.loads(query)
            except json.JSONDecodeError:
                # If not valid JSON, treat as a query string
                query_body = {"query": {"query_string": {"query": query}}}

            # Explicitly set size to 5 to return up to 5 records
            query_body["size"] = 5

            # Execute the search directly
            response = client.search(body=query_body, index=index_name)

            # Format results
            result = {}
            matching_records = []
            if response["hits"]["hits"]:
                for hit in response["hits"]["hits"]:
                    matching_records.append(hit["_source"])

            result["matching_records"] = matching_records

            Logger.info(
                f"OpenSearch query executed for intcid: {intcid}, found {len(matching_records)} records"
            )
            return result
        except Exception as e:
            Logger.error(f"Error executing OpenSearch query: {e}")
            return {"error": str(e)}


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
            index_name = index_entry.get("index")
            description = index_entry.get("desc", "No description available")

            result_string += f"Index Name: {index_name}\n"
            result_string += f"Description: {description}\n"
            result_string += "-" * 30 + "\n"
    else:
        result_string = "No document found matching the index list query.\n"
    Logger.info(f"Indices metadata fetched for intcid: {intcid}")
    return result_string


def get_single_event_from_alert(intcid, alert_id):
    Logger.info(
        f"Fetching single event from alert for intcid: {intcid}, alert_id: {alert_id}"
    )


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

    result_string += f"Index Name: {index_name}\n"
    result_string += f"Description: {description}\n"

    metadata_found = False
    fields = field_list_document.get("fields", [])
    if fields:
        metadata_found = True
        for field_entry in fields:
            field_name = field_entry.get("field", "Unknown")
            field_desc = field_entry.get("desc", "No description available")
            result_string += f"  Field: {field_name}\n"
            result_string += f"  Description: {field_desc}\n"
            result_string += "\n"

    if not metadata_found:
        result_string += "  No metadata available for this index.\n"

    result_string += "\n"
    Logger.info(f"Returning metadata")
    return result_string


def connect_to_opensearch(intcid):
    Logger.info(f"Connecting to OpenSearch for intcid: {intcid}")

    opensearch_data_query = {
        "intcid": intcid,
        "vendor": "wazuh",
        "type": "siem",
        "recordType": "investigation",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, opensearch_data_query
    )

    opensearch_host = document.get("url")
    pattern = r"https?://([^/:]+):(\d+)"
    match = re.search(pattern, opensearch_host)
    if match:
        opensearch_host = match.group(1)
        opensearch_port = int(match.group(2))
    else:
        Logger.error("No valid OpenSearch URL found")
        return None

    opensearch_username = document.get("username")
    opensearch_pass = document.get("password")

    try:
        # Basic authentication configuration
        client = OpenSearch(
            hosts=[{"host": opensearch_host, "port": opensearch_port}],
            http_auth=(opensearch_username, opensearch_pass),
            use_ssl=True,
            verify_certs=False,
            connection_class=RequestsHttpConnection,
        )
        Logger.info(f"Connected to OpenSearch for intcid: {intcid}")
        return client
    except Exception as e:
        Logger.error(f"Error connecting to OpenSearch: {e}")
        return None


def create_search_job(client, search_query):
    Logger.info(f"Creating search job for query: {search_query}")
    try:
        # In OpenSearch, searches are executed directly rather than creating a job
        # We'll store the query for execution in the next step
        return {"query": search_query, "job_id": str(time.time())}
    except Exception as e:
        Logger.error(f"Error creating search job: {e}")
        return None


def check_job_status(job):
    # OpenSearch queries are synchronous, so we'll just return True
    Logger.info(f"Job ready for execution with ID: {job['job_id']}")
    return True


def get_search_results(client, job):
    Logger.info(f"Executing search for job ID: {job['job_id']}")
    try:
        # Parse the query to get index and query body
        query_parts = job["query"].strip().split(" ", 1)
        if len(query_parts) < 2 or not query_parts[0].startswith("index="):
            Logger.error("Invalid query format. Expected: index=<index_name> <query>")
            return []

        index_name = query_parts[0].replace("index=", "").strip()
        query_string = query_parts[1]

        # Create a simple query_string query
        query_body = {"query": {"query_string": {"query": query_string}}}

        # Execute the search
        response = client.search(body=query_body, index=index_name)

        # Format results similar to Splunk's output
        result_list = []
        for hit in response["hits"]["hits"]:
            result = hit["_source"]
            result["_id"] = hit["_id"]
            result_list.append(result)

        Logger.info(f"Search results fetched for job ID: {job['job_id']}")
        return result_list
    except Exception as e:
        Logger.error(f"Error fetching search results: {e}")
        return []


def validate_query_syntax(index_name, query, intcid):
    Logger.info(f"Validating OpenSearch query syntax for intcid: {intcid}: {query}")
    try:
        client = connect_to_opensearch(intcid)
        if not client:
            return False

        # Create a validate query
        query_body = {"query": {"query_string": {"query": query}}}

        # Use the validate API endpoint
        try:
            client.indices.validate_query(body=query_body, index=index_name)
            Logger.info(
                f"OpenSearch query syntax validation completed for intcid: {intcid}"
            )
            return True
        except Exception as validation_error:
            Logger.error(f"Query validation failed: {validation_error}")
            return False

    except Exception as e:
        Logger.info(f"Error validating OpenSearch query: {e}")
        return False


def execute_wazuh_query(intcid, index_name, query):
    Logger.info(
        f"Executing OpenSearch query for intcid: {intcid}, index: {index_name}, query: {query}"
    )
    client = connect_to_opensearch(intcid)
    if client:
        query_body = None  # Initialize query_body
        try:
            # Try to parse query string as JSON
            try:
                query_body = json.loads(query)
            except json.JSONDecodeError:
                # If not valid JSON, treat as a query string
                query_body = {"query": {"query_string": {"query": query}}}

            # Execute the search directly
            response = client.search(body=query_body, index=index_name)

            # Format results
            result = {}
            result["total_matches_found"] = (
                response["hits"]["total"]["value"]
                if response["hits"]["total"]["value"] > 0
                else "No matches found"
            )
            result["sample_matching_record"] = (
                response["hits"]["hits"][0]["_source"]
                if response["hits"]["hits"]
                else {}
            )
            result["aggregation_data"] = (
                response["aggregations"] if "aggregations" in response else {}
            )
            Logger.info(f"OpenSearch query executed for intcid: {intcid}")
            return result
        except Exception as e:
            Logger.error(f"Error executing OpenSearch query: {e} with query body: {query_body}")
            return {"error": str(e)}


def validate_wazuh_query(index_name, query, intcid):
    return validate_query_syntax(index_name, query, intcid)


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


def push_template_data_to_mongo(
    intcid,
    vendor,
    env,
    tid,
    question_id,
    requirement,
    task,
    index_name,
    opensearch_query_template,
    opensearch_query,
):
    filter = {
        "type": "query_template",
        "intcid": intcid,
        "vendor": vendor,
        "tid": tid,
        "questions_id": question_id,
        "env": env,
    }

    document = {
        "type": "query_template",
        "triage_question": requirement,
        "task": task,
        "intcid": intcid,
        "vendor": vendor,
        "tid": tid,
        "question_id": question_id,
        "index_name": index_name,
        "env": env,
        "query_template": opensearch_query_template,
        "query": opensearch_query,
    }
    main_db = PropX.get_property("module.integration.config.db")
    query_template_collection = PropX.get_property(
        "module.query.template.cache.collection"
    )
    MongoDBManager.upsert_record(main_db, query_template_collection, filter, document)


def push_index_name_to_mongo(
    intcid, vendor, env, tid, question_id, requirement, index_name
):
    filter = {
        "type": "index_name",
        "intcid": intcid,
        "vendor": vendor,
        "tid": tid,
        "questions_id": question_id,
        "env": env,
    }

    document = {
        "type": "index_name",
        "step_question": requirement,
        "intcid": intcid,
        "vendor": vendor,
        "tid": tid,
        "index_name": index_name,
    }
    main_db = PropX.get_property("module.integration.config.db")
    query_template_collection = PropX.get_property(
        "module.query.template.cache.collection"
    )
    MongoDBManager.upsert_record(main_db, query_template_collection, filter, document)
