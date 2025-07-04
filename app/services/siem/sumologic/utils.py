"""Sumologic Utils"""

from pltfrm import PropX, Logger2 as Logger, MongoDBManager, AIManager, ElasticsearchManager
from typing import List, Dict, Any
import traceback
from app.services.siem.sumologic.models import AlertContextEntities, ExtractedEntity


class SumoLogicUtils:
    """
    Utility class for SumoLogic operations.
    """
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
            Logger.error("[sumologic] Access key is not set for this integration.")
            raise ValueError("Access key is not set for this integration.")
        return self.access_key
    
    def get_access_id(self) -> str:
        """
        Get the SumoLogic access ID for the current integration.

        Returns:
            str: The access ID.
        """
        if not self.access_id:
            Logger.error("[sumologic] Access ID is not set for this integration.")
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
    
    def fetch_index_list(self, query: str) -> list:
        """
        Fetches the list of indices based on the provided query.
        
        Args:
            query (str): The query to filter indices.
        
        Returns:
            list: A list of indices matching the query.
        """
        try:
            response = MongoDBManager.get_record_by_multiple_fields(
                self.main_db,
                self.toolsmetadata,
                query
            )
            return response.get("indices", [])
        except Exception as e:
            Logger.error(f"[sumologic] Error fetching index list: {str(e)}")
            return []
    
    def get_top_matching_tables(self, intcid: str, tid: str) -> list:

        filter = {
            "intcid": intcid,
            "tid": tid,
        }
        try:
            doc = MongoDBManager.get_record_by_multiple_fields(
                self.main_db, self.trenchrecords_db, filter
            )
            if doc and "matching_tables" in doc:
                matching_tables = doc["matching_tables"]
                Logger.info(
                    f"[sumologic] Found matching tables for intcid: {intcid}, tid: {tid}: {matching_tables}"
                )
                return matching_tables
            else:
                Logger.info(
                    f"[sumologic] No matching tables found for intcid: {intcid}, tid: {tid}."
                )
                return []
        except Exception as e:
            Logger.error(
                f"[sumologic] Error retrieving matching tables for intcid: {intcid}, tid: {tid}: {e}"
            )
            return []
    
    def get_table_name_from_mongo(self, intcid, vendor, env, tid, question_id, step_id):
        filter = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "env": env,
        }

        main_db = self.main_db
        query_template_collection = PropX.get_property(
            "module.query.template.cache.collection"
        )
        record = MongoDBManager.get_record_by_multiple_fields(
            main_db, query_template_collection, filter
        )
        if record:
            index_name = record.get("index_name")
            if index_name:
                Logger.debug(
                    f"[sumologic] Found table name '{index_name}' for intcid: {intcid}, vendor: {vendor}, tid: {tid}, question_id: {question_id}, step_id: {step_id}."
                )
                return index_name
            else:
                Logger.warn(
                    f"[sumologic] No index name found in MongoDB record for intcid: {intcid}, vendor: {vendor}, tid: {tid}, question_id: {question_id}, step_id: {step_id}."
                )

        return None
    
    def parse_indices(self, indices_data: List[Dict[str, Any]]) -> str:

        Logger.debug(f"[sumologic] Parsing indices: {indices_data}")

        if not indices_data:
            return "No SIEM indices available"

        try:
            # Build the formatted string
            output = ["Available SIEM Indices:\n"]

            for idx, info in enumerate(indices_data, 1):
                index_name = info.get("index", "Unknown Index")
                description = info.get("desc", "No description available")

                # Add formatted index information
                output.append(f"{idx}. {index_name}")
                output.append(f"   Description: {description}")

            # Join all lines with newlines
            formatted_output = "\n".join(output)
            Logger.debug(f"[sumologic] Formatted indices output: {formatted_output}")

            return formatted_output
        except Exception as e:
            Logger.error(f"[sumologic] Error formatting indices: {e}")
            return "Error formatting SIEM indices"
    
    def push_table_name_to_mongo(
        self, intcid, vendor, env, tid, question_id, step_id, requirement, index_name
    ):
        filter = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "env": env,
        }

        document = {
            "type": "index_name",
            "intcid": intcid,
            "vendor": vendor,
            "env": env,
            "tid": tid,
            "question_id": question_id,
            "step_id": step_id,
            "step_question": requirement,
            "index_name": index_name,
        }
        main_db = self.main_db
        query_template_collection = PropX.get_property(
            "module.query.template.cache.collection"
        )
        MongoDBManager.upsert_record(
            main_db, query_template_collection, filter, document
        )
    
    def check_table(self, intcid: str, table_name:str) -> bool:
        """
        Checks if a Sumologic table exists in the MongoDB collection.

        Args:
            intcid (str): Integration/Customer ID for logging.
            table_name (str): The name of the Sumologic table to check.

        Returns:
            bool: True if the table exists, False otherwise.
        """
        Logger.info(f"[sumologic] Checking if table '{table_name}' exists for intcid: {intcid}")
        filter = {
            "intcid": intcid,
            "type": "siem",
            "vendor": "sumologic",
            "subtype": "index_list",
            "indices.index": table_name,
        }
        try:
            doc = MongoDBManager.get_record_by_multiple_fields(
                self.main_db, self.toolsmetadata, filter
            )
            exists = bool(doc and doc.get("indices"))
            Logger.info(f"[sumologic] Table '{table_name}' exists: {exists}")
            return exists
        except Exception as e:
            Logger.error(f"[sumologic] Error checking table existence: {e}")
            return False
    
    def get_sample_records(self, intcid: str, table: str):
        """
        Fetches sample records for a given integration and table (index).

        Args:
            intcid (str): Integration/Customer ID.
            table (str): The name of the table (index) to fetch sample records from.

        Returns:
            list: List of sample records for the specified table.
        """
        query = {
            "intcid": intcid,
            "vendor": "sumologic",
            "subtype": "index_list",
            "indices.index": table
        }
        try:
            doc = MongoDBManager.get_record_by_multiple_fields(
                self.main_db, self.toolsmetadata, query
            )
            if not doc or "indices" not in doc:
                Logger.info(f"[sumologic] No indices found for intcid: {intcid}, table: {table}")
                return []
            # Find the index entry matching the table name
            for idx in doc["indices"]:
                if idx.get("index") == table:
                    return idx.get("sample_logs", [])
            Logger.info(f"[sumologic] No sample logs found for table: {table}")
            return []
        except Exception as e:
            Logger.error(f"[sumologic] Error fetching sample records: {e}")
            return []

    def get_sumologic_template_data_from_mongo(
        self, 
        intcid: str,
        env: str,
        tid: str,
        question_id: str,
        step_id: str,
    ):
        try:
            # Define filter similar to Wazuh, mapping Sumologic concepts
            # Note: Wazuh filter used 'questions_id', using 'question_id' for consistency.
            # Added table_name and requirement to filter for better uniqueness than Wazuh example.
            filter_doc = {
                "type": "query_template",
                "intcid": intcid,
                "vendor": "sumologic",  # Use siem_type as vendor
                "tid": tid,
                "question_id": question_id,  # Corrected key name
                "step_id": step_id,  # Added for context
                "env": env,
            }

            # Get DB and Collection names from PropX configuration
            # Ensure these property keys exist in your configuration
            main_db = PropX.get_property("module.integration.config.db")
            query_template_collection = PropX.get_property(
                "module.query.template.cache.collection"
            )

            if not main_db or not query_template_collection:
                Logger.error(
                    "[sumologic] MongoDB database or collection name not configured in PropX (module.integration.config.db / module.query.template.cache.collection). Cannot get Sumologic Query data."
                )
                return None

            # Call the upsert method from MongoDBManager
            # Assumes MongoDBManager.upsert_record(db_name, collection_name, filter_dict, update_dict) signature
            record = MongoDBManager.get_record_by_multiple_fields(
                main_db, query_template_collection, filter_doc
            )
            if record:
                # Check if the collection has the expected structure
                if "query_template" in record:
                    Logger.debug(
                        f"[sumologic] Found Sumologic Query template data for '{intcid}/{tid}/{question_id}' in MongoDB."
                    )
                    return record["query_template"]
                else:
                    Logger.warn(
                        f"[sumologic] Sumologic Query template data for '{intcid}/{tid}/{question_id}' does not contain 'query_template' key. Returning None."
                    )
                    return None
        except Exception as e:
            Logger.error(
                f"[sumologic] Failed to push Sumologic Query template data to MongoDB for {intcid}/{tid}/{question_id}: {e}\n{traceback.format_exc()}"
            )
            return None
        
    def get_prompt_name(self, source: str, prompt_type: str) -> str:
        
        """
        Get the prompt name based on the source and prompt type.

        Args:
            source (str): The source of the alert.
            prompt_type (str): The type of prompt (e.g., 'alert_context').

        Returns:
            str: The name of the prompt.
        """
        # Define a mapping for sources to prompt names
        filter = {
            "intcid": self.intcid,
            "type": "prompt_mapping",
            "subtype": prompt_type,
        }
        source_prompt_map = MongoDBManager.get_record_by_multiple_fields(
            self.main_db, self.integration, filter
        )
        prompt_mapping = source_prompt_map.get("prompt_mapping", {})

        Logger.info(f"Prompt mapping for {prompt_type}: {prompt_mapping}")
        if prompt_mapping:
            # If the source exists in the mapping, return the corresponding prompt name
            if source in prompt_mapping:
                return prompt_mapping[source]
        # If the source is not found, return the default prompt
        prompt = prompt_mapping.get("default", "")
        Logger.info(f"Using default prompt: {prompt} for source: {source}")
        return prompt

    def extract_entities(self, alert_obj: dict) -> List[Dict[str, Any]]:
        """
        Extracts key entities from an alert object, handling both direct dict and embedded raw string formats.
        For every value matching a pattern, the actual key from the alert is used.
        """

        response = AIManager.run_prompt_with_structured_output(
            intcid=self.intcid,
            prompt_template_name="SUMOLOGIC_ALERT_CONTEXT_ANCHOR_EXTRACTION",
            prompt_params={
                "alert": alert_obj,
            },
            model_name=PropX.get_property("module.llm.model"),
            model_class=AlertContextEntities,
            history_params={
                "aid": alert_obj.get("aid", ""),
            },
            type="alert_context",
            system_prompt="You are an expert extracting useful entities from alerts. ",
        )
        Logger.info(f"Response from AIManager: {response}")
        if not response or not response["entities"]:
            Logger.warn("No entities extracted from the alert.")
            return []
        entities = []
        for entity in response["entities"]:
            if isinstance(entity, ExtractedEntity):
                entities.append({"type": entity.type, "value": entity.value})
            elif isinstance(entity, dict) and "type" in entity and "value" in entity:
                entities.append({"type": entity["type"], "value": entity["value"]})
            else:
                Logger.warn(f"Unexpected entity format: {entity}")
        
        return entities

    def retrieve_context_for_alert(self, entities: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Retrieve the context for a specific alert based on the extracted entities.

        Args:
            entities (List[Dict[str, str]]): The extracted entities from the alert.
            alert (dict): The original alert object.

        Returns:
            Dict[str, Any]: The context information for the alert.
        """
        retrieved_context = {}

        for entity in entities:
            entity_type = entity["type"]
            entity_value = entity["value"]

            if entity_type == "source":
                try:
                    query_embedding = AIManager.get_vector_embedding("azure-embeddings", entity_value)
                    if query_embedding:
                        docs = ElasticsearchManager.get_multiple_best_match_with_params(
                            index_name="rag_integration",
                            query_terms=[
                                {"intcid": self.intcid},
                                {"type": "index_name"},
                                {"vendor": "sumologic"}
                            ],
                            embedding=query_embedding,
                        )
                        # Remove 'embeddings' from each doc
                        for doc in docs:
                            doc.pop("embeddings", None)
                        retrieved_context["source"] = docs
                except (KeyError, ValueError, TypeError) as e:
                    print(f"Error retrieving source context for '{entity_value}': {e}")

            else:
                try:
                    query_embedding = AIManager.get_vector_embedding("azure-embeddings", entity_type)
                    if query_embedding:
                        docs = ElasticsearchManager.get_multiple_best_match_with_params(
                            index_name="rag_integration",
                            query_terms=[
                                {"intcid": self.intcid},
                                {"type": "index_fields"},
                                {"vendor": "sumologic"}
                            ],
                            embedding=query_embedding,
                        )
                        # Remove 'embeddings' from each doc
                        for doc in docs:
                            doc.pop("embeddings", None)
                        retrieved_context[entity_type] = docs
                except (KeyError, ValueError, TypeError) as e:
                    print(f"Error retrieving activity for '{entity_value}': {e}")
                    
        return retrieved_context




