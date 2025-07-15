# app/services/intelligence/shodan/shodan_utils.py

# Standard library imports
import requests
import json
import datetime 
from typing import Dict, Any, Optional # Optional is no longer strictly needed but kept for consistency

# --- pltfrm imports (replace with your actual imports) ---
# from pltfrm import PropX, Logger2 as Logger, MongoDBManager 

# --- Dummy pltfrm implementations for testing (REMOVE IN PRODUCTION) ---
class Logger:
    @staticmethod
    def info(message):
        print(f"[INFO] {message}")
    @staticmethod
    def error(message):
        print(f"[ERROR] {message}")
    @staticmethod
    def warning(message):
        print(f"[WARNING] {message}")

class PropX:
    _properties = {}
    @staticmethod
    def set_property(key, value): PropX._properties[key] = value
    @staticmethod
    def get_property(key): return PropX._properties.get(key)

class MongoDBManager:
    _db = {} # Simple dict to simulate a database for testing
    @staticmethod
    def initialize():
        Logger.info("Dummy MongoDBManager initialized.")
        db_name = PropX.get_property("module.integration.config.db")
        collection_name = PropX.get_property("module.integration.config.collection")
        if not db_name or not collection_name:
            db_name = "dummy_integrations_db"
            collection_name = "configs"
        
        PropX.set_property("module.integration.config.db", db_name)
        PropX.set_property("module.integration.config.collection", collection_name)

        # Simulate initial data for intcid "1013" for Shodan
        # IMPORTANT: Replace "YOUR_SHODAN_API_KEY_HERE" if you want this to work via DB fetch
        MongoDBManager.set_record(
            db_name,
            collection_name,
            {"intcid": "1013", "vendor": "shodan", "type": "intelligence", "recordType": "investigation"},
            {
                "intcid": "1013",
                "toolId": "shodan-tool-id-example",
                "vendor": "shodan",
                "status": True,
                "recordType": "investigation",
                "desc": "Shodan intelligence integration config",
                "type": "intelligence",
                "createdBy": "System",
                "createdAt": datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z',
                "shodan_base_url": "https://api.shodan.io",
                "api_key": "YOUR_SHODAN_API_KEY_HERE", # <<< IMPORTANT: REPLACE THIS FOR DB POPULATION
                "updatedAt": datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z',
            }
        )
        Logger.info("Dummy Shodan config added to MongoDBManager for intcid 1013.")

    @staticmethod
    def set_record(db_name, collection_name, query, record):
        if db_name not in MongoDBManager._db: MongoDBManager._db[db_name] = {}
        if collection_name not in MongoDBManager._db[db_name]: MongoDBManager._db[db_name][collection_name] = []
        found = False
        for i, rec in enumerate(MongoDBManager._db[db_name][collection_name]):
            if all(rec.get(k) == v for k, v in query.items()):
                MongoDBManager._db[db_name][collection_name][i] = record
                found = True
                break
        if not found: MongoDBManager._db[db_name][collection_name].append(record)

    @staticmethod
    def get_record_by_multiple_fields(db_name, collection_name, query):
        if db_name in MongoDBManager._db and collection_name in MongoDBManager._db[db_name]:
            for record in MongoDBManager._db[db_name][collection_name]:
                if all(record.get(k) == v for k, v in query.items()):
                    return record
        return None
# --- End of Dummy pltfrm implementations ---


class ShodanUtils:
    """Utility class for Shodan operations."""

    def __init__(self, intcid: str):
        Logger.info(f"ShodanUtils: Initializing ShodanUtils for intcid {intcid}")
        self.intcid = intcid
        self.main_db = PropX.get_property("module.integration.config.db")
        self.integration_collection = PropX.get_property("module.integration.config.collection")
        
        # Ensure PropX and MongoDBManager are initialized for fetching
        try:
            if not PropX.get_property("module.integration.config.db"):
                PropX.set_property("module.integration.config.db", "dummy_integrations_db")
            if not PropX.get_property("module.integration.config.collection"):
                PropX.set_property("module.integration.config.collection", "configs")
            MongoDBManager.initialize() 
        except Exception as e:
            Logger.warning(f"ShodanUtils: PropX or MongoDBManager init issues: {e}. Cannot fetch config.")

        # --- Fetch Shodan Configuration from MongoDB ---
        config = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration_collection,
            {
                "intcid": self.intcid,
                "type": "intelligence", 
                "vendor": "shodan",
                "recordType": "investigation", 
            },
        )
        
        if not config:
            Logger.error(f"Shodan configuration not found in MongoDB for intcid: {self.intcid}")
            raise ValueError(f"Shodan configuration is missing for intcid: {self.intcid}.")

        self.api_key = config.get("api_key", "")
        self.shodan_base_url = config.get("shodan_base_url", "https://api.shodan.io")

        if not self.api_key:
            Logger.error(f"Shodan API key is missing in MongoDB configuration for intcid: {self.intcid}.")
            raise ValueError("Shodan configuration is incomplete (missing API key in DB).")
        
        # --- End of Configuration Fetching ---
        
        # --- Optional: Simulate storing Shodan API key in MongoDB for initial setup ---
        # This block is for initial setup/testing where you might not have the record yet.
        # It's good to keep this during development if you're not pre-populating DB manually.
        # Just ensure "YOUR_SHODAN_API_KEY_HERE" is replaced with a valid key for testing this part.
        if intcid: 
            try:
                MongoDBManager.set_record(
                    self.main_db,
                    self.integration_collection,
                    {
                        "intcid": self.intcid,
                        "type": "intelligence",
                        "vendor": "shodan",
                        "recordType": "investigation", 
                    },
                    {
                        "intcid": self.intcid, 
                        "toolId": "shodan-tool-id-example", 
                        "vendor": "shodan",
                        "status": True,
                        "recordType": "investigation", 
                        "desc": "Shodan intelligence integration config",
                        "type": "intelligence",
                        "createdBy": "System",
                        "createdAt": datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z',
                        "shodan_base_url": "https://api.shodan.io",
                        "api_key": "YOUR_SHODAN_API_KEY_HERE", # <<< IMPORTANT: REPLACE THIS FOR DB POPULATION
                        "updatedAt": datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z',
                    }
                )
                Logger.info(f"ShodanUtils: Config record simulated/upserted for intcid {self.intcid} with default key.")
            except Exception as e:
                Logger.warning(f"ShodanUtils: Could not simulate setting Shodan config record for {self.intcid}: {e}") 
        # --- End of Optional Simulation Block ---


    async def fetch_host_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Fetches detailed information for a specific IP address from Shodan and
        returns a highly flattened and concise report with only specified fields.
        """
        Logger.info(f"ShodanUtils: Fetching host info for IP: {ip_address}")
        
        url = f"{self.shodan_base_url}/shodan/host/{ip_address}"
        params = {"key": self.api_key}

        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            host_data = response.json()
            Logger.info(f"ShodanUtils: Host info fetched successfully for {ip_address}.")
            
            # --- Generating the EXACTLY specified flat report ---
            report = {
                "status": True,
                "description": f"Shodan host info fetched for {ip_address}",
                "ip_address": host_data.get('ip_str', 'N/A'),
                "organization": host_data.get('org', 'N/A'),
                "country": host_data.get('country_name', 'N/A'),
                "city": host_data.get('city', 'N/A'),
                "latitude": host_data.get('latitude', 'N/A'),
                "longitude": host_data.get('longitude', 'N/A'),
                "asn": host_data.get('asn', 'N/A'),
                "os": host_data.get('os', 'N/A'),
                "last_update": host_data.get('last_update', 'N/A'),
                # Flattening lists into comma-separated strings
                "open_ports_list": ", ".join(map(str, host_data.get('ports', []))) if host_data.get('ports') else "N/A",
                "hostnames_list": ", ".join(host_data.get('hostnames', [])) if host_data.get('hostnames') else "N/A",
                "domains_list": ", ".join(host_data.get('domains', [])) if host_data.get('domains') else "N/A",
                "total_vulnerabilities_detected": len(host_data.get('vulns', {})) 
            }
            
            return report 

        except requests.exceptions.HTTPError as http_err:
            Logger.error(f"ShodanUtils: HTTP error fetching host info for {ip_address}: {http_err}")
            try: error_details = response.json()
            except json.JSONDecodeError: error_details = {"message": response.text}
            return {
                "status": False,
                "description": f"Failed to fetch Shodan host info: {http_err}. Details: {json.dumps(error_details)}",
                "ip_address": ip_address 
            }
        except requests.exceptions.RequestException as err:
            Logger.error(f"ShodanUtils: Network or unexpected error fetching host info: {err}")
            return {
                "status": False,
                "description": f"An unexpected network error occurred: {str(err)}",
                "ip_address": ip_address 
            }

# --- The search_devices function has been REMOVED ---