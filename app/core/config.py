from typing import Dict, Any, Optional
import os
import sys
from pydantic_settings import BaseSettings
from pltfrm import Logger2 as Logger
from pltfrm.propx.propx import PropX


class Settings(BaseSettings):
    # Default values used before PropX is initialized
    API_PORT: int = 8080
    API_HOST: str = "0.0.0.0"
    APP_NAME: str = "LogIQ API"
    MAIN_DB: str = "main_db"
    MAIN_COLLECTION: str = "integration"
    DATA_DB: str = "data_db"
    DATA_COLLECTION: str = "toolsmetadata"

    # Dictionary to store all properties
    all_props: Dict[str, Any] = {}

    def initialize_from_propx(self):
        """Initialize settings from PropX after it has been loaded"""
        try:
            # Get specific API settings
            self.API_PORT = PropX.get_property_int("module.api.port", self.API_PORT)
            self.API_HOST = PropX.get_property("module.api.host") or self.API_HOST
            self.APP_NAME = PropX.get_property("module.api.name") or self.APP_NAME

            self.MAIN_DB = (
                PropX.get_property("module.integration.config.db") or "main_db"
            )
            self.MAIN_COLLECTION = (
                PropX.get_property("module.integration.config.collection")
                or "integration"
            )
            self.DATA_DB = (
                PropX.get_property("module.integration.metadata.db") or "data_db"
            )
            self.DATA_COLLECTION = (
                PropX.get_property("module.integration.metadata.collection")
                or "toolsmetadata"
            )

            # Store all properties for general access
            self.all_props = PropX.get_all_props() or {}
            Logger.debug("config: Settings loaded from PropX configuration")
        except Exception as e:
            error_msg = f"Warning: Failed to load settings from PropX: {e}"
            Logger.error(f"config: {error_msg}")

    def get_property(self, key: str, default: Any = None) -> Any:
        """Get a property value by key"""
        try:
            value = PropX.get_property(key) or default
            return value
        except Exception as e:
            Logger.error(f"config: Could not get property '{key}': {e}")
            return default if key not in self.all_props else self.all_props[key]

    def get_property_int(self, key: str, default: int = 0) -> int:
        """Get an integer property value by key"""
        try:
            return PropX.get_property_int(key, default)
        except Exception as ex:
            Logger.error(f"config: Could not get property '{key}': {ex}")
            val = self.all_props.get(key, default)
            try:
                return int(val)
            except Exception as e:
                Logger.error(f"config: Could not convert property '{key}' to int: {e}")
                return default

    def get_property_float(self, key: str, default: float = 0.0) -> float:
        """Get a float property value by key"""
        try:
            return PropX.get_property_float(key, default)
        except Exception as e:
            Logger.error(f"config: Could not get property '{key}': {e}")
            val = self.all_props.get(key, default)
            try:
                return float(val)
            except Exception as ex:
                Logger.error(
                    f"config: Could not convert property '{key}' to float: {ex}"
                )
                return default

    def get_matching_props(self, prefix: str) -> Dict[str, Any]:
        """Get properties matching a prefix"""
        try:
            return PropX.get_matching_props(prefix)
        except Exception as ex:
            Logger.error(f"config: Could not get matching properties: {ex}")
            return {k: v for k, v in self.all_props.items() if k.startswith(prefix)}

    class Config:
        env_file = ".env"
        arbitrary_types_allowed = True


settings = Settings()
