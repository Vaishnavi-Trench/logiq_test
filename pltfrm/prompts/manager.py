import datetime
from datetime import timezone  # Add timezone import

from ..logger2 import Logger2 as Logger
from ..mongo import MongoDBManager
from ..propx import PropX


class Singleton(object):
    """singleton base class"""

    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class PromptManager(Singleton):
    """main openai manager class"""

    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

        self.module = None
        self.db = None
        self.collection = None
        self.history_collection = None
        self.history_id = None

    @staticmethod
    def get_instance():
        """get or create the singleton instance of AIManager"""
        if PromptManager.__instance is None:
            PromptManager.__instance = PromptManager()

        return PromptManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    def set_module(self, module):
        """set module"""
        self.module = module

    def get_module(self):
        """get module"""
        return self.module

    def set_db(self, db):
        """set openai client"""
        self.db = db

    def get_db(self):
        """get openai client"""
        return self.db

    def set_collection(self, collection):
        """set openai client"""
        self.collection = collection

    def get_collection(self):
        """get openai client"""
        return self.collection

    def set_history_collection(self, history_collection):
        self.history_collection = history_collection

    def get_history_collection(self):
        return self.history_collection

    def set_history_id(self, history_id):
        """set history id"""
        self.history_id = history_id

    def get_history_id(self):
        """get history id"""
        return self.history_id

    @staticmethod
    def initialize():
        """initialize the OpenAI client"""
        PromptManager.get_instance().set_module(PropX.get_property("promptmgr.module"))
        PromptManager.get_instance().set_db(PropX.get_property("promptmgr.db"))
        PromptManager.get_instance().set_collection(
            PropX.get_property("promptmgr.collection")
        )
        PromptManager.get_instance().set_history_collection(
            PropX.get_property("promptmgr.history.collection")
        )
        PromptManager.get_instance().set_history_id(
            PropX.get_property("promptmgr.history.id")
        )

    @staticmethod
    def get_prompt_template(intcid, name, version=None, is_debug=False):
        """run a prompt"""
        prompt_template_str = ""
        prompt_version = 0

        module = PromptManager.get_instance().get_module()
        Logger.info(f"Getting prompt template for name from global, name: {name}")
        prompt_template_record = MongoDBManager.get_record_by_multiple_fields(
            PromptManager.get_instance().get_db(),
            PromptManager.get_instance().get_collection(),
            {"intcid": intcid, "module": module, "name": name, "active": 1},
        )
        if not prompt_template_record:
            Logger.info(f"Getting prompt template for name from global, name: {name}")
            prompt_template_record = MongoDBManager.get_record_by_multiple_fields(
                PromptManager.get_instance().get_db(),
                PromptManager.get_instance().get_collection(),
                {"intcid": "1000", "module": module, "name": name, "active": 1},
            )

        if prompt_template_record:
            Logger.info(f"Prompt template found for: {name}")
            prompt_template = prompt_template_record.get("sections")
            prompt_version = prompt_template_record.get("version", 0)
            for section in prompt_template:
                # Format the title in uppercase followed by ":"
                title = section["title"].upper() + ":"
                prompt_template_str += title + "\n"

                # Add the body with its existing formatting
                prompt_template_str += section["body"] + "\n"

                # Add a newline between sections
                prompt_template_str += "\n"
        else:
            Logger.error(
                f"Prompt template record not found for intcid {intcid} and name {name}"
            )

        return prompt_template_str, prompt_version

    @staticmethod
    def save_prompt_history(
        intcid,
        template_name,
        template_version,
        model_name,
        system_prompt,
        user_prompt,
        response,
        model_class,
        history_params,
        usage_data,
        type=None,
    ):
        module = PromptManager.get_instance().get_module()
        Logger.info(f"Saving prompt history for intcid {intcid}")
        try:
            if usage_data:
                prompt_tokens = usage_data.prompt_tokens
                completion_tokens = usage_data.completion_tokens
                total_tokens = usage_data.total_tokens
            else:
                prompt_tokens = 0
                completion_tokens = 0
                total_tokens = 0

            history_record = {
                "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
                "intcid": intcid,
                "module": module,
                "prompt_template_name": template_name,
                "prompt_template_version": template_version,
                "model_name": model_name,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "response": response,
                "model_class": model_class.__name__ if model_class else None,
                "type": (
                    type if type else PromptManager.get_instance().get_history_id()
                ),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }

            # add all history params
            if history_params:
                history_record.update(history_params)

            MongoDBManager.insert_record(
                PromptManager.get_instance().get_db(),
                PromptManager.get_instance().get_history_collection(),
                history_record,
            )
        except Exception as e:
            Logger.error(f"Error saving prompt history: {e}")
            return

        Logger.info("Prompt history saved successfully.")
