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

        self.db = None
        self.collection = None

    @staticmethod
    def get_instance():
        """get or create the singleton instance of AIManager"""
        if PromptManager.__instance is None:
            PromptManager.__instance = PromptManager()

        return PromptManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

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

    @staticmethod
    def initialize():
        """initialize the OpenAI client"""
        PromptManager.get_instance().set_db(PropX.get_property("promptmgr.db"))
        PromptManager.get_instance().set_collection(
            PropX.get_property("promptmgr.collection")
        )

    @staticmethod
    def get_prompt_template(intcid, module, name):
        """run a prompt"""
        prompt_template_str = ""

        Logger.info(
            f"Getting prompt template for name from private {intcid}, name: {name}"
        )
        prompt_template_record = MongoDBManager.get_record_by_multiple_fields(
            PromptManager.get_instance().get_db(),
            PromptManager.get_instance().get_collection(),
            {"intcid": intcid, "module": module, "name": name, "active": 1}
        )
        if not prompt_template_record:
            Logger.info(f"Getting prompt template for name from global, name: {name}")
            prompt_template_record = MongoDBManager.get_record_by_multiple_fields(
                PromptManager.get_instance().get_db(),
                PromptManager.get_instance().get_collection(),
                {"intcid": "1000", "module": module, "name": name, "active": 1}
            )

        if prompt_template_record:
            Logger.info(f"Prompt template found for: {name}")
            prompt_template = prompt_template_record.get("sections")
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

        # Log the final string
        # Logger.info(f"Prompt template string: {prompt_template_str}")

        return prompt_template_str
