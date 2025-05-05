from pymongo import MongoClient

from ..logger2 import Logger2 as Logger
from ..propx import PropX


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class MongoDBManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

        # Main DB related
        self.main_client = None
        self.main_db = None

        # Data DB related
        self.data_client = None
        self.data_db = None

    @staticmethod
    def get_instance():
        if MongoDBManager.__instance is None:
            MongoDBManager.__instance = MongoDBManager()

        return MongoDBManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    def set_main_client(self, main_client):
        self.main_client = main_client

    def get_main_client(self):
        return self.main_client

    def set_data_client(self, data_client):
        self.data_client = data_client

    def get_data_client(self):
        return self.data_client

    def set_main_db(self, main_db):
        self.main_db = main_db

    def get_main_db(self):
        return self.main_db

    def set_data_db(self, data_db):
        self.data_db = data_db

    def get_data_db(self):
        return self.data_db

    @staticmethod
    def initialize():
        try:
            # Get MongoDB connection parameters from configuration
            main_url = PropX.get_property("mongodb.main.url")
            main_db_name = PropX.get_property("mongodb.main.database")
            data_url = PropX.get_property("mongodb.data.url")
            data_db_name = PropX.get_property("mongodb.data.database")

            # Initialize main DB
            if not main_url:
                Logger.error("mongodb.main.url is not set in configuration")
                return

            if not main_db_name:
                Logger.error("mongodb.main.database is not set in configuration")
                return

            try:
                main_client = MongoClient(main_url)
                # Test the connection
                main_client.server_info()
                MongoDBManager.get_instance().set_main_client(main_client)
                main_database = main_client[main_db_name]
                MongoDBManager.get_instance().set_main_db(main_database)
                Logger.info(f"Connected to main MongoDB: {main_db_name}")
            except Exception as e:
                Logger.error(f"Error connecting to main MongoDB: {str(e)}")
        except Exception as e:
            Logger.error(f"Error initializing MongoDB connections: {str(e)}")

    @staticmethod
    def get_db_by_name(db_name):
        instance = MongoDBManager.get_instance()
        if db_name == "main_db":
            if instance.get_main_db() is None:
                Logger.warn("Attempted to use main_db but it's not initialized")
                return {}  # Return empty dict to avoid errors
            return instance.get_main_db()
        elif db_name == "data_db":
            if instance.get_data_db() is None:
                Logger.warn("Attempted to use data_db but it's not initialized")
                return {}  # Return empty dict to avoid errors
            return instance.get_data_db()
        else:
            Logger.error(f"Unsupported db_name: {db_name}")
            return {}  # Return empty dict to avoid errors

    # custom methods, send collection name and db_name
    @staticmethod
    def get_record_by_field(db, collection_name, field, value):
        database = MongoDBManager.get_db_by_name(db)
        try:
            collection = database[collection_name]
            return collection.find_one({field: value})
        except Exception as e:
            Logger.error(
                f"Error in get_record_by_field: {e} (db={db}, collection={collection_name})"
            )
            return None

    @staticmethod
    def get_record_by_multiple_fields(db, collection_name, filters):
        database = MongoDBManager.get_db_by_name(db)
        try:
            collection = database[collection_name]
            return collection.find_one(filters)
        except Exception as e:
            Logger.error(
                f"Error in get_record_by_multiple_fields: {e} (db={db}, collection={collection_name}, filters={filters})"
            )
            return None

    @staticmethod
    def get_all_records(db, collection_name, filters):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        return collection.find(filters) if collection is not None else None

    @staticmethod
    def delete_record_by_field(db, collection_name, field, value):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        return collection.delete_one({field: value}) if collection is not None else None

    @staticmethod
    def update_record_by_field(db, collection_name, field, value, update_data):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]

        # If update_data already contains MongoDB operators ($set, $unset, etc.), use it directly
        if any(key.startswith("$") for key in update_data.keys()):
            return (
                collection.update_one({field: value}, update_data)
                if collection is not None
                else None
            )
        else:
            # If no operators present, wrap the update data in $set
            return (
                collection.update_one({field: value}, {"$set": update_data})
                if collection is not None
                else None
            )

    @staticmethod
    def bulk_update_records(db, collection_name, operations):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        return collection.bulk_write(operations) if collection is not None else None

    @staticmethod
    def insert_record(db, collection_name, document):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        if collection is None:
            return None
        result = collection.insert_one(document)
        return result.inserted_id

    @staticmethod
    def upsert_record(db, collection_name, filter, update_data):
        database = MongoDBManager.get_db_by_name(db)
        try:
            collection = database[collection_name]
            if collection is None:
                return None

            # If update_data already contains MongoDB operators ($set, $unset, etc.), use it directly
            if any(key.startswith("$") for key in update_data.keys()):
                result = collection.update_one(filter, update_data, upsert=True)
            else:
                # If no operators present, wrap the update data in $set
                result = collection.update_one(
                    filter, {"$set": update_data}, upsert=True
                )

            # Return upserted_id if a new document was created, otherwise return modified_count
            if result.upserted_id:
                return result.upserted_id
            else:
                return result.modified_count
        except Exception as e:
            Logger.error(
                f"Error in upsert_record: {e} (db={db}, collection={collection_name}, filter={filter})"
            )
            return None

    @staticmethod
    def count_records_in_collection(db, collection_name, filters={}):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        return collection.count_documents(filters) if collection is not None else None

    @staticmethod
    def delete_record_by_filter(db, collection_name, filter):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        return collection.delete_one(filter) if collection is not None else None

    @staticmethod
    def update_record_by_filter(db, collection_name, filter, update_data):
        database = MongoDBManager.get_db_by_name(db)
        collection = database[collection_name]
        # Don't wrap in $set if update_data already contains operators
        if any(key.startswith("$") for key in update_data.keys()):
            return (
                collection.update_one(filter, update_data)
                if collection is not None
                else None
            )
        return (
            collection.update_one(filter, {"$set": update_data})
            if collection is not None
            else None
        )
