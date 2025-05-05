import redis
from redis import StrictRedis
from ..propx import PropX
from ..logger2 import Logger2 as Logger
import pandas as pd
from openai import OpenAI
from redis.exceptions import ResponseError
import numpy as np
import json
import time
from redis.commands.search.field import TextField, TagField, VectorField
from redis.commands.search.indexDefinition import IndexDefinition, IndexType
import struct


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class RedisManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")
        self.redis_client = None

    @staticmethod
    def get_instance():
        if RedisManager.__instance is None:
            RedisManager.__instance = RedisManager()
        return RedisManager.__instance

    def set_redis_client(self, redis_client):
        self.redis_client = redis_client

    def get_redis_client(self):
        return self.redis_client

    @staticmethod
    def initialize():
        Logger.info("Initializing Redis client")
        redis_client = StrictRedis(
            host=PropX.get_property("redis.host"),
            port=int(PropX.get_property("redis.port")),
            password=PropX.get_property("redis.password"),
        )
        RedisManager.get_instance().set_redis_client(redis_client)
        Logger.info("Redis client initialized")

    @staticmethod
    def set_key(key, value, expiry=None):
        Logger.info(f"Setting key: {key} with expiry: {expiry}")
        result = (
            RedisManager.get_instance().get_redis_client().set(key, value, ex=expiry)
        )
        Logger.info(f"Key set result: {result}")
        return result

    @staticmethod
    def get_key(key):
        Logger.info(f"Getting key: {key}")
        value = RedisManager.get_instance().get_redis_client().get(key)
        if value is not None:
            value = value.decode("utf-8")
        Logger.info(f"Retrieved value: {value}")
        return value

    @staticmethod
    def delete_key(key):
        Logger.info(f"Deleting key: {key}")
        result = RedisManager.get_instance().get_redis_client().delete(key)
        Logger.info(f"Key delete result: {result}")
        return result

    @staticmethod
    def exists_key(key):
        Logger.info(f"Checking existence of key: {key}")
        result = RedisManager.get_instance().get_redis_client().exists(key)
        Logger.info(f"Key exists: {result}")
        return result

    @staticmethod
    def set_hash_key(hash_name, key, value):
        Logger.info(f"Setting hash key: {key} in hash: {hash_name}")
        result = (
            RedisManager.get_instance().get_redis_client().hset(hash_name, key, value)
        )
        Logger.info(f"Hash key set result: {result}")
        return result

    @staticmethod
    def get_hash_key(hash_name, key):
        Logger.info(f"Getting hash key: {key} from hash: {hash_name}")
        value = RedisManager.get_instance().get_redis_client().hget(hash_name, key)
        if value is not None:
            value = value.decode("utf-8")
        Logger.info(f"Retrieved hash key value: {value}")
        return value

    @staticmethod
    def get_all_hash(hash_name):
        Logger.info(f"Getting all keys from hash: {hash_name}")
        values = RedisManager.get_instance().get_redis_client().hgetall(hash_name)
        decoded_values = (
            {k.decode("utf-8"): v.decode("utf-8") for k, v in values.items()}
            if values
            else {}
        )
        Logger.info(f"Retrieved hash values: {decoded_values}")
        return decoded_values

    @staticmethod
    def delete_hash_key(hash_name, key):
        Logger.info(f"Deleting hash key: {key} from hash: {hash_name}")
        result = RedisManager.get_instance().get_redis_client().hdel(hash_name, key)
        Logger.info(f"Hash key delete result: {result}")
        return result

    @staticmethod
    def bulk_set_key(pairs):
        Logger.info(f"Bulk setting keys: {pairs}")
        result = RedisManager.get_instance().get_redis_client().mset(pairs)
        Logger.info(f"Bulk set result: {result}")
        return result

    @staticmethod
    def bulk_get_keys(keys):
        Logger.info(f"Bulk getting keys: {keys}")
        values = RedisManager.get_instance().get_redis_client().mget(keys)
        decoded_values = [v.decode("utf-8") if v is not None else None for v in values]
        Logger.info(f"Retrieved bulk values: {decoded_values}")
        return decoded_values

    @staticmethod
    def count_keys(pattern="*"):
        Logger.info(f"Counting keys with pattern: {pattern}")
        keys = RedisManager.get_instance().get_redis_client().keys(pattern)
        decoded_keys = [k.decode("utf-8") for k in keys]
        count = len(decoded_keys)
        Logger.info(f"Counted keys: {count}")
        return count

    @staticmethod
    def index_exists(key):
        Logger.info(f"Checking if index exists for key: {key}")
        exists = RedisManager.get_instance().get_redis_client().exists(key) > 0
        Logger.info(f"Index exists: {exists}")
        return exists
