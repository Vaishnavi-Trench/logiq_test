from pltfrm.mq.kafka_consumer import KafkaConsumer
from pltfrm.mq.kafka_producer import KafkaProducer
from pltfrm.mq.pubsub_consumer import PubSubConsumer
from pltfrm.mq.pubsub_producer import PubSubProducer

from ..propx import PropX
from ..logger2 import Logger2 as Logger

class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class MQManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

        self.consumer = None
        self.producer = None
        self.queue_type = PropX.get_property("mqlib.queue.type")

    @staticmethod
    def get_instance():
        if MQManager.__instance is None:
            MQManager.__instance = MQManager()

        return MQManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    def set_consumer(self, consumer):
        self.consumer = consumer

    def get_consumer(self):
        return self.consumer

    def set_producer(self, producer):
        self.producer = producer

    def get_producer(self):
        return self.producer
    
    def get_queue_type(self):
        return self.queue_type

    @staticmethod
    def initialize(processor):
        queue_type = PropX.get_property("mqlib.queue.type")

        if queue_type == "kafka":
            MQManager.get_instance().set_producer(KafkaProducer())
            MQManager.get_instance().set_consumer(KafkaConsumer(processor))
        elif queue_type == "pubsub":
            MQManager.get_instance().set_producer(PubSubProducer())
            MQManager.get_instance().set_consumer(PubSubConsumer(processor))
        else:
            Logger.error("Unknown queue type: " + queue_type)

    @staticmethod
    def start():
        MQManager.get_instance().get_consumer().start()

    @staticmethod
    def send_to_topic(topic, data):
        MQManager.get_instance().get_producer().send_to_topic(topic, data)

    @staticmethod
    def send_default_topic(data):
        MQManager.get_instance().get_producer().send_default_topic(data)

    @staticmethod
    def send_default_topic_with_key(key, data):
        MQManager.get_instance().get_producer().send_default_topic_with_key(key, data)

    @staticmethod
    def stop():
        consumer = MQManager.get_instance().get_consumer()
        if consumer is not None:
            consumer.close()
        else:
            Logger.error("Attempting to close uninitialized consumer")

    @staticmethod
    def flush_output():
        MQManager.get_instance().get_producer().flush()
