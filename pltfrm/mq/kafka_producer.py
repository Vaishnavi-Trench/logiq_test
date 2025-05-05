from confluent_kafka import Producer, KafkaError
import os
import json
from ..logger2 import Logger2 as Logger
from ..propx import PropX


class KafkaProducer:

    def __init__(self):
        self.settings = PropX.get_producer_config('mqlib.kafka.producer.config.')
        self.default_out_topic = PropX.get_property('mqlib.kafka.producer.default.output.topic')
        self.producer_map = {}

    def get_pid_producer(self):
        mypid = os.getpid()
        if mypid not in self.producer_map:
            try:
                self.producer_map[mypid] = Producer(self.settings)
            except Exception as ex:
                Logger.error("Error in producer configuration  property:{}".format(ex))

        return self.producer_map[mypid]

    def send_to_topic(self, topic, data):
        try:
            self.get_pid_producer().produce(topic, json.dumps(data).encode('utf-8'))
        except Exception as ex:
            Logger.error("Error in sending the message, exception:{}".format(ex))

    def send_default_topic(self, data):
        try:
            retries = 0
            while retries < 5:
                try:
                    self.get_pid_producer().produce(self.default_out_topic, json.dumps(data).encode('utf-8'))
                    break
                except BufferError as ex:
                    self.get_pid_producer().flush()
                    Logger.warn("Buffer full, flush, exception:{}".format(ex))
            retries += 1
        except Exception as ex:
            Logger.error("Error in sending the message, exception:{}".format(ex))

    def send_default_topic_with_key(self, key, data):
        try:
            retries = 0
            while retries < 5:
                try:
                    self.get_pid_producer().produce(self.default_out_topic, key=key, value=json.dumps(data).encode('utf-8'))
                    break
                except BufferError as ex:
                    self.get_pid_producer().flush()
                    Logger.warn("Buffer full, flush, exception:{}".format(ex))
            retries += 1
        except Exception as ex:
            Logger.error("Error in sending the message, exception:{}".format(ex))

    def flush(self):
        for producer in self.producer_map.values():
            producer.flush()

        Logger.info("producer_flush: flushed output")
