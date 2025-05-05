from confluent_kafka import Consumer, KafkaError
import json
import os

from concurrent.futures import ProcessPoolExecutor
from ..logger2 import Logger2 as Logger
from ..propx import PropX
import pltfrm.mq.manager as manager


class KafkaConsumer:
    def _on_assign(self, consumer, partitions):
        try:
            Logger.info('on_assign() partitions:{}'.format(partitions))
            Logger.info('on_assign:{} partitions assigned:'.format(len(partitions)))
        except KafkaError as e:
            Logger.exception("Error in partition assign on_assign:{}".format(e))

    def _on_revoke(self, consumer, partitions):
        try:
            Logger.info('on_revoke() partitions:{}'.format(str(partitions)))
            # get the consumer details
            Logger.info('on_revoke:{} Commit successful'.format(len(partitions)))
        except KafkaError as e:
            Logger.exception("on_revoke: Error in consumer commit:{}".format(e))

    def __init__(self, processor):
        self.kafka_consumer = None
        self.running = True
        self.pool = None
        self.initialized = False

        self.topic_list = PropX.get_property('mqlib.kafka.consumer.topic.list')
        if self.topic_list is None:
            Logger.error("Cannot proceed without topic list configuration.")
            return

        self.poll_delay = PropX.get_property_int('mqlib.kafka.consumer.poll.delay', 5000)
        self.num_workers = PropX.get_property_int('mqlib.workers.max', 1)

        self.settings = PropX.get_consumer_config('mqlib.kafka.consumer.config.')
        self.settings['default.topic.config']={'auto.offset.reset': 'latest'}

        if self.initialized is False:
            try:
                self.kafka_consumer = Consumer(self.settings)
            except Exception as ex:
                Logger.error("Error in consumer configuration  property:{}".format(ex))

            self.kafka_consumer.subscribe([self.topic_list],on_assign=self._on_assign, on_revoke=self._on_revoke)
            self.pool = ProcessPoolExecutor(self.num_workers)
            self.processor = processor
            self.initialized = True
        else:
            Logger.debug("consumer_init: Already consumer initialized...")

    def start(self):
        self.running = True

        Logger.warn("consumer_start: start consuming: consumer id:{}".format(str(id(self))))
        try:
            while self.running:
                Logger.debug("running: Fetch more messages")
                record = self.kafka_consumer.poll(timeout = self.poll_delay)
                if record is not None and not record.error():
                    # self.pool.submit(self.processor, json.loads(record.value().decode('utf-8')))
                    self.processor(json.loads(record.value().decode('utf-8')))

            Logger.debug("consumer_exit: out from main loop, Start cleanup")
        except Exception as ex:
            print(ex)
            Logger.error("exception in main consumer loop:{}".format(str(ex)))
        finally:
            Logger.warn("consumer_exit: close consumer")
            self.kafka_consumer.close()
            Logger.warn("consumer_exit: shutdown worker pool")
            self.pool.shutdown(wait=True)
            Logger.warn("consumer_exit: flush producer output queue")
            # dirty way of accessing manager from here?
            manager.MQManager.get_instance().get_producer().flush()
            Logger.warn("consumer_exit: Done cleanup. exiting")

    def close(self):
        Logger.warn("consumer_exit: set running false: consumer id:{}".format(str(id(self))))
        self.running = False

