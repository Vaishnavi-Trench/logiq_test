from google.cloud import pubsub_v1
import json
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from ..logger2 import Logger2 as Logger
from ..propx import PropX

class PubSubConsumer:
    def __init__(self, processor):
        self.project_id = PropX.get_property('mqlib.pubsub.consumer.project.id')
        self.subscription_id = PropX.get_property('mqlib.pubsub.consumer.subscription.id')
        self.num_workers = PropX.get_property_int('mqlib.workers.max', 1)
        
        self.subscriber = pubsub_v1.SubscriberClient()
        self.subscription_path = self.subscriber.subscription_path(
            self.project_id, self.subscription_id)
        
        self.running = True
        self.pool = ProcessPoolExecutor(self.num_workers)
        self.processor = processor
        self.message_buffer = defaultdict(list)
        self.last_process_time = datetime.now()

    def callback(self, message):
        if not self.running:
            return

        try:
            data = json.loads(message.data.decode('utf-8'))
            Logger.info(f"received: data:{data}")            
            self.processor(data)
            
            message.ack()
            
        except Exception as ex:
            Logger.error(f"Error processing message: {ex}")
            message.nack()

    def start(self):
        self.running = True
        
        try:
            Logger.info(f"Listen for messages on: {self.subscription_path}")            
            streaming_pull_future = self.subscriber.subscribe(
                self.subscription_path, callback=self.callback)
            Logger.info(f"Started listening for messages on {self.subscription_path}")
            
            # Keep the main thread alive
            streaming_pull_future.result()
            
        except Exception as ex:
            Logger.error(f"Exception in consumer loop: {ex}")
        finally:
            self.close()

    def close(self):
        self.running = False
        self.pool.shutdown(wait=True)
        self.subscriber.close()
