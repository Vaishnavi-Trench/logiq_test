from google.cloud import pubsub_v1
import json
import os
from ..logger2 import Logger2 as Logger
from ..propx import PropX

class PubSubProducer:
    def __init__(self):
        self.project_id = PropX.get_property('mqlib.pubsub.producer.project.id')
        self.default_topic = PropX.get_property('mqlib.pubsub.producer.default.topic')
        
        # Create publisher client with message ordering enabled
        publisher_options = pubsub_v1.types.PublisherOptions(
            enable_message_ordering=True
        )
        client_options = {"api_endpoint": "us-central1-pubsub.googleapis.com:443"}
        self.publisher = pubsub_v1.PublisherClient(
            publisher_options=publisher_options,
            client_options=client_options
        )
        self.topic_paths = {}

    def _get_topic_path(self, topic_name):
        if topic_name not in self.topic_paths:
            self.topic_paths[topic_name] = self.publisher.topic_path(self.project_id, topic_name)
        return self.topic_paths[topic_name]

    def send_to_topic(self, topic, data):
        try:
            topic_path = self._get_topic_path(topic)
            future = self.publisher.publish(
                topic_path, 
                json.dumps(data).encode('utf-8')
            )
            future.result()
        except Exception as ex:
            Logger.error(f"Error in sending the message: {ex}")

    def send_default_topic(self, data):
        self.send_to_topic(self.default_topic, data)

    def send_default_topic_with_key(self, key, data):
        try:
            topic_path = self._get_topic_path(self.default_topic)
            # The ordering_key determines which subscription orderingKey to use
            future = self.publisher.publish(
                topic_path,
                json.dumps(data).encode('utf-8'),
                ordering_key=str(key)
            )
            future.result()  # Wait for the publish to complete
            Logger.debug(f"Message published with ordering key: {key}")
        except Exception as ex:
            Logger.error(f"Error in sending the message: {ex}")
            raise  # Re-raise to handle at higher level if needed

    def flush(self):
        # Pub/Sub publisher automatically handles batching and flushing
        pass
