import logging
import sys
from confluent_kafka import Producer
from .kafkaloggerhandler import KafkaLoggingHandler
from .fileloggerwrapper import LogCreator
from ..propx import PropX
from threading import Lock

class SingletonMeta(type):
    """
    Thread-safe Singleton Metaclass
    """
    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Logger2(metaclass=SingletonMeta):
    def __init__(self):
        self.logger = logging.getLogger("default")
        self.logger.setLevel(logging.INFO)
        self.initialized = False
        self.id = None

        # Prevent duplicate handlers
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def create_instance(self):
        """
        Initialize the logger based on the configuration.
        """
        if self.initialized:
            return
        
        self.initialized = True
        try:
            log_level = PropX.get_property('logger.level') or "INFO"
            log_level_map = {
                "DEBUG": logging.DEBUG,
                "WARN": logging.WARNING,
                "INFO": logging.INFO,
                "ERROR": logging.ERROR,
            }
            log_level = log_level_map.get(log_level.upper(), logging.INFO)

            ss_logger_output_type = PropX.get_property('module.logger.outputype')
            logger_name = PropX.get_property('module.logger.name')

            self.logger = logging.getLogger(logger_name)
            self.logger.setLevel(log_level)

            if ss_logger_output_type == 'kafka':
                kafka_topic = PropX.get_property('module.logger.topic')
                server = {'bootstrap.servers': PropX.get_property('module.logger.broker')}
                kafka_producer = Producer(server)
                kafka_handler = KafkaLoggingHandler(kafka_producer, kafka_topic, logger_name)
                self.logger.addHandler(kafka_handler)

            elif ss_logger_output_type == 'file':
                log_file_path = PropX.get_property('logger.dir')
                LogCreator.Path = log_file_path
                LogCreator.Level = log_level
                LogCreator()
                self.logger = LogCreator.return_logger(logger_name)

            self.logger.info(f"Logger initialized with level {log_level} and output type {ss_logger_output_type}")

        except Exception as e:
            self.logger.error(f"Error initializing logger: {e}", exc_info=True)

    def transform(self, msg):
        """
        Add an optional ID to log messages.
        """
        return f"{self.id} {msg}" if self.id else msg

    def debug_(self, msg): self.logger.debug(self.transform(msg))
    def info_(self, msg): self.logger.info(self.transform(msg))
    def warning_(self, msg): self.logger.warning(self.transform(msg))
    def error_(self, msg): self.logger.error(self.transform(msg))
    def critical_(self, msg): self.logger.critical(self.transform(msg))
    def exception_(self, msg): self.logger.exception(self.transform(msg))

    def setIdentity(self, id): self.id = id

    @staticmethod
    def setLoggerId(id): Logger2.getLoggerInstance().setIdentity(id)
    @staticmethod
    def getLoggerInstance(): return Logger2()
    @staticmethod
    def initialize(): Logger2.getLoggerInstance().create_instance()
    @staticmethod
    def debug(msg): Logger2.getLoggerInstance().debug_(msg)
    @staticmethod
    def info(msg): Logger2.getLoggerInstance().info_(msg)
    @staticmethod
    def warn(msg): Logger2.getLoggerInstance().warning_(msg)
    @staticmethod
    def error(msg): Logger2.getLoggerInstance().error_(msg)
    @staticmethod
    def critical(msg): Logger2.getLoggerInstance().critical_(msg)
    @staticmethod
    def exception(msg): Logger2.getLoggerInstance().exception_(msg)