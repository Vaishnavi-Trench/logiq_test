import logging
import time
import os


class LogCreator:
    Path = None
    Level = None
    directory = "log_db"
    log_level_mapper = {
        "DEBUG": logging.DEBUG,
        "WARN": logging.WARN,
        "INFO": logging.INFO,
        "ERROR": logging.ERROR,
    }

    def __init__(self):
        try:
            try:
                if (
                    LogCreator.Path is None or LogCreator.Path == ""
                ) and not os.path.exists(LogCreator.directory):
                    print(f"Creating log directory: {LogCreator.directory}")
                    os.makedirs(LogCreator.directory, exist_ok=True)
                    LogCreator.Path = LogCreator.directory + "/logger.log"
                    print(f"Setting log path to: {LogCreator.Path}")
                elif (
                    LogCreator.Path is None or LogCreator.Path == ""
                ) and os.path.exists(LogCreator.directory):
                    LogCreator.Path = LogCreator.directory + "/logger.log"
                    print(f"Setting log path to: {LogCreator.Path}")
            except OSError as e:
                print(f"Error creating log directory: {e}")
                if e.errno:
                    raise

            # Ensure parent directory exists
            if LogCreator.Path:
                log_dir = os.path.dirname(LogCreator.Path)
                if log_dir and not os.path.exists(log_dir):
                    print(f"Creating parent directory for log file: {log_dir}")
                    try:
                        os.makedirs(log_dir, exist_ok=True)
                    except OSError as e:
                        print(f"Failed to create log directory {log_dir}: {e}")

            print(f"Opening log file at: {LogCreator.Path}")
            LogCreator.file_handle = logging.FileHandler(LogCreator.Path, mode="a")
            formatter = logging.Formatter(
                "%(asctime)s: %(levelname)s : %(name)s : %(message)s"
            )
            formatter.converter = time.gmtime
            LogCreator.file_handle.setFormatter(formatter)
            print(f"Log file handler created successfully")
        except IOError as e:
            # raise
            print(f"IOError creating log file: {e.errno} - {e}")

    @staticmethod
    def return_logger(name):
        try:
            logger = logging.getLogger(name)
            logger.addHandler(LogCreator.file_handle)
            logger.setLevel(LogCreator.Level or logging.INFO)
            print(
                f"Logger '{name}' configured successfully with level {LogCreator.Level}"
            )
            return logger
        except AttributeError as a:
            print(f"AttributeError configuring logger: {a}")
            # Return a basic console logger as fallback
            fallback_logger = logging.getLogger(name)
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s: %(levelname)s : %(name)s : %(message)s"
            )
            handler.setFormatter(formatter)
            fallback_logger.addHandler(handler)
            return fallback_logger
