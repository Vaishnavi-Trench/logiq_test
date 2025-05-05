import argparse
import json
import requests
import time
import os


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class PropX(Singleton):
    __instance = None

    def get(self, name):
        try:
            return self.props[name]
        except:
            return None

    @staticmethod
    def get_consumer_config(pref):
        props = PropX.get_instance().props
        settings = {}
        for key, value in props.items():
            if key.startswith(pref):
                settings[key.replace(pref, "")] = value
        return settings

    @staticmethod
    def get_producer_config(pref):
        props = PropX.get_instance().props
        settings = {}
        for key, value in props.items():
            if key.startswith(pref):
                settings[key.replace(pref, "")] = value
        return settings

    @staticmethod
    def get_instance():
        if PropX.__instance is None:
            PropX.__instance = PropX()

        return PropX.__instance

    @staticmethod
    def get_all_props():
        return PropX.get_instance().props

    @staticmethod
    def get_matching_props(match_prefix):
        matching_props = {}
        all_props = PropX.get_instance().props
        for key, val in all_props.items():
            if key.startswith(match_prefix):
                matching_props[key] = val

        return matching_props

    @staticmethod
    def get_property(prop_name):
        prop_val = PropX.get_instance().get(prop_name)
        return prop_val

    @staticmethod
    def get_property_int(prop_name, default):
        try:
            prop_val = PropX.get_instance().get(prop_name)
            return int(prop_val)
        except:
            return default

    @staticmethod
    def get_property_float(prop_name, default):
        try:
            prop_val = PropX.get_instance().get(prop_name)
            return float(prop_val)
        except:
            return default

    @staticmethod
    def initialize():
        parser = argparse.ArgumentParser()

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--file", help="file name to load props from")
        group.add_argument("--url", help="server rest api to fetch props from")
        args = parser.parse_args()
        if args.file is not None:
            with open(args.file) as conf_file:
                PropX.get_instance().props = json.load(conf_file)
        elif args.url is not None:
            success = False

            while success is not True:
                try:
                    env_project_id = os.getenv("TRENCH_PROJECT_ID")
                    if env_project_id is not None:
                        response = requests.get(
                            url=args.url, params={"projectid": env_project_id}
                        )
                    else:
                        response = requests.get(args.url)
                    if response is not None and response.status_code == 200:
                        config = response.json()
                        if (
                            config is not None
                            and config["status"] == "success"
                            and "data" in config
                        ):
                            PropX.get_instance().props = config["data"]
                            success = True
                            continue
                    print(
                        "failed to get properties. Retry. response:{}".format(response)
                    )
                    time.sleep(5)
                except Exception as ex:
                    print("failed to get properties. Retry. ex:{}".format(ex))
                    time.sleep(5)

        print(PropX.get_instance().props)
