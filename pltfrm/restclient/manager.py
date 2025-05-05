import requests
from requests.auth import HTTPBasicAuth


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class RestClientManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

    @staticmethod
    def get_instance():
        if RestClientManager.__instance is None:
            RestClientManager.__instance = RestClientManager()

        return RestClientManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    @staticmethod
    def check_endpoint_with_auth(url, username, password):
        try:
            response = requests.get(
                url, auth=HTTPBasicAuth(username, password), timeout=5
            )
            if response.status_code == 200:
                return True, 0
            elif response.status_code == 401:
                return False, 401
            else:
                return False, response.status_code
        except requests.exceptions.Timeout:
            return False, -1
        except requests.exceptions.ConnectionError:
            return False, -2
        except requests.exceptions.RequestException as e:
            return False, -3
