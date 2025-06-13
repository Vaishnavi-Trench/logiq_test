import traceback
import numpy as np

from openai import AzureOpenAI, OpenAI, APITimeoutError
import instructor
from instructor.exceptions import (
    InstructorRetryException,
)
from langchain_core.prompts import PromptTemplate

from pydantic import ValidationError

from ..propx import PropX
from ..logger2 import Logger2 as Logger
from ..prompts import PromptManager


class Singleton(object):
    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class AIManager(Singleton):
    __instance = None

    def __init__(self):
        if self.__instance is not None:
            # To prevent re-initialization issues if __init__ logic were complex.
            # For a simple __init__ like this, it's less critical but good practice for singletons.
            return
        self.connections = {}
        AIManager.__instance = self  # Set instance here to allow __init__ to complete

    @staticmethod
    def get_instance():
        if AIManager.__instance is None:
            AIManager.__instance = AIManager()
        return AIManager.__instance

    def set_connection(self, model_name, connection):
        Logger.info(f"Client settings stored for model: {model_name}")
        self.connections[model_name] = connection
        # Logger.info(f"Client set for model: {model_name} with client: {connection}") # Can be verbose

    def get_connection(self, model_name):
        Logger.info(f"Getting client configuration for model: {model_name}")
        if model_name in self.connections:
            return self.connections[model_name]
        else:
            Logger.error(f"Connection for model '{model_name}' not found.")
            raise ValueError(f"Connection for model '{model_name}' not found.")

    @staticmethod
    def initialize():
        PromptManager.initialize()
        instance = AIManager.get_instance()
        if instance.connections:  # Avoid re-initializing if already done
            Logger.info("[AImgr] Already initialized.")
            return

        model_list_str = PropX.get_property("aimgr.agent.models")
        if not model_list_str:
            Logger.error("[AImgr] No models defined in 'aimgr.agent.models' property.")
            return
        model_list = model_list_str.split(",")
        Logger.info(f"[AImgr] Initializing models: {model_list}")

        default_timeout_seconds = 60  # Default timeout for each API request attempt
        default_instructor_max_retries = 3  # Default max retries for instructor

        for model_name in model_list:
            model_name = model_name.strip()
            type = PropX.get_property(f"aimgr.{model_name}.type")
            if not type:
                Logger.warn(
                    f"[AImgr] Type not configured for model {model_name}. Skipping."
                )
                continue

            try:
                request_timeout_seconds = default_timeout_seconds
                instructor_max_retries = default_instructor_max_retries
            except ValueError:
                Logger.warn(
                    f"[AImgr] Invalid numeric value for timeout or retries for {model_name}. Using defaults."
                )
                request_timeout_seconds = default_timeout_seconds
                instructor_max_retries = default_instructor_max_retries

            raw_client_for_patching = None  # Client instance that instructor will wrap
            general_purpose_client = None  # Unpatched client for other uses

            if type == "azure":
                api_version = PropX.get_property(f"aimgr.{model_name}.api.version")
                endpoint = PropX.get_property(f"aimgr.{model_name}.endpoint")
                api_key = PropX.get_property(f"aimgr.{model_name}.api.key")
                deployment_name = PropX.get_property(f"aimgr.{model_name}.agent.model")
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                if not all([api_version, endpoint, api_key, deployment_name]):
                    Logger.warn(
                        f"[AImgr] Azure configuration missing for {model_name}. Skipping."
                    )
                    continue

                common_azure_args = {
                    "api_version": api_version,
                    "azure_endpoint": endpoint,
                    "api_key": api_key,
                    "timeout": request_timeout_seconds,
                }
                general_purpose_client = AzureOpenAI(**common_azure_args)
                raw_client_for_patching = AzureOpenAI(
                    **common_azure_args
                )  # Separate instance for patching

                chat_client = instructor.patch(
                    raw_client_for_patching, mode=instructor.Mode.TOOLS
                )

                connection = {
                    "type": type,
                    "api_version": api_version,
                    "endpoint": endpoint,
                    "model": deployment_name,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": general_purpose_client,
                    "chat_client": chat_client,
                    "request_timeout_seconds": request_timeout_seconds,
                    "instructor_max_retries": instructor_max_retries,
                }
                instance.set_connection(model_name, connection)

            elif type == "openai":
                api_key = PropX.get_property(f"aimgr.{model_name}.api.key")
                model = PropX.get_property(f"aimgr.{model_name}.agent.model")
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                if not all([api_key, model]):
                    Logger.warn(
                        f"[AImgr] OpenAI configuration missing for {model_name}. Skipping."
                    )
                    continue

                common_openai_args = {
                    "api_key": api_key,
                    "timeout": request_timeout_seconds,
                }
                general_purpose_client = OpenAI(**common_openai_args)
                raw_client_for_patching = OpenAI(
                    **common_openai_args
                )  # Separate instance
                chat_client = instructor.patch(
                    raw_client_for_patching, mode=instructor.Mode.TOOLS
                )

                connection = {
                    "type": type,
                    "model": model,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": general_purpose_client,
                    "chat_client": chat_client,
                    "request_timeout_seconds": request_timeout_seconds,
                    "instructor_max_retries": instructor_max_retries,
                }
                instance.set_connection(model_name, connection)

            elif type == "gemini":  # Assuming Gemini via OpenAI-compatible endpoint
                api_key = PropX.get_property(
                    f"aimgr.{model_name}.api.key"
                )  # Often 'GOOGLE_API_KEY' or 'N/A' if endpoint handles auth
                model_id = PropX.get_property(
                    f"aimgr.{model_name}.agent.model"
                )  # e.g., models/gemini-1.5-flash-001
                endpoint = PropX.get_property(
                    f"aimgr.{model_name}.endpoint"
                )  # OpenAI-compatible endpoint URL
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                if not all(
                    [model_id, endpoint]
                ):  # API key might be optional depending on endpoint setup
                    Logger.warn(
                        f"[AImgr] Gemini (OpenAI-compatible) configuration missing for {model_name}. Skipping."
                    )
                    continue

                common_gemini_args = {
                    "api_key": (
                        api_key if api_key else "EMPTY"
                    ),  # httpx requires a non-empty string, some proxy endpoints might not need it.
                    "base_url": endpoint,
                    "timeout": request_timeout_seconds,
                }
                general_purpose_client = OpenAI(**common_gemini_args)
                raw_client_for_patching = OpenAI(
                    **common_gemini_args
                )  # Separate instance
                chat_client = instructor.patch(
                    raw_client_for_patching, mode=instructor.Mode.TOOLS
                )

                connection = {
                    "type": type,
                    "model": model_id,
                    "endpoint": endpoint,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": general_purpose_client,
                    "chat_client": chat_client,
                    "request_timeout_seconds": request_timeout_seconds,
                    "instructor_max_retries": instructor_max_retries,
                }
                instance.set_connection(model_name, connection)
            else:
                Logger.warn(
                    f"[AImgr] Unsupported model type '{type}' for model {model_name}. Skipping."
                )
                continue

            Logger.info(
                f"[AImgr] Model '{model_name}' ({type}) initialized. "
                f"Per-attempt timeout: {request_timeout_seconds}s, "
                f"Instructor max_retries: {instructor_max_retries}."
            )

    @staticmethod
    def get_vector_embedding(model_name, input_text):
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        # For embeddings, OpenAI expects the model to be an embedding model ID.
        # This 'model' might be a chat model. You should use a specific embedding model.
        # e.g., text-embedding-ada-002 or a model specified in props for embeddings.
        # Let's assume PropX has 'aimgr.{model_name}.embedding.model'
        embedding_model_id = connection.get("model")
        if not embedding_model_id:  # Fallback or error if not specified
            embedding_model_id = (
                "text-embedding-ada-002"  # A common default, but should be configurable
            )
            Logger.warn(
                f"Embedding model not specified for {model_name}, defaulting to {embedding_model_id}"
            )

        client = connection.get("client")  # Use the general_purpose_client
        if not client:
            raise ValueError(
                f"General client for model '{model_name}' not found for embeddings."
            )
        try:
            response = client.embeddings.create(
                model=embedding_model_id, input=input_text
            )
            query_vector = np.array(
                response.data[0].embedding, dtype=np.float32
            ).tolist()
            Logger.info(
                f"Query vector embedding generated successfully using {embedding_model_id} via {model_name} config!"
            )
            return query_vector
        except Exception as e:
            Logger.error(
                f"An error occurred while generating the query vector using {embedding_model_id}: {e}"
            )
            Logger.error(traceback.format_exc())
            raise

    @staticmethod
    def run_prompt_with_structured_output(
        intcid,
        prompt_template_name,
        prompt_params,
        model_name,
        model_class,
        history_params,
        type=None,
        system_prompt="You are a helpful Security Operation Center assistant who strictly follows the context given and return the results as stated",
    ):
        """
        Run a prompt and return the structured output, leveraging instructor's retry mechanism.
        """
        prompt_template, prompt_version = PromptManager.get_prompt_template(
            intcid, prompt_template_name
        )
        _prompt_template = PromptTemplate.from_template(prompt_template)
        _user_prompt = _prompt_template.invoke(prompt_params).text

        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)

        chat_client = connection.get("chat_client")
        if not chat_client:
            raise ValueError(
                f"Instructor-patched chat client for model '{model_name}' not found."
            )

        api_model_name = connection.get("model")  # This is the deployment/model ID
        # Timeout per attempt is already set on the chat_client instance's underlying OpenAI client
        per_attempt_timeout_seconds = connection.get("request_timeout_seconds")
        max_retries_for_call = connection.get("instructor_max_retries")

        Logger.info(
            f"[AImgr] Per-attempt timeout: {per_attempt_timeout_seconds}s. "
            f"Instructor max_retries for this call: {max_retries_for_call}."
        )

        try:
            # Instructor handles retries based on `max_retries` passed to `create`
            # and uses the timeout configured on the underlying client for each attempt.
            response = chat_client.chat.completions.create(
                model=api_model_name,
                response_model=model_class,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": _user_prompt},
                ],
                max_retries=max_retries_for_call,
            )

            try:
                usage_data = response._raw_response.usage
            except AttributeError:
                # If the response does not have usage data, we can set it to None or an empty dict
                usage_data = None

            reponse_object = response.model_dump()
            PromptManager.save_prompt_history(
                intcid,
                prompt_template_name,
                prompt_version,
                model_name,
                system_prompt,
                _user_prompt,
                reponse_object,
                model_class,
                history_params,
                usage_data,
                type=type,
            )

            return reponse_object
        except ValidationError as ve:
            # Pydantic Validation Error is not retriable by instructor's default API error policy,
            # as it indicates a mismatch between the LLM's output and the expected Pydantic model.
            Logger.error(
                f"[AImgr] Pydantic Validation Error (non-retriable by API retry logic): {ve.errors()}"
            )
            Logger.error(
                f"[AImgr] Failing Prompt for Pydantic Validation: {_user_prompt}"
            )  # Log the full prompt
            raise ve
        except APITimeoutError as te:
            # This is openai.APITimeoutError.
            # It's caught here if instructor's retries (each respecting the client's timeout)
            # ultimately fail because every attempt timed out.
            Logger.error(
                f"[AImgr] OpenAI API request timed out after {max_retries_for_call} retries by instructor. Error: {te}"
            )
            Logger.error(f"[AImgr] Failing Prompt that led to timeout: {_user_prompt}")
            raise te  # Re-raise the APITimeoutError
        except InstructorRetryException as ire:
            # This exception is raised by instructor if its retry mechanism (tenacity)
            # exhausts all attempts for retriable API errors.
            Logger.error(
                f"[AImgr] Instructor retries ({max_retries_for_call}) exhausted. Error: {ire}"
            )
            Logger.error(
                f"[AImgr] Failing Prompt that led to instructor retry exhaustion: {_user_prompt}"
            )
            # Log the underlying exception if available

            raise ire  # Re-raise InstructorRetryException
        except Exception as e:
            # Catch any other unexpected errors from the API call or instructor processing.
            Logger.error(
                f"[AImgr] An unexpected error occurred during structured output call for model '{model_name}': {e}"
            )
            Logger.error(traceback.format_exc())  # Log the full stack trace
            Logger.error(f"[AImgr] Failing Prompt: {_user_prompt}")
            raise e

    @staticmethod
    def run_prompt_with_structured_output_direct(
        system_prompt, user_prompt, model_name, model_class
    ):
        """
        Run a prompt and return the structured output, leveraging instructor's retry mechanism.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)

        chat_client = connection.get("chat_client")
        if not chat_client:
            raise ValueError(
                f"Instructor-patched chat client for model '{model_name}' not found."
            )

        api_model_name = connection.get("model")  # This is the deployment/model ID
        # Timeout per attempt is already set on the chat_client instance's underlying OpenAI client
        per_attempt_timeout_seconds = connection.get("request_timeout_seconds")
        max_retries_for_call = connection.get("instructor_max_retries")

        Logger.info(
            f"[AImgr] Per-attempt timeout: {per_attempt_timeout_seconds}s. "
            f"Instructor max_retries for this call: {max_retries_for_call}."
        )

        try:
            # Instructor handles retries based on `max_retries` passed to `create`
            # and uses the timeout configured on the underlying client for each attempt.
            response = chat_client.chat.completions.create(
                model=api_model_name,
                response_model=model_class,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_retries=max_retries_for_call,
            )

            return response
        except ValidationError as ve:
            # Pydantic Validation Error is not retriable by instructor's default API error policy,
            # as it indicates a mismatch between the LLM's output and the expected Pydantic model.
            Logger.error(
                f"[AImgr] Pydantic Validation Error (non-retriable by API retry logic): {ve.errors()}"
            )
            Logger.error(
                f"[AImgr] Failing Prompt for Pydantic Validation: {user_prompt}"
            )  # Log the full prompt
            raise ve
        except APITimeoutError as te:
            # This is openai.APITimeoutError.
            # It's caught here if instructor's retries (each respecting the client's timeout)
            # ultimately fail because every attempt timed out.
            Logger.error(
                f"[AImgr] OpenAI API request timed out after {max_retries_for_call} retries by instructor. Error: {te}"
            )
            Logger.error(f"[AImgr] Failing Prompt that led to timeout: {user_prompt}")
            raise te  # Re-raise the APITimeoutError
        except InstructorRetryException as ire:
            # This exception is raised by instructor if its retry mechanism (tenacity)
            # exhausts all attempts for retriable API errors.
            Logger.error(
                f"[AImgr] Instructor retries ({max_retries_for_call}) exhausted. Error: {ire}"
            )
            Logger.error(
                f"[AImgr] Failing Prompt that led to instructor retry exhaustion: {user_prompt}"
            )
            # Log the underlying exception if available

            raise ire  # Re-raise InstructorRetryException
        except Exception as e:
            # Catch any other unexpected errors from the API call or instructor processing.
            Logger.error(
                f"[AImgr] An unexpected error occurred during structured output call for model '{model_name}': {e}"
            )
            Logger.error(traceback.format_exc())  # Log the full stack trace
            Logger.error(f"[AImgr] Failing Prompt: {user_prompt}")
            raise e

    @staticmethod
    def run_prompt(
        model_name,
        prompt,
        system_prompt="You are an helpful Security Operation Center assistant who strictly follows the context given and return the results as stated",
    ):
        """
        Run a simple chat completion prompt using the specified model configuration.

        Args:
            prompt (str): The user's prompt.
            model_name (str): The name of the model configuration (e.g., 'azure', 'openai').

        Returns:
            str: The content of the AI's response message.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        model = connection.get("model")
        max_tokens = connection.get("max_tokens")
        max_completion_tokens = connection.get("max_completion_tokens")
        client = connection.get("client")
        # Use correct parameter depending on which is set
        completion_kwargs = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "model": model,
        }
        if max_completion_tokens is not None:
            completion_kwargs["max_completion_tokens"] = max_completion_tokens
        elif max_tokens is not None:
            completion_kwargs["max_tokens"] = max_tokens
        completion = client.chat.completions.create(**completion_kwargs)
        return completion.choices[0].message.content
