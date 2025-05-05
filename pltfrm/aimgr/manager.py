import json

import numpy as np
import tiktoken
from guardrails import Guard
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import AzureChatOpenAI, ChatOpenAI
from pydantic import ValidationError

# Removed google.generativeai and openai imports as they were commented out
from openai import AzureOpenAI, OpenAI

from ..logger2 import Logger2 as Logger
from ..propx import PropX


class Singleton(object):
    """singleton base class"""

    _instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instances[cls]


class AIManager(Singleton):
    """Main OpenAI manager class implementing the Singleton pattern."""

    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise Exception("This class is a singleton!")

        self.connections = {}

    @staticmethod
    def get_instance():
        """Get or create the singleton instance of AIManager."""
        if AIManager.__instance is None:
            AIManager.__instance = AIManager()

        return AIManager.__instance

    def __getattr__(self, name):
        return getattr(self.get_instance(), name)

    def set_connection(self, model_name, connection):
        """Set the asynchronous client for a specific model configuration."""
        Logger.info(f"Client set for model: {model_name}")
        self.connections[model_name] = connection
        Logger.info(f"Client set for model: {model_name} with client: {connection}")

    def get_connection(self, model_name):
        """Get the asynchronous client for a specific model configuration."""
        # Logger.info(f"Getting client for model: {self.model_name}") # Removed this line
        Logger.info(
            f"Getting client for model: {model_name}"
        )  # Log the argument instead
        return self.connections[model_name]

    @staticmethod
    def initialize():
        """Initialize the AI clients based on configuration properties."""
        instance = AIManager.get_instance()
        model_list = PropX.get_property("aimgr.agent.models").split(",")
        Logger.info(f"[AImgr] Models: {model_list}")
        for model_name in model_list:
            type = PropX.get_property(f"aimgr.{model_name}.type")
            if type == "azure":
                api_version = PropX.get_property(f"aimgr.{model_name}.api.version")
                endpoint = PropX.get_property(f"aimgr.{model_name}.endpoint")
                api_key = PropX.get_property(f"aimgr.{model_name}.api.key")
                deployment_name = PropX.get_property(f"aimgr.{model_name}.agent.model")
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                client = AzureOpenAI(
                    api_version=api_version,
                    azure_endpoint=endpoint,
                    api_key=api_key,
                )

                chat_client = AzureChatOpenAI(
                    openai_api_version=api_version,
                    azure_endpoint=endpoint,
                    deployment_name=deployment_name,
                    api_key=api_key,
                )
                # Store metadata
                connection = {
                    "type": type,
                    "api_version": api_version,
                    "endpoint": endpoint,
                    "model": deployment_name,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": client,
                    "chat_client": chat_client,
                }
                instance.set_connection(model_name, connection)
                Logger.info(
                    f"[AImgr] Azure model {model_name} initialized with metadata: {connection}"
                )
            elif type == "openai":
                api_key = PropX.get_property(f"aimgr.{model_name}.api.key")
                model = PropX.get_property(f"aimgr.{model_name}.agent.model")
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                client = OpenAI(api_key=api_key)
                chat_client = ChatOpenAI(model=model, api_key=api_key)

                # Store metadata
                connection = {
                    "type": type,
                    "model": model,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": client,
                    "chat_client": chat_client,
                }
                instance.set_connection(model_name, connection)
                Logger.info(
                    f"[AImgr] OpenAI model {model_name} initialized with metadata: {connection}"
                )
            elif type == "gemini":
                api_key = PropX.get_property(f"aimgr.{model_name}.api.key")
                model = PropX.get_property(f"aimgr.{model_name}.agent.model")
                endpoint = PropX.get_property(f"aimgr.{model_name}.endpoint")
                max_tokens = PropX.get_property(f"aimgr.{model_name}.max.tokens")

                client = OpenAI(api_key=api_key, base_url=endpoint)
                chat_client = ChatGoogleGenerativeAI(model=model, api_key=api_key)
                # Store metadata
                connection = {
                    "type": type,
                    "model": model,
                    "endpoint": endpoint,
                    "api_key": api_key,
                    "max_tokens": max_tokens,
                    "client": client,
                    "chat_client": chat_client,
                }
                instance.set_connection(model_name, connection)
                Logger.info(
                    f"[AImgr] Gemini model {model_name} initialized with metadata: {connection}"
                )

    @staticmethod
    def run_prompt(model_name, prompt):
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
        client = connection.get("client")
        completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an helpful assistant who strictly follows the context given",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            model=model,
        )
        return completion.choices[0].message.content

    @staticmethod
    def run_prompt_parse_json(model_name, prompt):
        """run a prompt and parse the json response"""
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        model = connection.get("model")
        max_tokens = connection.get("max_tokens")
        client = connection.get("client")
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are an helpful Security Operation Center assistant who strictly follows the context given and return the results as stated",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
        )
        try:
            # Extract substring that starts and ends with curly braces
            output = completion.choices[0].message.content
            Logger.info(f"[aimgr] Raw output: {output}")
            if not output.strip():  # Check for empty or whitespace-only response
                raise ValueError("The response is empty or contains only whitespace.")

            json_start = output.find("{")
            json_end = output.rfind("}") + 1

            if json_start == -1 or json_end == -1:  # Check if braces are missing
                raise ValueError("No valid JSON object found in the response.")

            json_content = output[json_start:json_end].strip()
            Logger.info(f"[aimgr] Output after parsing : {json_content}")
            return json.loads(json_content)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to parse JSON: {e}")

    @staticmethod
    def run_prompt_with_guard2(model_name, prompt, model_class):
        """run a prompt with pydantic guard"""
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        model = connection.get("model")
        client = connection.get("client")
        messages = [
            {
                "role": "system",
                "content": "You are an helpful Security Operation Center assistant who strictly follows the context given and return the results as stated",
            },
            {"role": "user", "content": prompt},
        ]
        guard = Guard.from_pydantic(output_class=model_class, messages=messages)
        result = guard(
            llm_api=client.chat.completions.create,
            model=model,
            num_reasks=1,
        )
        return result.raw_llm_output

    @staticmethod
    def get_agent_executor(model_name, tools, agent_prompt) -> AgentExecutor:
        """
        Create a Langchain tool-calling agent executor for a specific model configuration.

        Args:
            tools (list): A list of Langchain tools available to the agent.
            agent_prompt (ChatPromptTemplate): The prompt template defining the agent's behavior.
            model_name (str): The name of the model configuration (e.g., 'azure', 'openai') to use.

        Returns:
            AgentExecutor: The configured Langchain agent executor.

        Raises:
            ValueError: If the chat client for the specified model_name is not found.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        chat_client = connection.get("chat_client")
        if not chat_client:
            raise ValueError(f"Chat client for model '{model_name}' not found.")

        agent = create_tool_calling_agent(chat_client, tools, agent_prompt)
        return AgentExecutor(agent=agent, tools=tools, verbose=True)

    @staticmethod
    def get_vector_embedding(model_name, input_text):
        """
        Generate vector embedding for input text using the specified model configuration's embedding capability.

        Args:
            input_text (str): The text to generate embeddings for.
            model_name (str): The name of the model configuration (e.g., 'azure', 'openai').
                               The actual embedding model used is determined by 'aimgr.embedding.model' property.

        Returns:
            list: The embedding vector as a list of floats.

        Raises:
            ValueError: If the client for the model_name is not found or the embedding model property is missing.
            Exception: If any error occurs during embedding generation.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        client = connection.get("client")
        model = connection.get("model")
        try:
            response = client.embeddings.create(model=model, input=input_text)
            query_vector = np.array(
                response.data[0].embedding, dtype=np.float32
            ).tolist()
            Logger.info(
                f"Query vector embedding generated successfully using {model_name}!"
            )
            return query_vector

        except ValueError as ve:
            Logger.error(f"Configuration Error: {ve}")
            raise
        except Exception as e:
            Logger.error(f"An error occurred while generating the query vector: {e}")
            raise

    @staticmethod
    def token_calculator(model_name, name, prompt):
        """
        Calculates the number of tokens in the given prompt using the specified model.

        Args:
            name (str): The name associated with the prompt.
            prompt (str): The prompt string to be tokenized.

        Writes:
            The name and token count to a file named 'Tokens.txt'.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        model = connection.get("model")
        encoder = tiktoken.encoding_for_model(model)
        token_count = len(encoder.encode(prompt))
        Logger.info(f"Token count for {name}, model: {model}: {token_count}")

    @staticmethod
    def run_prompt_with_structured_output(model_name, prompt, model_class):
        """
        Run a prompt and return the structured output.

        Args:
            model_name (str): The name of the model configuration (e.g., 'azure', 'openai').
            prompt (str): The user's prompt.
            model_class: The Pydantic model class for the structured output.

        Returns:
            dict: The structured output from the AI's response message.

        Raises:
            ValidationError: If the LLM response fails Pydantic validation.
            ValueError: If the chat client for the model is not found.
            Exception: For other LLM or processing errors.
        """
        instance = AIManager.get_instance()
        connection = instance.get_connection(model_name)
        chat_client = connection.get("chat_client")
        if not chat_client:
            raise ValueError(f"Chat client for model '{model_name}' not found.")

        try:
            # Chain definition
            chain = chat_client.with_structured_output(model_class)
            # Invoke the chain
            response = chain.invoke(prompt)
            return response
        except ValidationError as e:
            # Log the detailed validation errors, including the input data that failed
            Logger.error(f"[AImgr] Pydantic Validation Error: {e.errors()}")
            # Optionally log the raw prompt as well for full context
            Logger.error(f"[AImgr] Failing Prompt: {prompt}")
            raise e  # Re-raise the exception after logging
        except Exception as e:
            # Catch other potential errors during invocation
            Logger.error(f"[AImgr] Error during structured output invocation: {e}")
            raise e
