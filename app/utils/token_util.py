import tiktoken
from pltfrm import PropX
from pltfrm import Logger2 as Logger


def token_calculator(name, prompt):
    """
    Calculates the number of tokens in the given prompt using the specified model.

    Args:
        name (str): The name associated with the prompt.
        prompt (str): The prompt string to be tokenized.

    Writes:
        The name and token count to a file named 'Tokens.txt'.
    """
    Logger.info("Starting token_calculator")
    model_name = PropX.get_property("module.agent.model")
    encoder = tiktoken.encoding_for_model(model_name)
    token_count = len(encoder.encode(prompt))

    Logger.info(f"Token count for {name}: {token_count}")
