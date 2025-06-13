from typing import Any
from pltfrm import Logger2 as Logger
from pltfrm.aimgr.manager import AIManager
import importlib


def execute_prompt(
    intcid: str,
    model_name: str,
    system_prompt: str,
    user_prompt: str,
    model_class: str = None,
) -> Any:  # Change return type from str to Any
    """
    Execute a prompt using the specified model and prompts.
    Args:
        intcid: The customer ID to get tools for
        model_name: The name of the model to use for executing the prompt
        system_prompt: The system prompt to use
        user_prompt: The user prompt to use
        model_class: Just the class name (e.g., "AlertNameResponse") - will be loaded from app.models.classes
    Returns:
        The result of the prompt execution (string or structured object depending on model_class)
    """
    Logger.info(f"Executing prompt for customer {intcid} using model {model_name}")

    if model_class and model_class.strip():
        try:
            # Use app.models.classes as the default module path
            Logger.info(f"Using structured output with model class: {model_class}")
            module_path = "app.models.classes"
            class_name = model_class.strip()

            # Import the module and get the class
            module = importlib.import_module(module_path)
            class_obj = getattr(module, class_name)

            return AIManager.run_prompt_with_structured_output_direct(
                system_prompt,
                user_prompt,
                model_name,
                class_obj,
            )
        except (ImportError, AttributeError, ValueError) as e:
            Logger.error(f"Failed to load model class {model_class}: {str(e)}")
            # Fall back to regular prompt
            Logger.info("Falling back to regular prompt")
            return AIManager.run_prompt(
                model_name, user_prompt, system_prompt=system_prompt
            )
    else:
        # Use regular prompt if no model class specified
        return AIManager.run_prompt(
            model_name, user_prompt, system_prompt=system_prompt
        )
