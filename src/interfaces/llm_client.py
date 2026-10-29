"""BaseLLMClient Abstract Base Class.

Defines the contract and shared functionality for Large Language Model integrations.
Demonstrates:
- Abstract Classes & Interfaces (abc.ABC, @abstractmethod)
- Encapsulation (_api_key, _model_name, _timeout)
- Polymorphism (Any derived client implements generate_structured_analysis)
- Liskov Substitution Principle (LSP)
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from jsonschema import SchemaError, ValidationError, validate


class BaseLLMClient(ABC):
    """Abstract Base Class for LLM providers (Gemini, Groq, etc.).

    Client code (such as AIManager) interacts only with this abstract contract,
    allowing providers to be swapped polymorphically at runtime.
    """

    def __init__(
        self,
        api_key: str,
        model_name: str,
        timeout: int = 60,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("API key must be a non-empty string.")
        if not isinstance(model_name, str) or not model_name.strip():
            raise ValueError("Model name must be a non-empty string.")

        self._api_key: str = api_key.strip()
        self._model_name: str = model_name.strip()
        self._timeout: int = max(5, int(timeout))

    # -------------------------------------------------------------------------
    # Encapsulation / Properties
    # -------------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        """Return the active model name."""
        return self._model_name

    @property
    def timeout(self) -> int:
        """Return the HTTP timeout in seconds."""
        return self._timeout

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return a human-readable identifier for the LLM provider."""
        raise NotImplementedError

    # -------------------------------------------------------------------------
    # Abstract Interface Contract
    # -------------------------------------------------------------------------

    @abstractmethod
    def generate_structured_analysis(
        self,
        prompt: str,
        response_schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Send a prompt and return parsed JSON conforming to response_schema.

        Must be implemented by concrete subclasses (e.g. GeminiClient, GroqClient).
        Returns a dictionary containing the validated JSON output or an error dictionary.
        """
        raise NotImplementedError

    # -------------------------------------------------------------------------
    # Shared Helper Methods
    # -------------------------------------------------------------------------

    def validate_schema(
        self,
        data: Dict[str, Any],
        schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Validate a parsed JSON dictionary against a JSON schema.

        Raises ValueError or RuntimeError if validation fails.
        """
        if not isinstance(data, dict):
            raise ValueError(f"Expected a dictionary response, got {type(data).__name__}.")

        try:
            validate(instance=data, schema=schema)
            return data
        except ValidationError as error:
            raise ValueError(
                f"Response failed schema validation: {error.message}"
            ) from error
        except SchemaError as error:
            raise RuntimeError(
                f"The provided JSON schema is malformed: {error.message}"
            ) from error

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(provider={self.provider_name!r}, model={self._model_name!r})"
