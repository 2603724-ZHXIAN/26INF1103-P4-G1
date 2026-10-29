"""GroqClient service implementation.

Concrete subclass of BaseLLMClient providing Groq Cloud API integration,
strict schema adaptation, and high-speed alternative LLM execution.
Demonstrates:
- Liskov Substitution Principle (LSP): Substituted seamlessly in place of GeminiClient
- Polymorphism: Implements generate_structured_analysis from BaseLLMClient
"""

import copy
import json
import logging
from typing import Any, Dict

import requests

from ..interfaces.llm_client import BaseLLMClient

LOGGER = logging.getLogger(__name__)


class GroqClient(BaseLLMClient):
    """Groq API client implementing BaseLLMClient."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "openai/gpt-oss-120b",
        timeout: int = 60,
    ) -> None:
        super().__init__(api_key=api_key, model_name=model_name, timeout=timeout)
        self._endpoint: str = "https://api.groq.com/openai/v1/chat/completions"

    @property
    def provider_name(self) -> str:
        return "Groq Cloud"

    def _make_schema_strict(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively enforce Groq strict JSON schema requirements."""
        if not isinstance(schema, dict):
            return schema

        strict_schema = copy.deepcopy(schema)

        if strict_schema.get("type") == "object":
            strict_schema["additionalProperties"] = False
            properties = strict_schema.get("properties", {})
            if properties:
                strict_schema["required"] = list(properties.keys())
                for key, prop in properties.items():
                    properties[key] = self._make_schema_strict(prop)

        elif strict_schema.get("type") == "array":
            items = strict_schema.get("items")
            if items:
                strict_schema["items"] = self._make_schema_strict(items)

        return strict_schema

    def generate_structured_analysis(
        self,
        prompt: str,
        response_schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Send prompt to Groq requesting structured output conforming to schema."""
        strict_schema = self._make_schema_strict(response_schema)

        json_prompt = (
            f"{prompt}\n\n"
            f"You must return ONLY valid JSON matching this exact JSON schema:\n"
            f"{json.dumps(strict_schema)}\n"
            f"Do NOT wrap the JSON in markdown fences or add extra text."
        )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "model": self._model_name,
            "messages": [{"role": "user", "content": json_prompt}],
            "temperature": 0.1,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "structured_output",
                    "schema": strict_schema,
                    "strict": True,
                },
            },
        }

        try:
            response = requests.post(
                self._endpoint,
                headers=headers,
                json=payload,
                timeout=self._timeout,
            )

            if response.status_code != 200:
                LOGGER.error("Groq HTTP %s: %s", response.status_code, response.text)
                return {
                    "error": f"Groq returned HTTP {response.status_code}",
                    "details": response.text[:1000],
                }

            data = response.json()
            raw_content = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw_content)

            return self.validate_schema(parsed, response_schema)

        except requests.exceptions.Timeout:
            return {"error": "Groq request timed out."}
        except requests.exceptions.RequestException as exc:
            return {"error": f"Groq network error: {exc}"}
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            return {
                "error": "Failed to parse structured response from Groq.",
                "details": str(exc),
            }
        except (ValueError, RuntimeError) as exc:
            return {
                "error": f"Schema validation failed: {exc}",
                "details": str(exc),
            }
