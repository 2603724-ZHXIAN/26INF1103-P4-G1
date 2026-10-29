"""GeminiClient service implementation.

Concrete subclass of BaseLLMClient providing Google Gemini API communication,
structured JSON schema enforcement, exponential retry backoff, and Google Search grounding.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from ..interfaces.llm_client import BaseLLMClient

LOGGER = logging.getLogger(__name__)


class GeminiClient(BaseLLMClient):
    """Google Gemini API client implementing BaseLLMClient."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-flash",
        timeout: int = 60,
        max_retries: int = 5,
    ) -> None:
        super().__init__(api_key=api_key, model_name=model_name, timeout=timeout)
        self._max_retries: int = max(1, int(max_retries))
        self._endpoint: str = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self._model_name}:generateContent"
        )

    @property
    def provider_name(self) -> str:
        return "Google Gemini"

    @property
    def max_retries(self) -> int:
        return self._max_retries

    def generate_structured_analysis(
        self,
        prompt: str,
        response_schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Send prompt to Gemini requesting strictly structured JSON output."""
        request_body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
                "responseJsonSchema": response_schema,
            },
        }

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self._api_key,
        }

        last_error = None

        for attempt in range(1, self._max_retries + 1):
            try:
                response = requests.post(
                    self._endpoint,
                    headers=headers,
                    json=request_body,
                    timeout=self._timeout,
                )

                if response.status_code == 200:
                    data = response.json()
                    raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                    parsed = json.loads(raw_text)
                    return self.validate_schema(parsed, response_schema)

                if response.status_code in {429, 500, 503, 504}:
                    delay = 2 ** attempt
                    LOGGER.warning(
                        "Gemini returned HTTP %s on attempt %s. Retrying in %ss...",
                        response.status_code,
                        attempt,
                        delay,
                    )
                    time.sleep(delay)
                    continue

                return {
                    "error": f"Gemini returned HTTP {response.status_code}",
                    "details": response.text[:1000],
                }

            except requests.exceptions.Timeout:
                last_error = "Gemini request timed out."
                LOGGER.warning("Gemini timeout on attempt %s", attempt)
            except requests.exceptions.RequestException as exc:
                last_error = f"Gemini network error: {exc}"
                LOGGER.warning("Gemini network error on attempt %s: %s", attempt, exc)
            except (json.JSONDecodeError, KeyError, IndexError) as exc:
                return {
                    "error": "Failed to parse structured response from Gemini.",
                    "details": str(exc),
                }
            except (ValueError, RuntimeError) as exc:
                return {
                    "error": f"Schema validation failed: {exc}",
                    "details": str(exc),
                }

            time.sleep(1)

        return {
            "error": "Gemini API unavailable after multiple retries.",
            "details": str(last_error),
        }

    def fetch_threat_radar(self, topic: Optional[str] = None) -> Dict[str, Any]:
        """Query live threat intelligence using Gemini with Google Search grounding."""
        time_context = "this month in 2026 / recent weeks"
        focus_target = (
            f"specifically focusing on: '{topic}'"
            if topic
            else "covering the top emerging consumer and enterprise scam campaigns"
        )
        prompt = (
            f"You are a Cyber Threat Intelligence Analyst for an educational cybersecurity engine.\n"
            f"Use the Google Search tool to search for the most recent, active scams, phishing campaigns, "
            f"and malware delivery trends reported {time_context}, {focus_target}.\n"
            f"Return your response in clean, structured Markdown covering Threat Overview, Tactics, Red Flags, "
            f"Real-World Examples, and Actionable Defense Guidance."
        )

        # Primary: Official Google GenAI SDK if installed
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self._api_key)
            response = client.models.generate_content(
                model=self._model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                ),
            )

            sources: List[Dict[str, str]] = []
            queries: List[str] = []

            try:
                candidate = response.candidates[0]
                metadata = getattr(candidate, "grounding_metadata", None)
                if metadata:
                    if getattr(metadata, "web_search_queries", None):
                        queries = list(metadata.web_search_queries)
                    for chunk in getattr(metadata, "grounding_chunks", []) or []:
                        web = getattr(chunk, "web", None)
                        if web and getattr(web, "uri", None):
                            sources.append({
                                "title": getattr(web, "title", "Threat Advisory"),
                                "url": getattr(web, "uri", ""),
                            })
            except Exception as meta_err:
                LOGGER.warning("Could not extract grounding metadata: %s", meta_err)

            return {
                "content": response.text,
                "sources": sources,
                "search_queries": queries,
                "model_name": self._model_name,
            }

        except Exception as sdk_err:
            LOGGER.warning("Google GenAI SDK failed (%s). Falling back to REST...", sdk_err)

        # Fallback: Direct REST call with search tools
        try:
            body = {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "tools": [{"google_search": {}}],
                "generationConfig": {"temperature": 0.3},
            }
            res = requests.post(
                self._endpoint,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": self._api_key,
                },
                json=body,
                timeout=self._timeout,
            )
            res.raise_for_status()
            data = res.json()
            cand = data["candidates"][0]
            content = cand["content"]["parts"][0]["text"]
            meta = cand.get("groundingMetadata", {})
            sources = [
                {"title": c.get("web", {}).get("title", "Threat Advisory"), "url": c.get("web", {}).get("uri", "")}
                for c in meta.get("groundingChunks", [])
                if c.get("web", {}).get("uri")
            ]
            return {
                "content": content,
                "sources": sources,
                "search_queries": meta.get("webSearchQueries", []),
                "model_name": self._model_name,
            }
        except Exception as rest_err:
            return {
                "error": "Failed to fetch threat radar from Gemini.",
                "details": str(rest_err),
            }
