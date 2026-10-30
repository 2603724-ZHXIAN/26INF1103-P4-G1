"""Unit tests for Base Classes and Service implementations.

Verifies:
- Abstract Base Class BaseLLMClient enforces interface contract for LLM clients
- Inheritance and Polymorphism across GeminiClient, GroqClient, and Mock implementations
- VirusTotalScanner as a standalone concrete service (YAGNI principle applied)
- Encapsulation of credentials and settings
- Liskov Substitution Principle (LSP) compliance for LLM clients
- Offline execution without requiring live API keys or network
"""

import unittest
from typing import Any, Dict

from src.interfaces import BaseLLMClient
from src.services import GeminiClient, GroqClient, VirusTotalScanner


class MockLLMClient(BaseLLMClient):
    """Mock implementation used to verify polymorphic execution without live APIs."""

    def __init__(self, canned_response: Dict[str, Any]) -> None:
        super().__init__(api_key="test_key", model_name="mock-model", timeout=10)
        self.canned_response = canned_response

    @property
    def provider_name(self) -> str:
        return "Mock Provider"

    def generate_structured_analysis(
        self, prompt: str, response_schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self.validate_schema(self.canned_response, response_schema)


class TestBaseLLMClientInterface(unittest.TestCase):
    """Test BaseLLMClient contract enforcement and ABC mechanics."""

    def test_abstract_class_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            BaseLLMClient(api_key="key", model_name="model")

    def test_concrete_mock_satisfies_contract(self):
        canned = {"threat_detected": True, "score": 85}
        client: BaseLLMClient = MockLLMClient(canned_response=canned)
        self.assertEqual(client.provider_name, "Mock Provider")
        self.assertEqual(client.model_name, "mock-model")

        schema = {
            "type": "object",
            "properties": {
                "threat_detected": {"type": "boolean"},
                "score": {"type": "integer"},
            },
            "required": ["threat_detected", "score"],
        }
        res = client.generate_structured_analysis("analyze this", schema)
        self.assertTrue(res["threat_detected"])
        self.assertEqual(res["score"], 85)

    def test_empty_api_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            GeminiClient(api_key="")
        with self.assertRaises(ValueError):
            GroqClient(api_key="   ")


class TestGeminiClient(unittest.TestCase):
    """Test GeminiClient concrete implementation of BaseLLMClient."""

    def test_inheritance_and_properties(self):
        client = GeminiClient(
            api_key="test_gemini_key",
            model_name="gemini-2.5-flash",
            timeout=25,
        )
        self.assertIsInstance(client, BaseLLMClient)
        self.assertEqual(client.provider_name, "Google Gemini")
        self.assertEqual(client.model_name, "gemini-2.5-flash")
        self.assertEqual(client.timeout, 25)

    def test_polymorphic_assignment(self):
        client: BaseLLMClient = GeminiClient(api_key="test_key")
        self.assertTrue(hasattr(client, "generate_structured_analysis"))
        self.assertTrue(hasattr(client, "validate_schema"))


class TestGroqClient(unittest.TestCase):
    """Test GroqClient concrete implementation of BaseLLMClient."""

    def test_inheritance_and_properties(self):
        client = GroqClient(
            api_key="test_groq_key",
            model_name="openai/gpt-oss-120b",
            timeout=40,
        )
        self.assertIsInstance(client, BaseLLMClient)
        self.assertEqual(client.provider_name, "Groq Cloud")
        self.assertEqual(client.model_name, "openai/gpt-oss-120b")
        self.assertEqual(client.timeout, 40)

    def test_schema_strictness_transformation(self):
        client = GroqClient(api_key="test_key")
        schema = {
            "type": "object",
            "properties": {
                "score": {"type": "integer"},
                "details": {
                    "type": "object",
                    "properties": {"flag": {"type": "string"}},
                },
            },
        }
        strict = client._make_schema_strict(schema)
        self.assertFalse(strict["additionalProperties"])
        self.assertIn("score", strict["required"])
        self.assertFalse(strict["properties"]["details"]["additionalProperties"])
        self.assertIn("flag", strict["properties"]["details"]["required"])


class TestVirusTotalScanner(unittest.TestCase):
    """Test VirusTotalScanner as a standalone concrete service (YAGNI principle)."""

    def test_virustotal_scanner_properties_and_hash(self):
        vt = VirusTotalScanner(api_key="test_vt_key")
        self.assertTrue(vt.is_available())

        # Test hash validator
        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertTrue(vt.is_supported_hash(valid_sha256))
        self.assertFalse(vt.is_supported_hash("not_a_hash"))

        # Test report URL generator
        url = vt.get_report_url("file", valid_sha256)
        self.assertEqual(url, f"https://www.virustotal.com/gui/file/{valid_sha256}")
        url_web = vt.get_report_url("url", "some_id")
        self.assertEqual(url_web, "https://www.virustotal.com/gui/url/some_id")

    def test_scanner_unconfigured_key_returns_error(self):
        vt_empty = VirusTotalScanner(api_key="")
        self.assertFalse(vt_empty.is_available())
        res = vt_empty.scan_resource("url", "https://example.com")
        self.assertIn("error", res)
        self.assertEqual(res.get("error_type"), "configuration_error")

    def test_scanner_invalid_resource_type_returns_error(self):
        vt = VirusTotalScanner(api_key="valid_key")
        res = vt.scan_resource("invalid_type", "target")
        self.assertIn("error", res)
        self.assertEqual(res.get("error_type"), "validation_error")


if __name__ == "__main__":
    unittest.main()
