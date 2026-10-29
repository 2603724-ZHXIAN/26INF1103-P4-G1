"""Unit tests for Base Classes and Service implementations.

Verifies:
- Abstract Base Classes (BaseLLMClient, IThreatScanner) enforce interface contracts
- Inheritance and Polymorphism across GeminiClient, GroqClient, and Mock implementations
- Encapsulation of credentials and settings
- Liskov Substitution Principle (LSP) compliance
- Offline execution without requiring live API keys or network
"""

import unittest
from typing import Any, Dict

from src.interfaces import BaseLLMClient, IThreatScanner
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


class MockThreatScanner(IThreatScanner):
    """Mock scanner used to verify IThreatScanner interface contract."""

    def scan_resource(self, resource_type: str, resource_identifier: str) -> Dict[str, Any]:
        return {
            "resource_type": resource_type,
            "resource_identifier": resource_identifier,
            "parsed_result": {
                "detection_stats": {"malicious": 5, "total": 70, "detection_ratio": 7.14}
            },
        }

    def get_report_url(self, resource_type: str, resource_id: str) -> str:
        return f"https://mockscanner.test/{resource_type}/{resource_id}"

    def is_available(self) -> bool:
        return True


class TestBaseLLMClient(unittest.TestCase):
    """Test BaseLLMClient contract and abstraction."""

    def test_abc_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            BaseLLMClient(api_key="key", model_name="model")

    def test_mock_client_implements_contract_polymorphically(self):
        canned = {"classification": "scam", "confidence": "high"}
        schema = {
            "type": "object",
            "properties": {
                "classification": {"type": "string"},
                "confidence": {"type": "string"},
            },
            "required": ["classification", "confidence"],
        }

        client: BaseLLMClient = MockLLMClient(canned_response=canned)
        self.assertEqual(client.provider_name, "Mock Provider")
        self.assertEqual(client.model_name, "mock-model")

        result = client.generate_structured_analysis("Check this text", schema)
        self.assertEqual(result["classification"], "scam")

    def test_schema_validation_rejects_missing_fields(self):
        canned = {"classification": "scam"}  # missing "confidence"
        schema = {
            "type": "object",
            "properties": {
                "classification": {"type": "string"},
                "confidence": {"type": "string"},
            },
            "required": ["classification", "confidence"],
        }
        client = MockLLMClient(canned_response=canned)
        with self.assertRaises(ValueError):
            client.generate_structured_analysis("Check text", schema)


class TestConcreteLLMClients(unittest.TestCase):
    """Test GeminiClient and GroqClient inheritance, encapsulation, and properties."""

    def test_gemini_client_properties(self):
        client = GeminiClient(api_key="test_gemini_key", model_name="gemini-3.5-flash")
        self.assertIsInstance(client, BaseLLMClient)
        self.assertEqual(client.provider_name, "Google Gemini")
        self.assertEqual(client.model_name, "gemini-3.5-flash")
        self.assertEqual(client.max_retries, 5)

    def test_groq_client_properties_and_strict_schema(self):
        client = GroqClient(api_key="test_groq_key", model_name="openai/gpt-oss-120b")
        self.assertIsInstance(client, BaseLLMClient)
        self.assertEqual(client.provider_name, "Groq Cloud")

        # Test Groq strict schema conversion
        schema = {
            "type": "object",
            "properties": {
                "score": {"type": "integer"},
                "details": {
                    "type": "object",
                    "properties": {"flag": {"type": "boolean"}},
                },
            },
        }
        strict = client._make_schema_strict(schema)
        self.assertFalse(strict["additionalProperties"])
        self.assertIn("score", strict["required"])
        self.assertFalse(strict["properties"]["details"]["additionalProperties"])
        self.assertIn("flag", strict["properties"]["details"]["required"])


class TestIThreatScanner(unittest.TestCase):
    """Test IThreatScanner interface and VirusTotalScanner implementation."""

    def test_scanner_interface_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            IThreatScanner()

    def test_mock_threat_scanner_satisfies_interface(self):
        scanner: IThreatScanner = MockThreatScanner()
        self.assertTrue(scanner.is_available())
        res = scanner.scan_resource("url", "https://suspicious.site")
        self.assertEqual(res["parsed_result"]["detection_stats"]["malicious"], 5)
        self.assertEqual(
            scanner.get_report_url("url", "abc"),
            "https://mockscanner.test/url/abc",
        )

    def test_virustotal_scanner_properties_and_hash(self):
        vt = VirusTotalScanner(api_key="test_vt_key")
        self.assertIsInstance(vt, IThreatScanner)
        self.assertTrue(vt.is_available())

        # Test hash validator
        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertTrue(vt.is_supported_hash(valid_sha256))
        self.assertFalse(vt.is_supported_hash("not_a_hash"))

        # Test report URL generator
        url = vt.get_report_url("file", valid_sha256)
        self.assertEqual(url, f"https://www.virustotal.com/gui/file/{valid_sha256}")


if __name__ == "__main__":
    unittest.main()
