import unittest
from unittest.mock import patch

from detector import detect_sensitive_info
from ollama_gateway import process_prompt


class SecurityFlowTests(unittest.TestCase):
    def test_contextual_secret_detection(self):
        prompt = "My API key is sk-1234567890abcdef and email john@example.com"
        detections = detect_sensitive_info(prompt)
        self.assertTrue(any(item["type"] in {"API_KEY", "EMAIL", "SECRET"} for item in detections))

    def test_process_prompt_returns_security_report_and_sanitizes_output(self):
        with patch("ollama_gateway.call_ollama", return_value="The email is john@example.com") as mock_call:
            result = process_prompt("The email is john@example.com", model="test-model", base_url="http://localhost:11434")

        self.assertIn("security_report", result)
        self.assertEqual(result["security_report"]["threat_level"], "HIGH")
        self.assertNotIn("john@example.com", result["final_response"])
        mock_call.assert_called_once()


if __name__ == "__main__":
    unittest.main()
