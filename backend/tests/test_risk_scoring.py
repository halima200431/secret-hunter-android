import unittest

from backend.scanners.risk_scoring import (
    calculate_secret_score,
    calculate_endpoint_score,
    get_risk_level,
    apply_risk_scoring,
)


class TestRiskScoring(unittest.TestCase):
    def test_password_is_critical(self):
        secret = {
            "type": "Password",
            "maskedValue": "admin********",
            "file": "res/values/strings.xml",
            "line": 12,
        }

        score = calculate_secret_score(secret)

        self.assertGreaterEqual(score, 86)
        self.assertEqual(get_risk_level(score), "Critical")

    def test_bearer_token_is_critical(self):
        secret = {
            "type": "Bearer Token",
            "maskedValue": "Bearer eyJ********",
            "file": "AuthManager.java",
            "line": 41,
        }

        score = calculate_secret_score(secret)

        self.assertGreaterEqual(score, 86)
        self.assertEqual(get_risk_level(score), "Critical")

    def test_http_admin_endpoint_is_high_or_critical(self):
        endpoint = {
            "url": "http://192.168.1.10:5000/admin",
            "type": "Admin Endpoint",
            "protocol": "HTTP",
            "file": "ApiClient.java",
            "line": 18,
        }

        score = calculate_endpoint_score(endpoint)

        self.assertGreaterEqual(score, 75)
        self.assertIn(get_risk_level(score), ["High", "Critical"])

    def test_global_score_result_structure(self):
        result = apply_risk_scoring(
            apk_name="demo.apk",
            files_analyzed=100,
            secrets=[
                {
                    "type": "API Key",
                    "maskedValue": "AIzaSyFak********",
                    "file": "Config.java",
                    "line": 24,
                }
            ],
            endpoints=[
                {
                    "url": "https://api.example.com/login",
                    "type": "API Login",
                    "protocol": "HTTPS",
                    "file": "NetworkService.java",
                    "line": 33,
                }
            ],
        )

        self.assertIn("globalScore", result)
        self.assertIn("globalRisk", result)
        self.assertIn("secrets", result)
        self.assertIn("endpoints", result)
        self.assertEqual(result["secretsCount"], 1)
        self.assertEqual(result["endpointsCount"], 1)


if __name__ == "__main__":
    unittest.main()