import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from scanners.endpoint_scanner import scan_endpoints


def create_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scan_endpoints_detects_urls_ips_and_api_paths(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    create_file(
        decompiled_path / "sources" / "com" / "example" / "LoginActivity.java",
        """
        package com.example;

        public class LoginActivity {
            String loginUrl = "http://192.168.1.10:8080/api/login";
            String usersUrl = "https://api.myapp.com/v1/users";
            String socketUrl = "ws://chat.myapp.com/socket";
            String authEndpoint = "/api/v1/auth/login";
            String adminEndpoint = "/admin/debug";
        }
        """
    )

    result = scan_endpoints(str(decompiled_path))

    findings = result["findings"]
    values = [finding["value"] for finding in findings]

    assert "http://192.168.1.10:8080/api/login" in values
    assert "192.168.1.10:8080" in values
    assert "https://api.myapp.com/v1/users" in values
    assert "ws://chat.myapp.com/socket" in values
    assert "/api/v1/auth/login" in values
    assert "/admin/debug" in values

    assert result["summary"]["total_findings"] >= 6
    assert result["summary"]["urls"] >= 3
    assert result["summary"]["ips"] >= 1
    assert result["summary"]["api_paths"] >= 2
    assert result["summary"]["critical"] >= 1
    assert result["summary"]["high"] >= 1


def test_http_login_endpoint_is_critical(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    create_file(
        decompiled_path / "sources" / "com" / "example" / "AuthService.java",
        """
        public class AuthService {
            String login = "http://api.bank.local/login";
        }
        """
    )

    result = scan_endpoints(str(decompiled_path))

    critical_findings = [
        finding for finding in result["findings"]
        if finding["severity"] == "CRITICAL"
    ]

    assert len(critical_findings) >= 1

    first_critical = critical_findings[0]

    assert first_critical["type"] == "URL"
    assert first_critical["classification"] == "VRAI_ENDPOINT"
    assert "HTTP" in first_critical["risk"] or "http" in first_critical["risk"].lower()


def test_false_positive_documentation_urls_are_low_risk(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    create_file(
        decompiled_path / "res" / "values" / "strings.xml",
        """
        <resources>
            <string name="android_schema">http://schemas.android.com/apk/res/android</string>
            <string name="doc">https://developer.android.com/reference</string>
            <string name="example">https://example.com/api/login</string>
        </resources>
        """
    )

    result = scan_endpoints(str(decompiled_path))

    false_positives = [
        finding for finding in result["findings"]
        if finding["classification"] == "FAUX_POSITIF"
    ]

    assert len(false_positives) >= 3

    for finding in false_positives:
        assert finding["severity"] == "LOW"


def test_ignored_binary_files_are_not_scanned(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    binary_file = decompiled_path / "res" / "drawable" / "image.png"
    binary_file.parent.mkdir(parents=True, exist_ok=True)
    binary_file.write_bytes(b"http://192.168.1.10:8080/api/login")

    result = scan_endpoints(str(decompiled_path))

    assert result["summary"]["total_findings"] == 0


def test_domain_detection_without_http(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    create_file(
        decompiled_path / "sources" / "com" / "example" / "Config.java",
        """
        public class Config {
            String domain = "api.production-app.com";
            String firebase = "myproject.firebaseio.com";
        }
        """
    )

    result = scan_endpoints(str(decompiled_path))

    values = [finding["value"] for finding in result["findings"]]

    assert "api.production-app.com" in values
    assert "myproject.firebaseio.com" in values

    domain_findings = [
        finding for finding in result["findings"]
        if finding["type"] == "DOMAIN"
    ]

    assert len(domain_findings) >= 2


def test_result_contains_file_line_context_and_recommendation(tmp_path):
    decompiled_path = tmp_path / "app_decompiled"

    create_file(
        decompiled_path / "sources" / "com" / "example" / "NetworkClient.java",
        """
        public class NetworkClient {
            String baseUrl = "http://10.0.2.2:5000/api/auth";
        }
        """
    )

    result = scan_endpoints(str(decompiled_path))

    finding = result["findings"][0]

    assert "type" in finding
    assert "value" in finding
    assert "file" in finding
    assert "line" in finding
    assert "context" in finding
    assert "severity" in finding
    assert "classification" in finding
    assert "risk" in finding
    assert "recommendation" in finding

    assert finding["file"].endswith("NetworkClient.java")
    assert finding["line"] > 0
    assert finding["context"] != ""
    assert finding["recommendation"] != ""