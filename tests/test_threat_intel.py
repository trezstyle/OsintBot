"""Tests for threat_intel submodules."""
from unittest.mock import Mock, patch

import pytest
import requests

from services.threat_intel.reputation import _is_ipv4, _strip_html, get_geoip
from services.threat_intel.vt import check_hash
from services.threat_intel.mitre import mitre_lookup
from services.threat_intel.osint import check_hibp, check_phone, check_email, _dig_txt, _has_mx


# ── reputation helpers ──


class TestIsIpv4:
    def test_valid(self):
        assert _is_ipv4("192.168.1.1") is True
        assert _is_ipv4("8.8.8.8") is True
        assert _is_ipv4("0.0.0.0") is True
        assert _is_ipv4("255.255.255.255") is True

    def test_invalid(self):
        assert _is_ipv4("256.1.1.1") is False
        assert _is_ipv4("not.an.ip") is False
        assert _is_ipv4("") is False
        assert _is_ipv4("::1") is False
        assert _is_ipv4("-1.0.0.0") is False


class TestStripHtml:
    def test_remove_tags(self):
        assert _strip_html("<b>hello</b>") == "hello"
        assert _strip_html("<p>text</p>") == "text"

    def test_remove_scripts(self):
        assert _strip_html("<script>alert(1)</script>body") == "body"

    def test_remove_styles(self):
        assert _strip_html("<style>.c{}</style>body") == "body"

    def test_decode_entities(self):
        assert _strip_html("&amp;") == "&"
        assert _strip_html("&quot;") == '"'

    def test_collapse_spaces(self):
        assert _strip_html("a    b") == "a b"
        assert _strip_html("a\n  b") == "a b"

    def test_empty(self):
        assert _strip_html("") == ""
        assert _strip_html("<br/>") == ""


class TestGetGeoip:
    def test_success(self):
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
        }

        with patch("services.threat_intel.reputation.requests.get", return_value=mock_resp):
            result = get_geoip("8.8.8.8")
            assert "Mountain View" in result
            assert "Google" in result
            assert "GeoIP" in result

    def test_http_error(self):
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 429

        with patch("services.threat_intel.reputation.requests.get", return_value=mock_resp):
            result = get_geoip("8.8.8.8")
            assert result == "GeoIP: N/A"

    def test_timeout(self):
        with patch(
            "services.threat_intel.reputation.requests.get",
            side_effect=requests.Timeout("timed out"),
        ):
            result = get_geoip("8.8.8.8")
            assert result == "GeoIP: N/A"

    def test_connection_error(self):
        with patch(
            "services.threat_intel.reputation.requests.get",
            side_effect=requests.ConnectionError("reset"),
        ):
            result = get_geoip("8.8.8.8")
            assert result == "GeoIP: N/A"


# ── VT hash check ──


class TestCheckHash:
    def test_invalid_md5_too_short(self):
        result = check_hash("abc")
        assert "Invalid hash format" in result

    def test_invalid_md5_wrong_chars(self):
        result = check_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
        assert "Invalid hash format" in result

    def test_invalid_sha1_wrong_length(self):
        result = check_hash("a" * 41)
        assert "Invalid hash format" in result

    def test_invalid_empty(self):
        result = check_hash("")
        assert "Invalid hash format" in result

    def test_valid_md5_no_api_key(self):
        result = check_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert "No API key" in result

    def test_valid_sha256_no_api_key(self):
        result = check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert "No API key" in result

    def test_api_error_handled(self):
        mock_settings = Mock()
        mock_settings.api.vt_api_key = "test-key"
        with patch("services.threat_intel.vt.settings", mock_settings):
            with patch(
                "services.threat_intel.vt.requests.get",
                side_effect=requests.ConnectionError("API down"),
            ):
                result = check_hash("d41d8cd98f00b204e9800998ecf8427e")
                assert "failed" in result.lower() or "check" in result.lower()


# ── MITRE lookup ──


class TestMitreLookup:
    def test_tid_formats(self):
        """Various TID formats should be normalized."""
        result = mitre_lookup("T999999")  # non-existent
        assert "not found" in result

    def test_no_prefix(self):
        """Without 'T' prefix should still work."""
        result = mitre_lookup("999999")
        assert "not found" in result

    def test_empty(self):
        result = mitre_lookup("")
        assert "not found" in result

    def test_lowercase(self):
        result = mitre_lookup("t999999")
        assert "not found" in result


# ── HIBP ──


class TestCheckHibp:
    def test_no_api_key(self):
        result = check_hibp("test@example.com")
        assert "No API key" in result

    def test_name_prefix(self):
        """name: prefix should work for breach detail lookup."""
        mock_settings = Mock()
        mock_settings.api.hibp_api_key = "test-key"
        with patch("services.threat_intel.osint.settings", mock_settings):
            with patch(
                "services.threat_intel.osint.requests.get",
                side_effect=requests.ConnectionError("API unreachable"),
            ):
                result = check_hibp("name:Adobe")
                assert "failed" in result.lower() or "HIBP" in result


# ── Phone OSINT ──


class TestCheckPhone:
    def test_empty(self):
        result = check_phone("")
        assert "failed" in result.lower()

    def test_invalid_number(self):
        result = check_phone("not-a-phone")
        assert "failed" in result.lower() or "Invalid" in result


# ── Email OSINT ──


class TestCheckEmail:
    def test_invalid_format(self):
        result = check_email("not-an-email")
        assert "Invalid email" in result

    def test_no_mx(self):
        """An email with a clearly non-existent domain should fail gracefully."""
        result = check_email("test@thq9x7k2z1.example.com")
        assert isinstance(result, str)
