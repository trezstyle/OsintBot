"""Tests for uncovered threat_intel functions: get_vt_report, check_urlscan, rep, mitre."""
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from services.threat_intel.vt import check_urlscan, get_vt_report
from services.threat_intel.reputation import (
    check_blacklist,
    check_ctlogs,
    check_http_headers,
    check_proxy,
    check_ssl,
    check_tor,
    get_abuseipdb_report,
    get_subdomains,
    get_whois,
    save_to_log,
)
from services.threat_intel.mitre import attack_simulation


# ── VT: get_vt_report ──


class TestGetVtReport:
    def test_no_api_key(self):
        result = get_vt_report("8.8.8.8")
        assert "No API key" in result

    @patch("services.threat_intel.vt.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("down")

        mock_settings = Mock()
        mock_settings.api.vt_api_key = "key"
        with patch("services.threat_intel.vt.settings", mock_settings):
            result = get_vt_report("8.8.8.8")
            assert "down" in result.lower() or "VT" in result


# ── VT: check_urlscan ──


class TestCheckUrlscan:
    def test_no_api_key(self):
        result = check_urlscan("https://example.com")
        assert "No API key" in result

    @patch("services.threat_intel.vt.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.post.side_effect = requests.ConnectionError("down")

        mock_settings = Mock()
        mock_settings.api.vt_api_key = "key"
        with patch("services.threat_intel.vt.settings", mock_settings):
            result = check_urlscan("https://example.com")
            assert "down" in result.lower() or "error" in result.lower()


# ── Reputation: get_abuseipdb_report ──


class TestGetAbuseipdbReport:
    def test_no_api_key(self):
        result = get_abuseipdb_report("8.8.8.8")
        assert "No API key" in result

    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("down")

        mock_settings = Mock()
        mock_settings.api.abuse_api_key = "key"
        with patch("services.threat_intel.reputation.settings", mock_settings):
            result = get_abuseipdb_report("8.8.8.8")
            assert "down" in result.lower() or "error" in result.lower()


# ── Reputation: get_whois ──


class TestGetWhois:
    @patch("services.threat_intel.reputation.subprocess.run")
    def test_whois_error(self, mock_run):
        mock_run.side_effect = FileNotFoundError("whois not found")
        result = get_whois("example.com")
        assert "whois" in result.lower()


# ── Reputation: get_subdomains ──


@patch("services.threat_intel.reputation.get_http")
class TestGetSubdomains:
    def test_crt_sh_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("crt.sh down")
        result = get_subdomains("example.com")
        assert "down" in result.lower() or "failed" in result.lower()


class TestCheckSsl:
    @patch("services.threat_intel.reputation.ssl.get_server_certificate")
    def test_connection_failure(self, mock_cert):
        mock_cert.side_effect = Exception("cert error")
        result = check_ssl("example.com")
        assert "error" in result.lower() or "SSL" in result


# ── Reputation: check_http_headers ──


class TestCheckHttpHeaders:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("down")
        result = check_http_headers("example.com")
        assert "failed" in result.lower() or "down" in result.lower()


# ── Reputation: check_blacklist ──


class TestCheckBlacklist:
    def test_makes_real_dns_queries(self):
        result = check_blacklist("8.8.8.8")
        assert isinstance(result, str)
        assert len(result) > 10


# ── Reputation: check_tor ──


class TestCheckTor:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("tor down")
        result = check_tor("8.8.8.8")
        assert "failed" in result.lower() or "tor" in result.lower()


# ── Reputation: check_proxy ──


class TestCheckProxy:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("proxy down")
        result = check_proxy("8.8.8.8")
        assert "failed" in result.lower()


# ── Reputation: check_ctlogs ──


class TestCheckCtlogs:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("ct down")
        result = check_ctlogs("example.com")
        assert "failed" in result.lower()


# ── Reputation: check_blacklist ──


class TestCheckBlacklist:
    def test_smoke(self):
        result = check_blacklist("8.8.8.8")
        assert isinstance(result, str)
        assert len(result) > 10


# ── Reputation: check_tor ──


class TestCheckTor:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("tor down")
        result = check_tor("8.8.8.8")
        assert "failed" in result.lower() or "tor" in result.lower()


# ── Reputation: check_proxy ──


class TestCheckProxy:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("proxy down")
        result = check_proxy("8.8.8.8")
        assert "failed" in result.lower()


# ── Reputation: check_ctlogs ──


class TestCheckCtlogs:
    @patch("services.threat_intel.reputation.get_http")
    def test_connection_error(self, mock_get_http):
        mock_session = MagicMock()
        mock_get_http.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("ct down")
        result = check_ctlogs("example.com")
        assert "failed" in result.lower()


# ── Reputation: save_to_log (smoke test, can't fully test side effects) ──


class TestSaveToLog:
    def test_does_not_raise(self):
        save_to_log("8.8.8.8", "Test log entry")


# ── MITRE: attack_simulation ──


class TestAttackSimulation:
    def test_unknown_tid(self):
        result = attack_simulation("T999999")
        assert "not found" in result.lower()

    def test_no_prefix(self):
        result = attack_simulation("999999")
        assert "not found" in result.lower()
