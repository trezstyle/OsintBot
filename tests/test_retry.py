"""Tests for HTTP retry/backoff utility."""
from unittest.mock import Mock, patch

import pytest
import requests

from services.retry import http_get, http_post


class TestHttpRetry:
    def test_success_first_try(self):
        mock_resp = Mock(spec=requests.Response)
        mock_resp.ok = True
        mock_resp.status_code = 200

        with patch("services.retry.requests.get", return_value=mock_resp) as mock_get:
            resp = http_get("https://example.com/api")
            assert resp is mock_resp
            assert mock_get.call_count == 1

    def test_retry_on_500(self):
        fail = Mock(spec=requests.Response)
        fail.ok = False
        fail.status_code = 500

        ok = Mock(spec=requests.Response)
        ok.ok = True
        ok.status_code = 200

        with patch("services.retry.requests.get", side_effect=[fail, ok]) as mock_get:
            resp = http_get("https://example.com/api", retries=2)
            assert resp is ok
            assert mock_get.call_count == 2

    def test_retry_on_connection_error(self):
        ok = Mock(spec=requests.Response)
        ok.ok = True
        ok.status_code = 200

        with patch(
            "services.retry.requests.get",
            side_effect=[requests.ConnectionError("reset"), ok],
        ) as mock_get:
            resp = http_get("https://example.com/api", retries=2)
            assert resp is ok
            assert mock_get.call_count == 2

    def test_no_retry_on_404(self):
        fail = Mock(spec=requests.Response)
        fail.ok = False
        fail.status_code = 404

        with patch("services.retry.requests.get", return_value=fail) as mock_get:
            resp = http_get("https://example.com/api", retries=3)
            assert resp is fail
            assert mock_get.call_count == 1  # no retry on 404

    def test_no_retry_on_401(self):
        fail = Mock(spec=requests.Response)
        fail.ok = False
        fail.status_code = 401

        with patch("services.retry.requests.get", return_value=fail) as mock_get:
            resp = http_get("https://example.com/api", retries=3)
            assert resp is fail
            assert mock_get.call_count == 1

    def test_retry_exhaustion_raises(self):
        fail = Mock(spec=requests.Response)
        fail.ok = False
        fail.status_code = 502

        with patch("services.retry.requests.get", return_value=fail) as mock_get:
            with pytest.raises(requests.HTTPError):
                http_get("https://example.com/api", retries=2, base_delay=0.01)
            assert mock_get.call_count == 3  # 1 initial + 2 retries

    def test_connection_error_exhaustion_raises(self):
        with patch(
            "services.retry.requests.get",
            side_effect=requests.ConnectionError("timeout"),
        ) as mock_get:
            with pytest.raises(requests.ConnectionError):
                http_get("https://example.com/api", retries=2, base_delay=0.01)
            assert mock_get.call_count == 3

    def test_non_retryable_request_exc(self):
        """Non-retryable request exceptions (e.g. invalid URL) should raise immediately."""
        with patch(
            "services.retry.requests.get",
            side_effect=requests.RequestException("invalid url"),
        ) as mock_get:
            with pytest.raises(requests.RequestException):
                http_get("https://example.com/api", retries=3)
            assert mock_get.call_count == 1  # no retry

    def test_post_success(self):
        mock_resp = Mock(spec=requests.Response)
        mock_resp.ok = True
        mock_resp.status_code = 200

        with patch("services.retry.requests.post", return_value=mock_resp) as mock_post:
            resp = http_post("https://example.com/api")
            assert resp is mock_resp
            assert mock_post.call_count == 1

    def test_post_retry_on_429(self):
        fail = Mock(spec=requests.Response)
        fail.ok = False
        fail.status_code = 429

        ok = Mock(spec=requests.Response)
        ok.ok = True
        ok.status_code = 200

        with patch("services.retry.requests.post", side_effect=[fail, ok]) as mock_post:
            resp = http_post("https://example.com/api", retries=2, base_delay=0.01)
            assert resp is ok
            assert mock_post.call_count == 2

    def test_timeout_retry(self):
        ok = Mock(spec=requests.Response)
        ok.ok = True
        ok.status_code = 200

        with patch(
            "services.retry.requests.get",
            side_effect=[requests.Timeout("timed out"), ok],
        ) as mock_get:
            resp = http_get("https://example.com/api", retries=2, base_delay=0.01)
            assert resp is ok
            assert mock_get.call_count == 2
