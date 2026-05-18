"""Retry/backoff utilities for external HTTP API calls."""
import logging
import random
import time
from typing import Any, Optional

import requests

log = logging.getLogger("cyber_volt.retry")

_TRANSIENT_STATUS = {429, 500, 502, 503, 504}

_RETRYABLE_EXC = (
    requests.ConnectionError,
    requests.Timeout,
    ConnectionError,
    TimeoutError,
)


def _should_retry(exc: Optional[Exception], status_code: Optional[int]) -> bool:
    """Return True if the error is transient and worth retrying."""
    if status_code is not None and status_code in _TRANSIENT_STATUS:
        return True
    if exc is not None:
        if isinstance(exc, _RETRYABLE_EXC):
            return True
        if isinstance(exc, requests.RequestException) and exc.response is None:
            return True
    return False


def _do_request(method: str, url: str, **kwargs) -> requests.Response:
    if method == "GET":
        return requests.get(url, **kwargs)
    return requests.post(url, **kwargs)


def _request_with_retry(
    method: str,
    url: str,
    *,
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> requests.Response:
    """Make an HTTP request with exponential backoff retry.

    Retries only on transient errors (connection, timeout, 5xx, 429).
    Raises the last exception if all retries are exhausted.
    """
    log_ = logger or log
    last_exc: Optional[Exception] = None
    last_status: Optional[int] = None

    for attempt in range(1 + retries):
        try:
            resp = _do_request(method, url, **kwargs)
            if resp.ok:
                return resp
            if not _should_retry(None, resp.status_code):
                return resp
            last_status = resp.status_code
            log_.warning(
                "HTTP %s %s (attempt %d/%d)",
                resp.status_code, url[:80], attempt + 1, 1 + retries,
            )
        except _RETRYABLE_EXC as exc:
            last_exc = exc
            log_.warning(
                "%s %s (attempt %d/%d): %s",
                type(exc).__name__, url[:80], attempt + 1, 1 + retries, exc,
            )
        except requests.RequestException as exc:
            # Non-retryable — raise immediately
            raise

        if attempt < retries:
            delay = min(base_delay * (2 ** attempt) + random.random(), max_delay)
            time.sleep(delay)

    if last_status is not None:
        raise requests.HTTPError(
            f"HTTP {last_status} after {retries} retries: {url[:80]}",
        )
    raise last_exc  # type: ignore[misc]


def http_get(
    url: str,
    *,
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> requests.Response:
    """GET request with exponential backoff retry."""
    return _request_with_retry(
        "GET", url, retries=retries, base_delay=base_delay,
        max_delay=max_delay, logger=logger, **kwargs,
    )


def http_post(
    url: str,
    *,
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> requests.Response:
    """POST request with exponential backoff retry."""
    return _request_with_retry(
        "POST", url, retries=retries, base_delay=base_delay,
        max_delay=max_delay, logger=logger, **kwargs,
    )
