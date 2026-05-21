"""Shared utilities for threat intelligence modules."""
import re


def strip_html(value: str) -> str:
    """Remove HTML tags, scripts, styles, and normalize whitespace."""
    value = re.sub(r"<script\b[^>]*>.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b[^>]*>.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"&quot;|&#34;", '"', value)
    value = re.sub(r"&amp;", "&", value)
    value = re.sub(r"&nbsp;|&#160;", " ", value)
    return re.sub(r"\s+", " ", value).strip()