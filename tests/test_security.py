"""Tests for security module."""
import pytest
from security import validate_ip, validate_domain, validate_hostname, validate_package_name
from security import is_authorized, ALLOWED_USERS, ALLOWED_CHATS, AUTH_CONFIGURED


class TestValidateIP:
    @pytest.mark.parametrize("ip,expected", [
        ("192.168.1.1", "192.168.1.1"),
        ("8.8.8.8", "8.8.8.8"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
        (" 10.0.0.1 ", "10.0.0.1"),
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("256.1.1.1", None),
        ("-1.0.0.0", None),
        ("not.an.ip", None),
        ("", None),
        ("   ", None),
        ("300.300.300.300", None),
        ("abc.def.ghi.jkl", None),
    ])
    def test_validate_ip(self, ip, expected):
        assert validate_ip(ip) == expected


class TestValidateDomain:
    @pytest.mark.parametrize("domain,expected", [
        ("example.com", "example.com"),
        ("sub.domain.org", "sub.domain.org"),
        ("my-host.com", "my-host.com"),
        ("localhost.localdomain", "localhost.localdomain"),
        ("a.co", "a.co"),
        (" EXAMPLE.COM ", "example.com"),
        ("-bad.com", None),
        ("bad-.com", None),
        ("a" * 254 + ".com", None),
        ("", None),
        ("   ", None),
        (".com", None),
        ("a..b.com", None),
        ("spaces in domain.com", None),
    ])
    def test_validate_domain(self, domain, expected):
        assert validate_domain(domain) == expected


class TestValidateHostname:
    @pytest.mark.parametrize("host,expected", [
        ("192.168.1.1", "192.168.1.1"),
        ("example.com", "example.com"),
        ("::1", "::1"),
        ("invalid", None),
    ])
    def test_validate_hostname(self, host, expected):
        assert validate_hostname(host) == expected


class TestValidatePackageName:
    @pytest.mark.parametrize("pkg,expected", [
        ("openssl", "openssl"),
        ("libc6", "libc6"),
        ("python3.12", "python3.12"),
        ("libstdc++6", "libstdc++6"),
        (" OPENSSL ", "openssl"),
        ("-rf", None),
        ("../etc", None),
        ("rm -rf", None),
        ("a" * 129, None),
        ("", None),
    ])
    def test_validate_package_name(self, pkg, expected):
        assert validate_package_name(pkg) == expected


class TestIsAuthorized:
    def test_no_auth_configured(self):
        """When no ALLOWED_USERS/ALLOWED_CHATS configured, reject all."""
        assert is_authorized(123, 456) is False

    def test_user_in_allowed(self):
        ALLOWED_USERS.append(42)
        try:
            assert is_authorized(42, 999) is True
        finally:
            ALLOWED_USERS.clear()

    def test_chat_in_allowed(self):
        ALLOWED_CHATS.append(-100)
        try:
            assert is_authorized(999, -100) is True
        finally:
            ALLOWED_CHATS.clear()

    def test_user_not_in_allowed(self):
        ALLOWED_USERS.append(42)
        try:
            assert is_authorized(99, 0) is False
        finally:
            ALLOWED_USERS.clear()
