import pytest
from pydantic import ValidationError

from config import ProxyParser


def test_valid_proxy_without_auth():
    proxy = ProxyParser(url="http://proxy.example.com:8080")
    assert proxy.protocol == "http"
    assert proxy.server == "proxy.example.com"
    assert proxy.port == 8080
    assert proxy.username is None
    assert proxy.password is None


def test_valid_proxy_with_auth():
    proxy = ProxyParser(url="https://user:pass@proxy.example.com:8443")
    assert proxy.protocol == "https"
    assert proxy.server == "proxy.example.com"
    assert proxy.port == 8443
    assert proxy.username == "user"
    assert proxy.password == "pass"


def test_http_proxy_without_port():
    proxy = ProxyParser(url="http://proxy.example.com")
    assert proxy.protocol == "http"
    assert proxy.server == "proxy.example.com"
    assert proxy.port == 80  # The default port should be substituted


def test_https_proxy_without_port():
    proxy = ProxyParser(url="https://proxy.example.com")
    assert proxy.protocol == "https"
    assert proxy.server == "proxy.example.com"
    assert proxy.port == 443  # The default port should be substituted


def test_proxy_invalid_protocol():
    with pytest.raises(ValidationError, match="URL must start with http:// or https://"):
        ProxyParser(url="ftp://proxy.example.com:8080")


def test_proxy_missing_server():
    with pytest.raises(ValidationError, match="SERVER must be specified"):
        ProxyParser(url="http://:8080")


def test_proxy_with_username_without_password():
    with pytest.raises(ValidationError, match="PASSWORD must be provided if USERNAME is set"):
        ProxyParser(url="http://user@proxy.example.com:8080")


def test_proxy_with_password_without_username():
    with pytest.raises(ValidationError, match="USERNAME must be provided if PASSWORD is set"):
        ProxyParser(url="http://:pass@proxy.example.com:8080")
