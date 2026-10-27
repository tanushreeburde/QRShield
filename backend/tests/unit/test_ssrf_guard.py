import pytest
from app.security.ssrf_guard import validate_url_for_ssrf, SSRFBlockedException


def test_ssrf_blocks_loopback_ipv4():
    with pytest.raises(SSRFBlockedException) as exc_info:
        validate_url_for_ssrf("http://127.0.0.1:8080/admin")
    assert "blocked" in str(exc_info.value).lower()


def test_ssrf_blocks_cloud_metadata_ip():
    with pytest.raises(SSRFBlockedException) as exc_info:
        validate_url_for_ssrf("http://169.254.169.254/latest/meta-data")
    assert "blocked" in str(exc_info.value).lower()


def test_ssrf_blocks_rfc1918_private_ips():
    for private_url in [
        "http://10.0.0.1/status",
        "http://172.16.5.10/",
        "http://192.168.1.254/router"
    ]:
        with pytest.raises(SSRFBlockedException):
            validate_url_for_ssrf(private_url)


def test_ssrf_blocks_localhost_hostname():
    with pytest.raises(SSRFBlockedException):
        validate_url_for_ssrf("http://localhost:3000/api")
    with pytest.raises(SSRFBlockedException):
        validate_url_for_ssrf("http://sub.localhost/api")


def test_ssrf_blocks_internal_domains():
    with pytest.raises(SSRFBlockedException):
        validate_url_for_ssrf("http://myprinter.local/")
    with pytest.raises(SSRFBlockedException):
        validate_url_for_ssrf("http://service.internal/")


def test_ssrf_blocks_loopback_ipv6():
    with pytest.raises(SSRFBlockedException):
        validate_url_for_ssrf("http://[::1]/debug")


def test_ssrf_allows_public_domain(monkeypatch):
    import socket
    # Mock DNS resolution for public.example.com to public IP 93.184.216.34
    def mock_getaddrinfo(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    # Should not raise
    validate_url_for_ssrf("https://public.example.com/page")
