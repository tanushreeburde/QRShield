import pytest
import respx
import httpx
from app.analysis.redirect_tracker import RedirectTracker


@pytest.mark.asyncio
@respx.mock
async def test_redirect_tracker_single_hop(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    respx.get("https://example.com/target").mock(return_value=httpx.Response(200, text="OK"))

    tracker = RedirectTracker()
    final_url, hops, findings = await tracker.track("https://example.com/target")

    assert final_url == "https://example.com/target"
    assert len(hops) == 1
    assert hops[0].status_code == 200
    assert len(findings) == 0


@pytest.mark.asyncio
@respx.mock
async def test_redirect_tracker_multi_hop_domain_change(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    respx.get("https://short.com/abc").mock(return_value=httpx.Response(301, headers={"Location": "https://landing.com/final"}))
    respx.get("https://landing.com/final").mock(return_value=httpx.Response(200, text="Final Page"))

    tracker = RedirectTracker()
    final_url, hops, findings = await tracker.track("https://short.com/abc")

    assert final_url == "https://landing.com/final"
    assert len(hops) == 2
    codes = [f.code for f in findings]
    assert "REDIRECT_DOMAIN_CHANGE" in codes


@pytest.mark.asyncio
@respx.mock
async def test_redirect_tracker_blocks_ssrf_hop(monkeypatch):
    import socket
    # Allow initial host
    def mock_getaddrinfo(h, p, proto=0):
        if "public.com" in h:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    # Redirects to loopback
    respx.get("https://public.com/redirect").mock(return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/internal"}))

    tracker = RedirectTracker()
    final_url, hops, findings = await tracker.track("https://public.com/redirect")

    codes = [f.code for f in findings]
    assert "SSRF_BLOCKED_HOP" in codes
    assert any(f.critical for f in findings)
