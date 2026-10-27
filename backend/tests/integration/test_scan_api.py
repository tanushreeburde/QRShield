import asyncio
import pytest
import respx
import httpx
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.data.db import init_db


@pytest.fixture(autouse=True, scope="session")
def prepare_db():
    asyncio.run(init_db())


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "configured_services" in data


@pytest.mark.asyncio
async def test_malformed_url_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan", json={"url": "ftp://invalid-scheme.com"})
        assert resp.status_code == 422

        resp2 = await client.post("/api/v1/scan", json={"url": ""})
        assert resp2.status_code == 422


@pytest.mark.asyncio
@respx.mock
async def test_scan_benign_url(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    respx.get("https://example.com/clean").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body><h1>Clean Page</h1></body></html>")
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan", json={"url": "https://example.com/clean"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "LOW_RISK"
        assert len(data["redirect_chain"]) == 1
        assert any("does not guarantee" in d for d in data["disclaimers"])
        assert "reputation" in data["unavailable_checks"]


@pytest.mark.asyncio
@respx.mock
async def test_scan_phishing_lookalike_with_login(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    html = """
    <html>
        <body>
            <form action="https://paypa1.com/login" method="post">
                <input type="text" name="email" />
                <input type="password" name="password" />
                <button type="submit">Log In</button>
            </form>
        </body>
    </html>
    """
    respx.get("https://paypa1.com/signin").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan", json={"url": "https://paypa1.com/signin"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "HIGH_RISK"
        evidence_codes = [e["code"] for e in data["evidence"]]
        assert "LOOKALIKE_DOMAIN_SUSPECTED" in evidence_codes
        assert "LOGIN_FORM_DETECTED" in evidence_codes


@pytest.mark.asyncio
async def test_scan_ssrf_blocked_direct():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000/internal"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "HIGH_RISK"
        evidence_codes = [e["code"] for e in data["evidence"]]
        assert "SSRF_BLOCKED_HOP" in evidence_codes


@pytest.mark.asyncio
@respx.mock
async def test_scan_history_and_deletion(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    respx.get("https://example.com/hist").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>OK</body></html>")
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        scan_resp = await client.post("/api/v1/scan", json={"url": "https://example.com/hist"})
        scan_id = scan_resp.json()["scan_id"]

        hist_resp = await client.get("/api/v1/history")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert any(item["id"] == scan_id for item in hist_data["items"])

        del_resp = await client.delete(f"/api/v1/history/{scan_id}")
        assert del_resp.status_code == 200

        hist_resp2 = await client.get("/api/v1/history")
        assert not any(item["id"] == scan_id for item in hist_resp2.json()["items"])


@pytest.mark.asyncio
async def test_scan_url_auto_normalization(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # User provides domain without scheme: should be auto-prefixed with https://
        resp = await client.post("/api/v1/scan", json={"url": "example.com/test"})
        assert resp.status_code == 200
        assert resp.json()["submitted_url"] == "https://example.com/test"


@pytest.mark.asyncio
async def test_decode_image_endpoint(monkeypatch):
    from app.api import routes_scan

    # Mock qr_decoder to return test URL
    monkeypatch.setattr(routes_scan.qr_decoder, "decode_bytes", lambda b: ("https://bank-security.com", None))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        files = {"file": ("test_qr.png", b"fake-png-bytes", "image/png")}
        resp = await client.post("/api/v1/scan/decode-image", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["decoded_text"] == "https://bank-security.com"
        assert data["is_url"] is True
        assert data["normalized_url"] == "https://bank-security.com"


@pytest.mark.asyncio
async def test_decode_image_failure(monkeypatch):
    from app.api import routes_scan

    monkeypatch.setattr(routes_scan.qr_decoder, "decode_bytes", lambda b: (None, "No QR detected"))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        files = {"file": ("blank.png", b"blank-bytes", "image/png")}
        resp = await client.post("/api/v1/scan/decode-image", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["error"] == "No QR detected"

