import urllib.request
import json

def test_live():
    base_url = "http://127.0.0.1:8000"

    print("--- 1. Testing Health Endpoint ---")
    with urllib.request.urlopen(f"{base_url}/api/v1/health") as response:
        assert response.status == 200
        health = json.loads(response.read().decode())
        print("Health status:", health)
        assert health["status"] == "ok"

    print("\n--- 2. Testing Safe Scan (https://example.com) ---")
    req = urllib.request.Request(
        f"{base_url}/api/v1/scan",
        data=json.dumps({"url": "https://example.com"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        scan_res = json.loads(response.read().decode())
        print("Scan result verdict:", scan_res["verdict"], "Score:", scan_res["score"])
        print("Final URL:", scan_res["final_url"])
        print("Redirect chain length:", len(scan_res["redirect_chain"]))
        print("Evidence count:", len(scan_res["evidence"]))
        print("Disclaimers:", scan_res["disclaimers"])
        assert scan_res["verdict"] == "LOW_RISK"
        assert len(scan_res["disclaimers"]) > 0

    print("\n--- 3. Testing SSRF Block Protection (http://127.0.0.1:8000/secret) ---")
    req_ssrf = urllib.request.Request(
        f"{base_url}/api/v1/scan",
        data=json.dumps({"url": "http://127.0.0.1:8000/secret"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_ssrf) as response:
        assert response.status == 200
        ssrf_res = json.loads(response.read().decode())
        print("SSRF scan verdict:", ssrf_res["verdict"])
        evidence_codes = [e["code"] for e in ssrf_res["evidence"]]
        print("Evidence codes:", evidence_codes)
        assert ssrf_res["verdict"] == "HIGH_RISK"
        assert "SSRF_BLOCKED_HOP" in evidence_codes

    print("\n--- 4. Testing Lookalike Typosquatting (http://paypa1.com/login) ---")
    req_look = urllib.request.Request(
        f"{base_url}/api/v1/scan",
        data=json.dumps({"url": "http://paypa1.com/login"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_look) as response:
        assert response.status == 200
        look_res = json.loads(response.read().decode())
        print("Lookalike scan verdict:", look_res["verdict"], "Score:", look_res["score"])
        ev_codes = [e["code"] for e in look_res["evidence"]]
        print("Evidence codes:", ev_codes)
        assert "LOOKALIKE_DOMAIN_SUSPECTED" in ev_codes

    print("\n--- 5. Testing History Endpoint ---")
    with urllib.request.urlopen(f"{base_url}/api/v1/history") as response:
        assert response.status == 200
        history = json.loads(response.read().decode())
        print("Total scans logged in SQLite history:", history["total"])
        assert history["total"] >= 2

    print("\n--- ALL LIVE E2E CHECKS PASSED SUCCESSFULLY! ---")

if __name__ == "__main__":
    test_live()
