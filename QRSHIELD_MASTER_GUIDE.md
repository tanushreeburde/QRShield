# QRShield — Complete Project Master Guide & Specification

> **Everything you need to know about the QRShield Cross-Platform QR & URL Security Inspector.**

---

## 1. Executive Summary & Problem Statement

### What is QRShield?
**QRShield** is a fast, lightweight, and explainable cybersecurity website and analysis engine designed to protect users against **Quishing (QR Phishing)** and malicious links. 

### The Problem It Solves
When a standard smartphone or computer camera scans a QR code, the operating system simply offers to open the link in the browser immediately. Attackers exploit this blind trust by:
1. **Pasting malicious QR stickers** over legitimate QR codes (e.g. at parking meters, restaurant menus, payment counters).
2. **Sending phishing emails** containing QR codes to bypass corporate email security gateways (which scan text links but often ignore images).
3. **Using URL shorteners and multi-hop redirects** (`bit.ly`, `tinyurl.com`) to obscure the destination domain until after the user has already clicked.
4. **Deploying lookalike domains (typosquatting / homoglyphs)** (e.g. `paypa1.com`, `apple-id-verify.com`) to steal login credentials or banking OTPs.

### How QRShield Solves It
Instead of automatically opening links, QRShield acts as an **intelligent security airlock**:
1. It decodes the QR code (via live camera, image upload, or pasted screenshot).
2. It classifies the QR content type (URL, UPI Payment, Wi-Fi, vCard, Plain Text).
3. If it is a web link, it performs a **deep, multi-layered security inspection** *before* your browser ever renders the page.
4. It provides a **clean, minimalist verdict** (Safe, Suspicious, or High Risk) with a direct "Open Link" button for safe sites, and a **"Why?"** breakdown on demand.
5. If it is a **Payment QR (UPI)**, it extracts payee details, UPI ID, and amount, preventing accidental payment fraud and refusing to launch dangerous browser links.

---

## 2. System Architecture

QRShield uses a **decoupled, high-performance architecture**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        QRShield Web Frontend                           │
│  (Modern Responsive HTML5 / CSS3 / Vanilla ES6 JavaScript)             │
│                                                                        │
│  [ Camera Scanner ]       [ Upload / Ctrl+V ]      [ Direct URL Input ]│
│  (WebRTC getUserMedia)    (Drag-and-Drop)          (Clipboard Paste)   │
│  (Native BarcodeDetector) (Client jsQR fallback)                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP Fetch / Multipart POST
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend Engine                          │
│                                                                        │
│  ┌───────────────────────┐  ┌────────────────────────────────────────┐ │
│  │ Static Web Server     │  │ Security API Routes                    │ │
│  │ (Serves Frontend App) │  │  • POST /api/v1/scan                    │ │
│  └───────────────────────┘  │  • POST /api/v1/scan/decode-image       │ │
│                             │  • GET  /api/v1/history                 │ │
│                             │  • GET  /api/v1/health                  │ │
│                             └───────────────────┬────────────────────┘ │
│                                                 │                      │
│  ┌──────────────────────────────────────────────▼────────────────────┐ │
│  │               6-Layer Security Inspection Engine                  │ │
│  │                                                                   │ │
│  │  1. URL Syntax & Obfuscation Heuristics                           │ │
│  │  2. Redirect Chain Tracker + SSRF Guard (Up to 8 hops)            │ │
│  │  3. Brand Lookalike & Homoglyph Typosquatting Engine              │ │
│  │  4. Domain Age (WHOIS) & TLD Abuse Heuristics                     │ │
│  │  5. Webpage Inspection (Login & Payment form analysis)            │ │
│  │  6. Threat Intelligence & Safe Browsing Feeds                     │ │
│  └──────────────────────────────────────────────┬────────────────────┘ │
│                                                 │                      │
│                             ┌───────────────────▼────────────────────┐ │
│                             │ SQLite Audit Database (aiosqlite)      │ │
│                             │ Stores scan history, hops, and evidence│ │
│                             └────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 3 Input Modes

When you open the website (`http://127.0.0.1:8000`), a segmented tab bar allows selecting between three functional input modes:

### 1. Camera Scanner
- Uses the browser's native **WebRTC `navigator.mediaDevices.getUserMedia`** API.
- Works across laptop webcams, PC external webcams, and mobile cameras.
- Uses hardware-accelerated **`window.BarcodeDetector`** (Chrome/Edge) with a local **`jsQR`** CPU canvas fallback.
- Point the camera at a QR code to decode it in real time.

### 2. Upload Image
- **File Browser**: Select any `.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`, or `.gif`.
- **Drag-and-Drop**: Drop an image file directly onto the dropzone.
- **Global `Ctrl+V` Screenshot Paste**: Press `Ctrl+V` anywhere on the webpage to inspect a screenshot from your clipboard.
- **Dual Decoding Pipeline**: Decodes in the browser first; if the image is low-contrast, noisy, or inverted, it forwards it to the backend's OpenCV + pyzbar multi-pass enhancement engine.

### 3. Enter URL
- Text input field with a "Paste" button and Enter-key submission.
- Auto-normalizes URLs (e.g. entering `github.com` auto-prefixes `https://github.com`).

---

## 4. How the Security Engine Works: The 6 Inspection Layers

The engine answers the question: **"Is this destination safe, suspicious, or dangerous?"** using 6 deterministic, multi-signal inspection layers:

### Layer 1: URL Structure & Obfuscation Analysis
- **Unencrypted HTTP Check**: Flags unencrypted plain `http://` connections where credentials or session cookies can be sniffed.
- **Raw IP Host Detection**: Flags URLs using IP addresses directly (e.g. `http://45.33.32.156/login`) rather than registered domain names (a classic phishing indicator).
- **The Userinfo `@` Trick**: Detects URLs formatted like `https://google.com@phishing-server.com`, which mislead users into thinking they are visiting Google.
- **Excessive Length & Obfuscation**: Flags URLs over 256 characters or containing excessive multi-layer percent-encoding (`%252F`, `%20`) used to evade basic keyword filters.
- **URL Shorteners**: Flags known shortener domains (`bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`) that conceal the final landing site.

### Layer 2: Hop-by-Hop Redirect Tracker with SSRF Guard
- **Up to 8 Hops Followed**: Follows the redirect chain sequentially using real HTTP `HEAD`/`GET` requests.
- **Cross-Domain Traversal**: Flags when a link starts at `companyA.com` and traverses across multiple unrelated second-level domains before terminating.
- **SSL Downgrade**: Flags if an initial secure `https://` link silently redirects to an unencrypted `http://` page.
- **SSRF (Server-Side Request Forgery) Guard**: Every intermediate IP address is resolved via DNS and checked against RFC-1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `::1`), and cloud metadata services (`169.254.169.254`). Any attempt to scan internal networks is instantly blocked and flagged as `HIGH_RISK`.

### Layer 3: Brand Lookalike & Typosquatting Detection
- **Levenshtein Distance Analysis**: Compares the domain against a database of commonly targeted global brands (PayPal, Netflix, Google, Apple, Microsoft, Amazon, Bank of America, etc.).
  - Example: `paypa1.com`, `arnazon.com`, `netfIix.com`.
- **Unicode Homoglyph Detection**: Detects internationalized domain names (IDNs) using Cyrillic, Greek, or Latin lookalike characters (e.g. Cyrillic `а` vs Latin `a`).

### Layer 4: Domain Age (WHOIS) & TLD Abuse Heuristics
- **Domain Age Heuristic**: Legitimate organizations usually have domains registered for years. Phishing campaigns almost always register **throwaway domains less than 30 days old**.
- **High-Risk TLD Analysis**: Penalizes top-level domains frequently abused for disposable spam and phishing campaigns (such as `.top`, `.xyz`, `.fit`, `.work`, `.click`).

### Layer 5: Webpage & Form Security Inspection
- Safely fetches the HTML content of the final destination page:
  - **Login / Credential Forms**: Detects `<input type="password">` or username/login fields.
  - **Payment & Card Forms**: Detects credit card number inputs, CVV, or banking fields.
  - **Cross-Domain Form Submissions**: Flags if a login page secretly posts submitted credentials to a different external domain (`<form action="http://malicious-collector.com">`).

### Layer 6: Reputation Databases
- Evaluates the domain and URL against threat intelligence databases (including Google Safe Browsing API when configured).

---

## 5. Risk Scoring & Decision Mechanics

Each detected finding carries a calibrated weight defined in `backend/app/config/risk_weights.yaml`:

| Finding Code | Severity | Weight | Critical? |
| :--- | :--- | :--- | :--- |
| `SSRF_BLOCKED_HOP` | HIGH | 80 | **Yes (Immediate High Risk)** |
| `REPUTATION_MATCH_FOUND` | HIGH | 90 | **Yes (Immediate High Risk)** |
| `HOMOGLYPH_DOMAIN_DETECTED` | HIGH | 55 | No |
| `LOOKALIKE_DOMAIN_SUSPECTED` | HIGH | 50 | No |
| `FORM_SUBMITS_TO_DIFFERENT_DOMAIN` | HIGH | 45 | No |
| `BRAND_CONTEXT_MISMATCH` | HIGH | 45 | No |
| `PAYMENT_FORM_DETECTED` | HIGH | 40 | No |
| `SUSPICIOUS_USERINFO_AT_SYMBOL` | HIGH | 40 | No |
| `RECENTLY_REGISTERED_DOMAIN` | HIGH | 35 | No |
| `IP_LITERAL_HOST` | HIGH | 35 | No |
| `LOGIN_FORM_DETECTED` | MEDIUM | 30 | No |
| `URL_SHORTENER_DETECTED` | MEDIUM | 25 | No |
| `REDIRECT_DOMAIN_CHANGE` | MEDIUM | 25 | No |
| `INSECURE_SCHEME_HTTP` | MEDIUM | 20 | No |
| `UNCOMMON_TLD` | MEDIUM | 20 | No |
| `MULTIPLE_REDIRECTS` | LOW | 15 | No |
| `EXCESSIVE_URL_LENGTH` | LOW | 15 | No |

### Verdict Thresholds

```
   Score: 0                      30                      70               100+
   ───────┼───────────────────────┼───────────────────────┼─────────────────►
          │       LOW RISK        │      SUSPICIOUS       │    HIGH RISK
          │     [LOW RISK]        │     [SUSPICIOUS]      │   [HIGH RISK]
```

1. **LOW RISK (Score 0 – 29)**:
   - Clean domain, valid HTTPS, no suspicious redirects, clean reputation.
   - **UI Action**: One-click **"Open URL"** button (opens directly in a new tab) + "Technical Details" button.
2. **SUSPICIOUS (Score 30 – 69)**:
   - Contains red flags (e.g. URL shortener + newly registered domain + multiple redirects).
   - **UI Action**: Displays only the top 1–2 key concerns, a **"Technical Details"** button, and an **"Open Anyway"** button with a confirmation warning.
3. **HIGH RISK (Score 70+ OR any Critical flag)**:
   - Severe threats detected (e.g. typosquatting PayPal, credential harvesting form, private IP SSRF attempt).
   - **UI Action**: Displays the critical threat, a **"Technical Details"** breakdown button, and primary action **"Close (Stay Safe)"**.

---

## 6. Smart Handling of Non-URL QR Codes

Not all QR codes are web links! QRShield automatically classifies non-URL codes and displays clear, safe guidance without attempting to open browser links:

| QR Type | Detection Signature | What is Displayed | Action Available |
| :--- | :--- | :--- | :--- |
| **UPI Payment** | `upi://pay?...` | Payee Name, UPI ID (VPA), Amount, Note. Shows safe notice explaining web browsers cannot process direct payments. | **"Copy Details"** (User opens PhonePe, GPay, or Paytm) |
| **Wi-Fi Network** | `WIFI:T:...;S:...;P:...` | Network Name (SSID), Security type (WPA/WPA2), Password. | **"Copy Password"** to connect via device settings |
| **Contact (vCard)** | `BEGIN:VCARD` | Name, Phone Number, Email, Organization. | **"Copy Details"** |
| **Plain Text** | Any non-link string | Cleanly formatted text block with clear notice that it is not an openable link. | **"Copy Text"** |

---

## 7. Progressive Disclosure UI Design Philosophy

A key user complaint with security tools is the **"wall of text"** problem: users are immediately bombarded with 20 lines of diagnostic jargon and end up ignoring all warnings.

**QRShield uses Progressive Disclosure**:
1. **At-a-Glance First**: The initial modal shows only 3 things:
   - Clear Status Icon & Verdict (`Looks Safe`, `Proceed with Caution`, `High Risk`).
   - The verified final destination URL.
   - The primary action button (`Open Link`, `Open Anyway`, or `Do Not Open`).
2. **Key Highlights Only**: If suspicious or dangerous, only the **top 1 or 2 most critical reasons** are shown in bullet points (e.g. *"Domain registered only 12 days ago"*).
3. **Full Details on Demand ("Why?")**: Clicking the **"Why?"** or **"View Technical Details"** button opens a deep diagnostic drawer with:
   - Overall Risk Score (/100).
   - Complete visual redirect chain with HTTP status codes and domain hops.
   - Comprehensive evidence table with severity badges (`HIGH`, `MEDIUM`, `LOW`, `INFO`).
   - Disclaimers and unavailable checks.

---

## 8. Complete Project File Structure

```
beh project/
│
├── run_website.bat                    # Windows double-click launcher
├── run_website.py                     # Python launcher (starts backend + opens browser)
├── QRSHIELD_MASTER_GUIDE.md           # Master documentation (this file)
│
├── frontend/                          # Clean, lightweight Web Application
│   ├── index.html                     # Responsive UI layout & modal templates
│   ├── css/
│   │   └── style.css                  # Modern cybersecurity dark theme
│   └── js/
│       ├── app.js                     # WebRTC camera, file upload, Ctrl+V, router
│       └── jsqr.min.js                # Bundled offline client-side QR decoder
│
└── backend/                           # FastAPI Security Engine
    ├── requirements.txt               # Python package dependencies
    ├── qrshield.db                    # SQLite audit database
    ├── .env / .env.example            # Environment configuration
    │
    ├── app/
    │   ├── main.py                    # App entry point, mounts frontend/ & API
    │   ├── config.py                  # Timeouts, limits, and feature toggles
    │   ├── logging_config.py          # Structured logging configuration
    │   │
    │   ├── analysis/                  # Core security analysis modules
    │   │   ├── qr_decoder.py          # OpenCV + pyzbar multi-pass QR image decoder
    │   │   ├── url_analyzer.py        # URL syntax, obfuscation, and shortener checks
    │   │   ├── redirect_tracker.py    # Multi-hop redirect follower with SSRF guard
    │   │   ├── domain_analyzer.py     # Domain age (WHOIS) & TLD risk heuristics
    │   │   ├── lookalike_detector.py  # Levenshtein typosquatting & Unicode homoglyphs
    │   │   ├── webpage_analyzer.py    # Form detection (login/payment/cross-domain)
    │   │   ├── brand_context.py       # Brand context mismatch engine
    │   │   ├── reputation_client.py   # Optional Google Safe Browsing client
    │   │   └── risk_engine.py         # Evidence scoring, thresholds & verdict engine
    │   │
    │   ├── api/                       # REST API route handlers
    │   │   ├── routes_scan.py         # POST /api/v1/scan, POST /scan/decode-image
    │   │   ├── routes_history.py      # GET /api/v1/history, DELETE /history/{id}
    │   │   └── routes_health.py       # GET /api/v1/health
    │   │
    │   ├── schemas/                   # Pydantic request & response models
    │   │   ├── scan.py                # ScanRequest, ScanResponse, ImageDecodeResponse
    │   │   └── common.py              # Finding, RedirectHop, VerdictEnum
    │   │
    │   ├── security/                  # Backend security guards
    │   │   ├── ssrf_guard.py          # DNS & RFC-1918 private/loopback IP validation
    │   │   └── rate_limiter.py        # Per-IP sliding-window rate limiter
    │   │
    │   ├── data/                      # Database & data assets
    │   │   ├── db.py                  # SQLAlchemy async engine & session maker
    │   │   ├── models.py              # ScanRecord, FindingRecord, RedirectHopRecord
    │   │   └── brand_list.json        # 60+ targeted brand domains for typosquatting
    │   │
    │   └── config/
    │       └── risk_weights.yaml      # Configurable risk weights and thresholds
    │
    ├── tests/                         # Complete automated test suite (38 tests)
    │   ├── conftest.py                # Shared fixtures
    │   ├── integration/
    │   │   └── test_scan_api.py       # 9 API integration tests
    │   └── unit/
    │       ├── test_url_analyzer.py
    │       ├── test_redirect_tracker.py
    │       ├── test_risk_engine.py
    │       ├── test_ssrf_guard.py
    │       ├── test_lookalike_detector.py
    │       └── test_webpage_analyzer.py
    │
    └── scripts/
        └── verify_live_e2e.py         # End-to-end live verification script
```

---

## 9. API Reference

All endpoints are hosted at `/api/v1` and documentable via Swagger UI at `http://127.0.0.1:8000/docs`:

### 1. `POST /api/v1/scan`
Submits a URL for full multi-layered security analysis.
- **Request Body**:
  ```json
  {
    "url": "https://example.com",
    "claimed_brand_text": "optional brand context",
    "client_platform": "web"
  }
  ```
- **Response**:
  ```json
  {
    "scan_id": "c7a8b8c2-48f1-4f76-bf10-fa37f6d7c81a",
    "submitted_url": "https://example.com",
    "final_url": "https://example.com/",
    "verdict": "LOW_RISK",
    "score": 0,
    "redirect_chain": [
      {
        "hop": 1,
        "url": "https://example.com/",
        "status_code": 200,
        "domain": "example.com"
      }
    ],
    "evidence": [],
    "unavailable_checks": [],
    "disclaimers": ["Low risk does not guarantee the site is benign."],
    "analyzed_at": "2026-09-27T15:20:00Z"
  }
  ```

### 2. `POST /api/v1/scan/decode-image`
Uploads an image file to decode any QR codes using OpenCV and pyzbar.
- **Form Data**: `file` (Multipart file upload)
- **Response**:
  ```json
  {
    "success": true,
    "decoded_text": "https://example.com",
    "is_url": true,
    "normalized_url": "https://example.com",
    "error": null
  }
  ```

### 3. `GET /api/v1/history?limit=30&offset=0`
Retrieves the audit log of past scans stored in the SQLite database.

### 4. `DELETE /api/v1/history/{scan_id}`
Deletes a specific scan record and its associated findings from history.

### 5. `GET /api/v1/health`
Returns the status of all backend modules (SSRF guard, rate limiter, database, WHOIS lookup).

---

## 10. How to Run, Test, and Verify

### Prerequisites
- Python 3.10+ (Python 3.13 is installed in `backend/venv`)
- Any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Safari)

### Quick Launch (One-Click)

**On Windows**:
Double-click `run_website.bat` in the project root folder.

**Via Command Line**:
```powershell
python run_website.py
```
*This command starts the backend engine and automatically opens `http://127.0.0.1:8000` in your default browser.*

### Running Automated Tests
To run all 38 unit and integration tests:
```powershell
cd backend
.\venv\Scripts\python.exe -m pytest -v
```
*(All 38 tests pass in ~12 seconds).*

### Running Live End-to-End Verification
To test live scanning of real-world scenarios (safe sites, SSRF loopback protection, typosquatting domains, and history recording):
```powershell
cd backend
.\venv\Scripts\python.exe scripts\verify_live_e2e.py
```

---

## 11. Technology Stack Summary

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Frontend Framework** | Pure HTML5, CSS3, ES6 JavaScript | Instant load time (<50ms), zero node_modules/webpack dependencies, 100% portable. |
| **Camera & QR Scanner** | WebRTC `getUserMedia` + `BarcodeDetector` + `jsQR` | 60fps hardware-accelerated camera scanning across laptops, desktops, and mobile devices. |
| **Image Processing** | OpenCV (`cv2`) + `pyzbar` | Multi-pass contrast enhancement and adaptive thresholding for noisy or inverted QR images. |
| **Backend Framework** | FastAPI (Python) + Uvicorn | Async performance, auto-generated OpenAPI documentation, strict Pydantic validation. |
| **Database** | SQLite + SQLAlchemy 2.0 (Async `aiosqlite`) | Zero-configuration persistence for scan history and audit records. |
| **Security Heuristics** | Levenshtein Distance (`rapidfuzz`), Unicode Homoglyphs, `python-whois`, `tldextract` | Pure deterministic cybersecurity detection without relying on slow external APIs. |
