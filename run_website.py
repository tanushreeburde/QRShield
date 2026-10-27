"""
QRShield Website Launcher
Starts the FastAPI backend + web frontend server and opens http://127.0.0.1:8000 in your default browser.
"""

import sys
import os
import time
import webbrowser
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = BASE_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import uvicorn


def main():
    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}"

    print("=" * 60)
    print("   QRShield — QR & URL Security Inspector Website")
    print(f"   Opening website at: {url}")
    print("   Press Ctrl+C to stop the server")
    print("=" * 60)

    # Launch browser after a slight delay so server is up
    def open_browser():
        time.sleep(1.0)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    os.chdir(str(BACKEND_DIR))
    uvicorn.run("app.main:app", host=host, port=port, reload=False, log_level="info")


if __name__ == "__main__":
    main()
