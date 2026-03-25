#!/usr/bin/env python3
"""Test CAS TGT-based session keepalive for Garmin Connect.

Usage:
  # First authenticate (saves tokens to garmin_tokens.json):
  GARMIN_EMAIL="you@example.com" GARMIN_PASSWORD="pass" \
    .venv/bin/python garmin-browser-auth.py

  # Then test keepalive:
  .venv/bin/python test_keepalive.py [--loop MINUTES]
"""

import argparse
import base64
import json
import sys
import time
from pathlib import Path

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    sys.exit(1)


CONNECT = "https://connect.garmin.com"
SSO = "https://sso.garmin.com"
CLIENT_ID = "GarminConnect"
SERVICE_URL = f"{CONNECT}/app"
TOKEN_FILE = Path("garmin_tokens.json")


def decode_jwt_exp(jwt_web: str) -> int:
    """Extract expiration timestamp from JWT."""
    parts = jwt_web.split(".")
    payload = parts[1] + "=="
    decoded = json.loads(base64.urlsafe_b64decode(payload))
    return decoded.get("exp", 0)


def jwt_remaining(jwt_web: str) -> tuple[int, str]:
    """Return (seconds_remaining, human_readable)."""
    exp = decode_jwt_exp(jwt_web)
    remaining = exp - int(time.time())
    if remaining <= 0:
        return remaining, "EXPIRED"
    h, m = remaining // 3600, (remaining % 3600) // 60
    return remaining, f"{h}h {m}m"


def load_session():
    """Load saved cookies into a curl_cffi session."""
    if not TOKEN_FILE.exists():
        sys.exit(1)

    data = json.loads(TOKEN_FILE.read_text())
    sess = cffi_requests.Session(impersonate="chrome")

    for name, value in data.get("cookies", {}).items():
        # Set cookies on appropriate domains
        if name in (
            "CASTGC",
            "CASRMC",
            "CASMFA",
            "SESSION",
            "__VCAP_ID__",
            "ADRUM_BTa",
            "ADRUM_BT1",
            "ADRUM_BTs",
            "SameSite",
        ):
            sess.cookies.set(name, value, domain="sso.garmin.com")
        elif name in ("GARMIN-SSO", "GARMIN-SSO-CUST-GUID", "GMN_TRACKABLE"):
            sess.cookies.set(name, value, domain=".garmin.com")
        elif name in {"JWT_WEB", "session"}:
            sess.cookies.set(name, value, domain=".connect.garmin.com")
        else:
            # Cloudflare cookies etc
            sess.cookies.set(name, value)

    jwt_web = data.get("jwt_web", "")
    return sess, jwt_web


def test_api(sess, label=""):
    """Make a test API call."""
    r = sess.get(
        f"{CONNECT}/proxy/userprofile-service/socialProfile",
        headers={
            "Accept": "application/json",
            "NK": "NT",
            "DI-Backend": "connectapi.garmin.com",
            "Origin": CONNECT,
            "Referer": f"{CONNECT}/modern/",
        },
        timeout=15,
    )
    return r.status_code == 200


def refresh_via_cas_tgt(sess) -> str | None:
    """Use CAS TGT cookies to get a new service ticket without re-auth.
    Returns new JWT_WEB or None.
    """
    # Step 1: Hit sign-in — CAS TGT cookies should auto-issue a ticket
    r = sess.get(
        f"{SSO}/portal/sso/en-US/sign-in",
        params={"clientId": CLIENT_ID, "service": SERVICE_URL},
        allow_redirects=True,
        timeout=30,
    )
    final_url = str(r.url)

    # Check for ticket in final URL or redirect history
    import re

    ticket = None
    # Check final URL
    m = re.search(r"ticket=(ST-[A-Za-z0-9\-]+)", final_url)
    if m:
        ticket = m.group(1)
    else:
        # Check redirect history
        for hist in getattr(r, "history", []):
            m = re.search(r"ticket=(ST-[A-Za-z0-9\-]+)", str(hist.url))
            if m:
                ticket = m.group(1)
                break
        # If redirected to /app/ successfully, JWT_WEB may already be set
        if not ticket and "connect.garmin.com/app" in final_url:
            # Check if JWT_WEB was refreshed during redirect
            for c in sess.cookies.jar:
                if c.name == "JWT_WEB":
                    new_jwt = c.value
                    remaining, human = jwt_remaining(new_jwt)
                    return new_jwt
            return None

    if not ticket:
        return None

    # Step 2: Consume ticket at /app/
    sess.get(
        f"{CONNECT}/app/",
        params={"ticket": ticket},
        allow_redirects=True,
        timeout=30,
    )

    # Extract new JWT_WEB
    jwt_web = None
    for c in sess.cookies.jar:
        if c.name == "JWT_WEB":
            jwt_web = c.value
            break

    if jwt_web:
        remaining, human = jwt_remaining(jwt_web)
    else:
        pass

    return jwt_web


def save_session(sess, jwt_web):
    """Save updated session to token file."""
    cookies = {}
    for c in sess.cookies.jar:
        cookies[c.name] = c.value
    data = {"jwt_web": jwt_web, "cookies": cookies}
    TOKEN_FILE.write_text(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Test Garmin CAS TGT keepalive")
    parser.add_argument(
        "--loop", type=int, default=0, help="Loop every N minutes (0 = single run)"
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force a CAS TGT refresh even if JWT is valid",
    )
    args = parser.parse_args()

    while True:
        sess, jwt_web = load_session()

        # Show current JWT status
        remaining, human = jwt_remaining(jwt_web)

        # Test current token
        api_ok = test_api(sess, "current")

        # Refresh if needed
        if args.force_refresh or remaining < 900 or not api_ok:
            new_jwt = refresh_via_cas_tgt(sess)
            if new_jwt:
                jwt_web = new_jwt
                save_session(sess, jwt_web)
                test_api(sess, "refreshed")
            else:
                pass
        else:
            pass

        if args.loop <= 0:
            break

        time.sleep(args.loop * 60)


if __name__ == "__main__":
    main()
