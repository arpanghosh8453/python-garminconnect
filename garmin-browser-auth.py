#!/usr/bin/env python3
"""Get Garmin JWT tokens via portal login using curl_cffi.
The JWT_WEB cookie is set during /app/ ticket consumption.

Usage:
  GARMIN_EMAIL="you@example.com" GARMIN_PASSWORD="pass" \
    .venv/bin/python garmin-browser-auth.py
"""

import base64
import json
import os
from pathlib import Path

from curl_cffi import requests as cffi_requests

SSO_BASE = "https://sso.garmin.com"
CONNECT_BASE = "https://connect.garmin.com"
SERVICE_URL = f"{CONNECT_BASE}/app"
CLIENT_ID = "GarminConnect"


def portal_login(email, password):
    """Portal login via curl_cffi. Returns (ticket, session)."""
    sess = cffi_requests.Session(impersonate="chrome")

    sess.get(
        f"{SSO_BASE}/portal/sso/en-US/sign-in",
        params={"clientId": CLIENT_ID, "service": SERVICE_URL},
        timeout=30,
    )

    lp = {"clientId": CLIENT_ID, "locale": "en-US", "service": SERVICE_URL}
    ph = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "origin": SSO_BASE,
    }
    r = sess.post(
        f"{SSO_BASE}/portal/api/login",
        params=lp,
        headers=ph,
        json={
            "username": email,
            "password": password,
            "rememberMe": True,
            "captchaToken": "",
        },
        timeout=30,
    )
    r.raise_for_status()
    rj = r.json()
    resp_type = rj.get("responseStatus", {}).get("type", "UNKNOWN")

    if resp_type == "MFA_REQUIRED":
        method = rj.get("customerMfaInfo", {}).get("mfaLastMethodUsed", "email")
        code = input(f"MFA code ({method}): ").strip()
        mr = sess.post(
            f"{SSO_BASE}/portal/api/mfa/verifyCode",
            params=lp,
            headers=ph,
            json={
                "mfaMethod": method,
                "mfaVerificationCode": code,
                "rememberMyBrowser": True,
                "reconsentList": [],
                "mfaSetup": False,
            },
            timeout=30,
        )
        mr.raise_for_status()
        rj = mr.json()
        resp_type = rj.get("responseStatus", {}).get("type", "UNKNOWN")

    if resp_type != "SUCCESSFUL":
        raise RuntimeError(f"Login failed: {rj}")

    return rj["serviceTicketId"], sess


def main():
    email = os.environ.get("GARMIN_EMAIL")
    password = os.environ.get("GARMIN_PASSWORD")
    if not email or not password:
        email = input("Email: ").strip()
        password = input("Password: ").strip()

    # Step 1: Portal login
    ticket, sess = portal_login(email, password)

    # Step 2: Consume ticket — JWT_WEB is set as cookie here
    sess.get(
        f"{CONNECT_BASE}/app/",
        params={"ticket": ticket},
        allow_redirects=True,
        timeout=30,
    )

    # Extract JWT_WEB from cookies
    jwt_web = None
    for c in sess.cookies.jar:
        if c.name == "JWT_WEB":
            jwt_web = c.value
            break

    if not jwt_web:
        raise SystemExit(1)

    # Decode JWT expiration
    import base64 as b64mod

    jwt_parts = jwt_web.split(".")
    jwt_payload = json.loads(b64mod.urlsafe_b64decode(jwt_parts[1] + "=="))
    exp = jwt_payload.get("exp", 0)
    import time

    exp - int(time.time())

    # Try many different API endpoint patterns to find what works
    api_headers = {
        "Accept": "application/json",
        "NK": "NT",
        "DI-Backend": "connectapi.garmin.com",
        "Origin": CONNECT_BASE,
        "Referer": f"{CONNECT_BASE}/modern/",
    }
    test_eps = [
        # /proxy/ prefix
        f"{CONNECT_BASE}/proxy/usersummary-service/usersummary/daily?calendarDate=2026-03-25",
        f"{CONNECT_BASE}/proxy/device-service/deviceregistration/devices",
        f"{CONNECT_BASE}/proxy/activitylist-service/activities/search/activities?start=0&limit=1",
        # bare paths
        f"{CONNECT_BASE}/usersummary-service/usersummary/daily?calendarDate=2026-03-25",
        f"{CONNECT_BASE}/device-service/deviceregistration/devices",
        # /modern/proxy/ prefix
        f"{CONNECT_BASE}/modern/proxy/usersummary-service/usersummary/daily?calendarDate=2026-03-25",
        f"{CONNECT_BASE}/modern/proxy/device-service/deviceregistration/devices",
        # connectapi subdomain
        "https://connectapi.garmin.com/usersummary-service/usersummary/daily?calendarDate=2026-03-25",
        # /services/
        f"{CONNECT_BASE}/services/auth/token/user/current",
    ]
    for url in test_eps:
        try:
            r = sess.get(url, headers=api_headers, timeout=10)
            r.text[:120].replace("\n", " ")
            has_data = r.text != "{}" and len(r.text) > 5
            if has_data:
                pass
        except Exception:
            pass

    # Step 4: Save tokens
    cookies_dict = {}
    for c in sess.cookies.jar:
        cookies_dict[c.name] = c.value

    token_bundle = {
        "jwt_web": jwt_web,
        "cookies": cookies_dict,
    }

    # Save JSON
    local_path = Path.cwd() / "garmin_tokens.json"
    local_path.write_text(json.dumps(token_bundle, indent=2))

    # Base64 for GitHub secret
    base64.b64encode(json.dumps(token_bundle).encode()).decode()


if __name__ == "__main__":
    main()
