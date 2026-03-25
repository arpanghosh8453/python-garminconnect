"""State-of-the-art authentication engine for Garmin Connect."""

import json
import logging
from pathlib import Path
from typing import Any

import requests

try:
    from curl_cffi import requests as cffi_requests

    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

_LOGGER = logging.getLogger(__name__)

CLIENT_ID = "GarminConnect"
SSO_SERVICE_URL = "https://connect.garmin.com/app/"


import contextlib

from .exceptions import (  # noqa: E402
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)


class Client:
    """A client to communicate with Garmin Connect."""

    def __init__(self, domain: str = "garmin.com", **kwargs: Any) -> None:
        self.domain = domain
        self._sso = f"https://sso.{domain}"
        self._connect = f"https://connect.{domain}"

        self.jwt_web: str | None = None
        self.csrf_token: str | None = None  # kept for backward compat

        # Garth backward compatibility properties
        self.profile: dict | None = None

        # Use curl_cffi for all HTTP to bypass Cloudflare TLS fingerprinting
        self.cs: Any = None
        if HAS_CFFI:
            self.cs = cffi_requests.Session(impersonate="chrome")
        else:
            self.cs = requests.Session()
            pool_connections = kwargs.get("pool_connections", 20)
            pool_maxsize = kwargs.get("pool_maxsize", 20)
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=pool_connections,
                pool_maxsize=pool_maxsize,
            )
            self.cs.mount("https://", adapter)
            self.cs.mount("http://", adapter)

        self._tokenstore_path: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.jwt_web)

    def get_api_headers(self) -> dict[str, str]:
        if not self.is_authenticated:
            raise GarminConnectAuthenticationError("Not authenticated")
        headers = {
            "Accept": "application/json",
            "NK": "NT",
            "Origin": self._connect,
            "Referer": f"{self._connect}/modern/",
            "DI-Backend": f"connectapi.{self.domain}",
        }
        if self.csrf_token:
            headers["connect-csrf-token"] = str(self.csrf_token)
        return headers

    def login(
        self,
        email: str,
        password: str,
        prompt_mfa: Any = None,
        return_on_mfa: bool = False,
        use_playwright: bool = False,
    ) -> tuple[str | None, Any]:
        """Log in to Garmin Connect.

        Tries portal login with curl_cffi first (bypasses Cloudflare TLS),
        falls back to mobile API, then Playwright.
        """
        if use_playwright:
            return self.login_playwright(email, password)

        # Try portal login with curl_cffi first (most reliable)
        if HAS_CFFI:
            try:
                return self._portal_login(
                    email,
                    password,
                    prompt_mfa=prompt_mfa,
                    return_on_mfa=return_on_mfa,
                )
            except Exception as e:
                _LOGGER.warning("Portal login failed (%s), trying mobile API", e)

        # Fallback: mobile API login
        return self._mobile_login(
            email,
            password,
            prompt_mfa=prompt_mfa,
            return_on_mfa=return_on_mfa,
        )

    def _portal_login(
        self,
        email: str,
        password: str,
        prompt_mfa: Any = None,
        return_on_mfa: bool = False,
    ) -> tuple[str | None, Any]:
        """Portal login using curl_cffi with Chrome TLS fingerprint."""
        sess = cffi_requests.Session(impersonate="chrome")

        # Step 1: GET sign-in page (sets SESSION + Cloudflare cookies)
        signin_url = f"{self._sso}/portal/sso/en-US/sign-in"
        sess.get(
            signin_url,
            params={"clientId": CLIENT_ID, "service": SSO_SERVICE_URL},
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.9",
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "none",
            },
            timeout=30,
        )

        # Step 2: POST credentials
        referer = f"{signin_url}?clientId={CLIENT_ID}&service={SSO_SERVICE_URL}"
        login_params = {
            "clientId": CLIENT_ID,
            "locale": "en-US",
            "service": SSO_SERVICE_URL,
        }
        post_headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "origin": self._sso,
            "referer": referer,
            "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        r = sess.post(
            f"{self._sso}/portal/api/login",
            params=login_params,
            headers=post_headers,
            json={
                "username": email,
                "password": password,
                "rememberMe": True,
                "captchaToken": "",
            },
            timeout=30,
        )
        r.raise_for_status()
        res = r.json()
        resp_type = res.get("responseStatus", {}).get("type")

        if resp_type == "MFA_REQUIRED":
            self._mfa_method = res.get("customerMfaInfo", {}).get(
                "mfaLastMethodUsed", "email"
            )
            self._mfa_cffi_session = sess
            self._mfa_cffi_params = login_params
            self._mfa_cffi_headers = post_headers

            if return_on_mfa:
                return "needs_mfa", sess

            if prompt_mfa:
                mfa_code = prompt_mfa()
                self._complete_mfa_portal(mfa_code)
                return None, None
            raise GarminConnectAuthenticationError(
                "MFA Required but no prompt_mfa mechanism supplied"
            )

        if resp_type == "SUCCESSFUL":
            ticket = res["serviceTicketId"]
            self._establish_session(ticket, sess=sess)
            return None, None

        if resp_type == "INVALID_USERNAME_PASSWORD":
            raise GarminConnectAuthenticationError(
                "401 Unauthorized (Invalid Username or Password)"
            )

        raise GarminConnectAuthenticationError(f"Portal login failed: {res}")

    def _complete_mfa_portal(self, mfa_code: str) -> None:
        """Complete MFA verification via portal API with curl_cffi."""
        sess = self._mfa_cffi_session
        r = sess.post(
            f"{self._sso}/portal/api/mfa/verifyCode",
            params=self._mfa_cffi_params,
            headers=self._mfa_cffi_headers,
            json={
                "mfaMethod": getattr(self, "_mfa_method", "email"),
                "mfaVerificationCode": mfa_code,
                "rememberMyBrowser": True,
                "reconsentList": [],
                "mfaSetup": False,
            },
            timeout=30,
        )
        res = r.json()
        if res.get("responseStatus", {}).get("type") == "SUCCESSFUL":
            ticket = res["serviceTicketId"]
            self._establish_session(ticket, sess=sess)
            return
        raise GarminConnectAuthenticationError(f"MFA Verification failed: {res}")

    def _mobile_login(
        self,
        email: str,
        password: str,
        prompt_mfa: Any = None,
        return_on_mfa: bool = False,
    ) -> tuple[str | None, Any]:
        """Fallback: mobile API login using requests (original flow)."""
        sess: requests.Session = requests.Session()
        sess.headers = {
            "User-Agent": "GarminConnect/5.7.1.3 CFNetwork/1498.700.2 Darwin/23.6.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        sess.get(
            f"{self._sso}/mobile/sso/en/sign-in",
            params={"clientId": CLIENT_ID},
        )

        r = sess.post(
            f"{self._sso}/mobile/api/login",
            params={
                "clientId": CLIENT_ID,
                "locale": "en-US",
                "service": SSO_SERVICE_URL,
            },
            json={
                "username": email,
                "password": password,
                "rememberMe": True,
                "captchaToken": "",
            },
        )

        # Failover to Playwright if Cloudflare blocks mobile endpoint
        if r.status_code == 429:
            try:
                import playwright

                _LOGGER.warning("Cloudflare 429 detected! Failing over to Playwright.")
                return self.login_playwright(email, password)
            except ImportError:
                raise GarminConnectConnectionError(
                    "Login failed (429 Rate Limit). Install curl_cffi or playwright."
                )

        try:
            res = r.json()
        except Exception as err:
            raise GarminConnectConnectionError(
                f"Login failed (Not JSON): HTTP {r.status_code}"
            ) from err

        resp_type = res.get("responseStatus", {}).get("type")

        if resp_type == "MFA_REQUIRED":
            self._mfa_method = res.get("customerMfaInfo", {}).get(
                "mfaLastMethodUsed", "email"
            )
            self._mfa_session = sess

            if return_on_mfa:
                return "needs_mfa", self._mfa_session

            if prompt_mfa:
                mfa_code = prompt_mfa()
                self._complete_mfa(mfa_code)
                return None, None
            raise GarminConnectAuthenticationError(
                "MFA Required but no prompt_mfa mechanism supplied"
            )

        if resp_type == "SUCCESSFUL":
            ticket = res["serviceTicketId"]
            self._establish_session(ticket)
            return None, None

        if (
            "status-code" in res.get("error", {})
            and res["error"]["status-code"] == "429"
        ):
            raise GarminConnectTooManyRequestsError("429 Rate Limit")

        if resp_type == "INVALID_USERNAME_PASSWORD":
            raise GarminConnectAuthenticationError(
                "401 Unauthorized (Invalid Username or Password)"
            )

        raise GarminConnectAuthenticationError(
            f"Unhandled Garmin Login JSON, Login failed: {res}"
        )

    def login_playwright(
        self, email: str, password: str, display_ui: bool = False
    ) -> tuple[str | None, Any]:
        """Bypass Cloudflare by fully automating native Microsoft Edge browser physics."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise GarminConnectAuthenticationError(
                "Playwright block missing: run `pip install playwright`"
            ) from e

        with sync_playwright() as p:
            # We explicitly emulate the edge browser channel to bypass stealth checks natively
            browser = p.chromium.launch(headless=not display_ui, channel="msedge")
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
            )
            page = context.new_page()

            sso_url = (
                f"{self._sso}/sso/embed"
                "?id=gauth-widget"
                "&embedWidget=true"
                f"&gauthHost={self._sso}/sso"
                "&clientId=GarminConnect"
                "&locale=en_US"
                f"&redirectAfterAccountLoginUrl={self._sso}/sso/embed"
                f"&service={self._sso}/sso/embed"
            )

            page.goto(sso_url)
            page.wait_for_selector('input[name="username"]', timeout=30000)
            page.fill('input[name="username"]', email)
            page.fill('input[name="password"]', password)
            import time

            time.sleep(1)

            # Guarantee long-lived sessions intrinsically by asserting the native DOM checkbox if visible
            try:
                if page.is_visible('input[id="rememberMe"]'):
                    page.check('input[id="rememberMe"]')
            except Exception:
                pass

            page.click('button[type="submit"]')

            start = time.time()
            ticket = None
            needs_mfa = False
            while time.time() - start < 120:
                try:
                    content = page.content()

                    if "ticket=" in page.url:
                        import re

                        m = re.search(r"ticket=(ST-[A-Za-z0-9\-]+)", page.url)
                        if m:
                            ticket = m.group(1)
                            break

                    m2 = re.search(r"ticket=(ST-[A-Za-z0-9\-]+)", content)
                    if m2:
                        ticket = m2.group(1)
                        break

                    # Instantly catch generic authentication denial organically
                    if "Invalid sign in." in content:
                        browser.close()
                        raise GarminConnectAuthenticationError(
                            "Garmin natively rejected the provided username or password inside the browser session."
                        )

                    # Aggressively intercept MFA organically by detecting the visual text or alternate input names
                    # Playwright's is_visible() fails mechanically on Garmin's proprietary MFA DOM layers, so we evaluate the raw HTML tree
                    is_mfa_visible = False
                    active_mfa_selector = ""

                    if (
                        'name="mfa-code"' in content
                        or 'name="mfaCode"' in content
                        or 'name="mfaVerificationCode"' in content
                        or 'name="verificationCode"' in content
                    ):
                        # Garmin preloads the MFA HTML blocks invisibly. It only physically executes MFA if the username block is simultaneously annihilated natively!
                        if 'name="username"' not in content:
                            is_mfa_visible = True

                            if 'name="mfa-code"' in content:
                                active_mfa_selector = 'input[name="mfa-code"]'
                            elif 'name="mfaCode"' in content:
                                active_mfa_selector = 'input[name="mfaCode"]'
                            elif 'name="mfaVerificationCode"' in content:
                                active_mfa_selector = (
                                    'input[name="mfaVerificationCode"]'
                                )
                            else:
                                active_mfa_selector = 'input[name="verificationCode"]'

                    if is_mfa_visible and not needs_mfa:
                        needs_mfa = True
                        mfa_code = input("MFA one-time code: ").strip()

                        try:
                            # If the HTML physically renders it, assert it
                            if 'id="rememberMyBrowser"' in content:
                                page.check('input[id="rememberMyBrowser"]', force=True)
                        except Exception:
                            pass

                        # Securely fill the dominant field dynamically based on the exact DOM mapping using forceful injections
                        page.fill(active_mfa_selector, mfa_code, force=True)

                        # Submit MFA organically with force to bypass disabled JavaScript overlays
                        try:
                            page.click(
                                "#mfa-verification-code-submit",
                                timeout=5000,
                                force=True,
                            )
                        except Exception:
                            page.click('button[type="submit"]', force=True)

                        # Wait gently for the physical MFA submission payload to parse into the ticket organically
                        time.sleep(2)
                except Exception:
                    pass
                time.sleep(1)

            if not ticket:
                try:
                    page.screenshot(path="playwright_debug.png")
                    with open("playwright_mfa_dom.txt", "w") as f:
                        f.write(page.content())
                except Exception:
                    pass
                browser.close()
                raise GarminConnectAuthenticationError(
                    "Playwright emulated SSO login failed. Review playwright_mfa_dom.txt locally."
                )

            browser.close()

        self._establish_session(ticket)
        return None, None

    def _complete_mfa(self, mfa_code: str) -> None:
        r = self._mfa_session.post(
            f"{self._sso}/mobile/api/mfa/verifyCode",
            params={
                "clientId": CLIENT_ID,
                "locale": "en-US",
                "service": SSO_SERVICE_URL,
            },
            json={
                "mfaMethod": getattr(self, "_mfa_method", "email"),
                "mfaVerificationCode": mfa_code,
                "rememberMyBrowser": True,
                "reconsentList": [],
                "mfaSetup": False,
            },
        )
        res = r.json()
        if res.get("responseStatus", {}).get("type") == "SUCCESSFUL":
            ticket = res["serviceTicketId"]
            self._establish_session(ticket)
            return
        raise GarminConnectAuthenticationError(f"MFA Verification failed: {res}")

    def _establish_session(self, ticket: str, sess: Any = None) -> None:
        """Consume a CAS ticket at /app/ to get JWT_WEB cookie.

        The JWT_WEB token is set as a cookie by Garmin Connect during
        ticket consumption — NOT returned in the /di-oauth/refresh body.
        """
        # Reuse the portal login session if provided (has SSO cookies)
        if sess is not None:
            self.cs = sess

        self.cs.get(
            f"{self._connect}/app/",
            params={"ticket": ticket},
            allow_redirects=True,
            timeout=30,
        )

        # Extract JWT_WEB from cookies
        jwt_web = None
        for c in self.cs.cookies.jar:
            if c.name == "JWT_WEB":
                jwt_web = c.value
                break

        if not jwt_web:
            raise GarminConnectAuthenticationError(
                "JWT_WEB cookie not set after ticket consumption"
            )

        self.jwt_web = jwt_web
        _LOGGER.debug("JWT_WEB obtained from cookie")

        # Call di-oauth/refresh to update session (returns 201 {})
        try:
            self.cs.post(
                f"{self._connect}/services/auth/token/di-oauth/refresh",
                headers={
                    "Accept": "application/json",
                    "NK": "NT",
                    "Referer": f"{self._connect}/modern/",
                },
                timeout=15,
            )
        except Exception:
            pass  # refresh is optional; JWT_WEB cookie is already set

    def _refresh_session(self) -> None:
        """Refresh JWT by re-consuming a CAS ticket via TGT cookies.

        The CAS TGT cookies (CASTGC, CASRMC) can mint new service
        tickets without re-authentication. The ticket is consumed
        during the redirect chain, setting a fresh JWT_WEB cookie.
        """
        if not self.is_authenticated:
            return
        try:
            # Hit sign-in — CAS TGT cookies auto-issue ticket via redirect
            self.cs.get(
                f"{self._sso}/portal/sso/en-US/sign-in",
                params={"clientId": CLIENT_ID, "service": SSO_SERVICE_URL},
                allow_redirects=True,
                timeout=15,
            )
            # JWT_WEB is refreshed via the redirect chain
            for c in self.cs.cookies.jar:
                if c.name == "JWT_WEB":
                    self.jwt_web = c.value
                    _LOGGER.debug("Session refreshed via CAS TGT")
                    if self._tokenstore_path:
                        with contextlib.suppress(Exception):
                            self.dump(self._tokenstore_path)
                    return

            # Fallback: try di-oauth/refresh
            self.cs.post(
                f"{self._connect}/services/auth/token/di-oauth/refresh",
                headers={
                    "Accept": "application/json",
                    "NK": "NT",
                    "Referer": f"{self._connect}/modern/",
                },
                timeout=10,
            )
            for c in self.cs.cookies.jar:
                if c.name == "JWT_WEB":
                    self.jwt_web = c.value
                    break
        except Exception as err:
            _LOGGER.debug(f"Refresh failed: {err}")

    def dumps(self) -> str:
        """Serialize session state to JSON string."""
        cookies = {}
        for c in self.cs.cookies.jar:
            cookies[c.name] = c.value
        data: dict[str, Any] = {
            "jwt_web": self.jwt_web,
            "csrf_token": self.csrf_token,
            "cookies": cookies,
        }
        return json.dumps(data)

    def dump(self, path: str) -> None:
        """Write tokens safely natively to disk format."""
        p = Path(path).expanduser()
        if p.is_dir() or not p.name.endswith(".json"):
            p = p / "garmin_tokens.json"

        # Ensure parent directories exist
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.dumps())

    def load(self, path: str) -> None:
        try:
            self._tokenstore_path = path
            p = Path(path).expanduser()
            if p.is_dir() or not p.name.endswith(".json"):
                p = p / "garmin_tokens.json"
            self.loads(p.read_text())
        except Exception as e:
            raise GarminConnectConnectionError(
                f"Token path not loading cleanly: {e}"
            ) from e

    def loads(self, tokenstore: str) -> None:
        try:
            data = json.loads(tokenstore)
            self.jwt_web = data.get("jwt_web")
            self.csrf_token = data.get("csrf_token")
            raw_cookies = data.get("cookies", {})

            # Map cookies to their correct domains
            sso_cookies = {
                "CASTGC",
                "CASRMC",
                "CASMFA",
                "SESSION",
                "__VCAP_ID__",
                "ADRUM_BTa",
                "ADRUM_BT1",
                "ADRUM_BTs",
                "SameSite",
            }
            garmin_cookies = {"GARMIN-SSO", "GARMIN-SSO-CUST-GUID", "GMN_TRACKABLE"}
            connect_cookies = {"JWT_WEB", "session", "__cflb"}

            for k, v in raw_cookies.items():
                if k in sso_cookies:
                    self.cs.cookies.set(k, v, domain=f"sso.{self.domain}")
                elif k in garmin_cookies:
                    self.cs.cookies.set(k, v, domain=f".{self.domain}")
                elif k in connect_cookies:
                    self.cs.cookies.set(k, v, domain=f".connect.{self.domain}")
                else:
                    self.cs.cookies.set(k, v, domain=f".{self.domain}")

            if not self.is_authenticated:
                raise GarminConnectAuthenticationError("Missing tokens from dict load")
        except Exception as e:
            raise GarminConnectConnectionError(
                f"Token extraction loads() structurally failed: {e}"
            ) from e

    def connectapi(self, path: str, **kwargs: Any) -> Any:
        return self._run_request("GET", path, **kwargs).json()

    def request(self, method: str, _domain: str, path: str, **kwargs: Any) -> Any:
        # Legacy garth used this to distinguish API vs WEB
        kwargs.pop("api", None)
        return self._run_request(method, path, **kwargs)

    def post(self, _domain: str, path: str, **kwargs: Any) -> Any:
        api = kwargs.pop("api", False)
        resp = self._run_request("POST", path, **kwargs)
        if api:
            return resp.json() if hasattr(resp, "json") else None
        return resp

    def put(self, _domain: str, path: str, **kwargs: Any) -> Any:
        api = kwargs.pop("api", False)
        resp = self._run_request("PUT", path, **kwargs)
        if api:
            return resp.json() if hasattr(resp, "json") else None
        return resp

    def delete(self, _domain: str, path: str, **kwargs: Any) -> Any:
        api = kwargs.pop("api", False)
        resp = self._run_request("DELETE", path, **kwargs)
        if api:
            return resp.json() if hasattr(resp, "json") else None
        return resp

    def resume_login(self, client_state: Any, mfa_code: str) -> tuple[str | None, Any]:
        _ = client_state
        self._complete_mfa(mfa_code)
        return None, None

    def download(self, path: str, **kwargs: Any) -> bytes:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        # Ensure we politely accept any binary format Garmin transmits
        kwargs["headers"].update({"Accept": "*/*"})
        return self._run_request("GET", path, **kwargs).content

    def _token_expires_soon(self) -> bool:
        if not self.jwt_web:
            return False

        try:
            import base64
            import json
            import time

            parts = str(self.jwt_web).split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
                payload = json.loads(payload_json)
                exp = payload.get("exp")

                # Proactively trigger a refresh if the token dies within 15 minutes
                if exp and time.time() > (int(exp) - 900):
                    return True
        except Exception:
            pass
        return False

    def _run_request(self, method: str, path: str, **kwargs: Any) -> Any:
        if self.is_authenticated and self._token_expires_soon():
            self._refresh_session()

        # Use /proxy/ prefix for API calls (works with JWT_WEB cookie auth)
        if not path.startswith("/proxy/"):
            clean = path.lstrip("/")
            # Strip legacy prefixes
            for prefix in ("gc-api/",):
                if clean.startswith(prefix):
                    clean = clean[len(prefix) :]
            path = f"/proxy/{clean}"

        url = f"{self._connect}{path}"

        if "timeout" not in kwargs:
            kwargs["timeout"] = 15

        headers = self.get_api_headers()
        custom_headers = kwargs.pop("headers", {})
        headers.update(custom_headers)

        resp = self.cs.request(method, url, headers=headers, **kwargs)

        # Implement 401 refresh intercept universally
        if resp.status_code == 401:
            self._refresh_session()
            resp = self.cs.request(
                method, url, headers=self.get_api_headers(), **kwargs
            )

        if resp.status_code == 204:

            class EmptyJSONResp:
                status_code = 204
                content = b""

                def json(self) -> Any:
                    return {}

                def __repr__(self) -> str:
                    return "{}"

                def __str__(self) -> str:
                    return "{}"

            return EmptyJSONResp()

        if resp.status_code >= 400:
            error_msg = f"API Error {resp.status_code}"
            try:
                error_data = resp.json()
                if isinstance(error_data, dict):
                    msg = (
                        error_data.get("message")
                        or error_data.get("content")
                        or error_data.get("detailedImportResult", {})
                        .get("failures", [{}])[0]
                        .get("messages", [""])[0]
                    )
                    if msg:
                        error_msg += f" - {msg}"
                    else:
                        error_msg += f" - {error_data}"
            except Exception:
                # If it's short, just attach the text
                if len(resp.text) < 500:
                    error_msg += f" - {resp.text}"
            raise GarminConnectConnectionError(error_msg)

        return resp
