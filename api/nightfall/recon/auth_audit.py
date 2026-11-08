"""Profile B playbook 7: Authentication Configuration Audit (design §4.7).

Signs in as one designated test identity over HTTPS and checks how the application handles
the session:
  * the login page is served only over HTTPS (plain HTTP redirects or refuses)
  * the session cookies set at login have Secure, HttpOnly and SameSite
  * the session identifier changes at login (no fixation)
  * logging out ends the session on the server (if a logout link is found)
  * for HTTP basic: credentials are never requested over plain HTTP

What it never does: guess passwords, try other accounts, test lockout (out of v1, owner
decision 4), attack two-factor, or send anything but GET, except one POST to the identity's
registered login path. Every request goes through the address-pinning client (scope
exclusions, no private addresses, redirects recorded but not followed, certificate
verified), at most one per second and at most 200 per run. It stops on a 429, on three
server errors in a row, or on any sign the account is locked.

The credential arrives in memory from the worker (RunContext.identity) and goes no
further: the evidence stores methods, paths, status codes and cookie attributes only.
Cookie values, request and response bodies, the username and the password are never
written anywhere; requests name the identity as <test-identity:label>.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

import httpx

from nightfall.core.db.models import Confidence, RiskClass
from nightfall.recon.collectors import CollectorResult, Network, RunContext
from nightfall.recon.posture import parse_cookie
from nightfall.recon.safe_http import Exchange, Refused, SafeHttp

MAX_REQUESTS = 200
MIN_INTERVAL = 1.0  # seconds between requests
DEADLINE = 1800.0  # 30 minutes
LOCKED = re.compile(
    rb"account (is )?(locked|disabled|suspended)|too many (failed )?(login )?attempts|"
    rb"temporarily (locked|blocked)",
    re.IGNORECASE,
)
LOGOUT = re.compile(r"log\s*-?\s*out|sign\s*-?\s*out", re.IGNORECASE)


class StopRun(Exception):
    """A stop condition: the run ends and records why."""


class _Forms(HTMLParser):
    """Forms, inputs and links of one page. Nothing is executed."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.links: list[tuple[str, str]] = []
        self._form: dict[str, Any] | None = None
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(
                {"name": a.get("name", ""), "type": a.get("type", "text").lower(),
                 "value": a.get("value", "")}
            )  # fmt: skip
        elif tag == "a":
            self._href, self._text = a.get("href", ""), []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href = None


def page(body: bytes) -> _Forms:
    p = _Forms()
    with contextlib.suppress(Exception):  # a page we can't parse simply has no forms
        p.feed(body[: 512 * 1024].decode("utf-8", "replace"))
    return p


def login_form(p: _Forms) -> dict[str, Any] | None:
    return next((f for f in p.forms if any(i["type"] == "password" for i in f["inputs"])), None)


def _cookie_header(jar: dict[str, str]) -> dict[str, str]:
    return {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} if jar else {}


def _set_cookies(ex: Exchange) -> list[tuple[str, str, dict[str, Any]]]:
    """(name, value, attributes) for each Set-Cookie. Values stay in memory only."""
    out = []
    for k, v in ex.headers:
        if k.lower() == "set-cookie":
            name, _, rest = v.partition("=")
            value = rest.split(";", 1)[0]
            out.append((name.strip(), value.strip(), parse_cookie(v)))
    return out


class _Session:
    """Counts, paces and records requests; enforces the stop conditions."""

    def __init__(
        self,
        client: SafeHttp,
        host: str,
        port: int | None,
        label: str,
        sleep: Callable[[float], None],
        clock: Callable[[], float],
    ) -> None:
        self.client, self.host, self.port, self.label = client, host, port, label
        self.sleep, self.clock = sleep, clock
        self.started = clock()
        self.last: float | None = None
        self.log: list[dict[str, Any]] = []
        self.errors_in_a_row = 0

    def send(
        self,
        method: str,
        scheme: str,
        path: str,
        *,
        jar: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        note: str = "",
    ) -> Exchange | None:
        if len(self.log) >= MAX_REQUESTS:
            raise StopRun(f"Request budget of {MAX_REQUESTS} used up.")
        if self.clock() - self.started > DEADLINE:
            raise StopRun("The 30-minute limit was reached.")
        if self.last is not None:
            wait = MIN_INTERVAL - (self.clock() - self.last)
            if wait > 0:
                self.sleep(wait)
        self.last = self.clock()
        entry: dict[str, Any] = {"method": method, "url": f"{scheme}://{self.host}{path}"}
        if note:
            entry["note"] = note
        try:
            ex = self.client.request(
                self.host,
                scheme,
                True,  # certificates verified: credentials never go to an unverified server
                method=method,
                path=path,
                port=self.port if scheme == "https" else None,
                headers={**_cookie_header(jar or {}), **(headers or {})},
                body=body,
            )
        except Refused:
            raise
        except (httpx.HTTPError, OSError) as exc:
            entry["error"] = type(exc).__name__
            self.log.append(entry)
            return None
        entry.update(
            status=ex.status,
            location=ex.location,
            set_cookies=[{**a, "value": "<redacted>"} for _, _, a in _set_cookies(ex)],
        )
        self.log.append(entry)
        if ex.status == 429:
            raise StopRun("The site answered 429 (too many requests).")
        self.errors_in_a_row = self.errors_in_a_row + 1 if ex.status >= 500 else 0
        if self.errors_in_a_row >= 3:
            raise StopRun("Three server errors in a row.")
        if LOCKED.search(ex.body):
            raise StopRun("The response suggests the account is locked; stopped at once.")
        return ex


@dataclass
class SignedIn:
    pre: dict[str, str]  # cookies before sign-in (values in memory only)
    set_at_login: list[tuple[str, str, dict[str, Any]]]
    jar: dict[str, str]  # cookies after sign-in
    landing: str  # where sign-in sent the browser, on this host
    headers: dict[str, str]  # extra request headers (HTTP basic)


def sign_in_form(s: _Session, ident: dict[str, str]) -> SignedIn:
    """Signs in through the login form on the identity's registered login path: one GET of
    the page, one POST to that same path. Raises StopRun if that isn't possible."""
    path = ident["login_path"]
    host = s.host
    first = s.send("GET", "https", path, note="login page")
    if first is None or first.status != 200:
        raise StopRun("The login page didn't load over HTTPS.")
    form = login_form(page(first.body))
    if form is None:
        raise StopRun("No login form with a password field on the registered login path.")
    base = f"https://{host}{path}"
    action = urljoin(base, form["action"] or path)
    parts = urlsplit(action)
    if parts.hostname != host or (parts.path or "/") != path or form["method"] != "post":
        raise StopRun(
            "The form doesn't POST to the registered login path; register that path "
            "instead (only that endpoint may receive a POST)."
        )
    pre = {n: v for n, v, _ in _set_cookies(first)}
    fields: dict[str, str] = {}
    user_field = pw_field = None
    for i in form["inputs"]:
        if not i["name"]:
            continue
        if i["type"] == "password" and pw_field is None:
            pw_field = i["name"]
        elif i["type"] in ("text", "email") and user_field is None:
            user_field = i["name"]
        elif i["type"] in ("hidden", "submit"):
            fields[i["name"]] = i["value"]
    if not user_field or not pw_field:
        raise StopRun("The login form has no username field.")
    fields[user_field], fields[pw_field] = ident["username"], ident["password"]
    login = s.send(
        "POST", "https", path, jar=pre,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urlencode(fields).encode(), note="sign in as <test-identity>",
    )  # fmt: skip
    if login is None:
        raise StopRun("The login request failed.")
    set_at_login = _set_cookies(login)
    jar = {**pre, **{n: v for n, v, _ in set_at_login}}
    landing = path
    if login.location:
        loc = urlsplit(urljoin(base, login.location))
        if loc.hostname == host:
            landing = loc.path or "/"
    failed = (login.status == 200 and login_form(page(login.body)) is not None) or (
        login.status in (401, 403)
    )
    if failed or landing == path and login.status in (301, 302, 303):
        raise StopRun("Sign-in didn't succeed with the test identity.")
    return SignedIn(pre, set_at_login, jar, landing, {})


def sign_in(s: _Session, ident: dict[str, str]) -> SignedIn:
    """A signed-in session for either login method (playbook 8 uses both identities)."""
    if ident["login_method"] == "basic":
        token = base64.b64encode(f"{ident['username']}:{ident['password']}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        ok = s.send("GET", "https", ident["login_path"], headers=headers, note="sign in (basic)")
        if ok is None or ok.status >= 400:
            raise StopRun("Sign-in didn't succeed with the test identity.")
        return SignedIn({}, [], {}, "/", headers)
    return sign_in_form(s, ident)


class AuthAudit:
    key = "auth-audit"
    label = "Authentication configuration audit (Profile B)"
    risk_class = RiskClass.MODERATE
    method = (
        "Sign in as a designated test identity over HTTPS; GET only apart from one POST to "
        "its registered login path; at most 200 requests, 1 per second"
    )

    def __init__(
        self,
        make_client: Callable[[list[Network]], SafeHttp] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.make_client = make_client or (lambda nets: SafeHttp(excluded_networks=nets))
        self.sleep, self.clock = sleep, clock

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        ident = ctx.identity
        if not ident:
            raise Refused("No designated test identity was provided for this run.")
        m = re.fullmatch(r"https://([^:/]+)(?::(\d+))?", ident["origin"])
        if not m or m.group(1) != target:
            raise Refused("The test identity doesn't belong to this target.")
        port = int(m.group(2)) if m.group(2) else None
        label = ident["label"]
        s = _Session(
            self.make_client(list(ctx.excluded_networks)), target, port, label,
            self.sleep, self.clock,
        )  # fmt: skip
        result: dict[str, Any] = {
            "identity": f"<test-identity:{label}>",
            "method": ident["login_method"],
            "login_path": ident["login_path"],
            "login_over_http": None,
            "basic_over_http": None,
            "authenticated": False,
            "cookies": [],
            "rotated": None,
            "logout_found": None,
            "logout_invalidates": None,
            "stopped": None,
        }
        try:
            if ident["login_method"] == "basic":
                self._basic(s, ident, result)
            else:
                self._form(s, ident, result)
        except StopRun as exc:
            result["stopped"] = str(exc)
        result["requests"] = len(s.log)
        raw = json.dumps({"target": target, "auth": result, "requests": s.log}, indent=2)
        for secret in (ident.get("password"), ident.get("username")):
            if secret and secret in raw:  # defence in depth: never store the credential
                raw = raw.replace(secret, f"<test-identity:{label}>")
        return CollectorResult(
            raw=raw.encode(),
            content_type="application/json",
            tool_name=self.key,
            tool_version="janus-auth-audit/1",
            source=self.key,
            confidence=Confidence.HIGH,
            posture={"auth": result},
        )

    # --- HTTP basic ---------------------------------------------------------------------

    def _basic(self, s: _Session, ident: dict[str, str], r: dict[str, Any]) -> None:
        path = ident["login_path"]
        token = base64.b64encode(f"{ident['username']}:{ident['password']}".encode()).decode()
        anon = s.send("GET", "https", path, note="without credentials")
        asks = (
            anon is not None
            and anon.status == 401
            and any(
                k.lower() == "www-authenticate" and v.lower().startswith("basic")
                for k, v in anon.headers
            )
        )
        if not asks:
            r["stopped"] = "The login path doesn't ask for HTTP basic credentials over HTTPS."
            return
        auth = s.send(
            "GET", "https", path, headers={"Authorization": f"Basic {token}"},
            note="with <test-identity> credentials",
        )  # fmt: skip
        r["authenticated"] = auth is not None and auth.status < 400
        plain = s.send("GET", "http", path, note="plain HTTP, without credentials")
        r["basic_over_http"] = (
            plain is not None
            and plain.status == 401
            and any(k.lower() == "www-authenticate" for k, _ in plain.headers)
        )

    # --- Login form ---------------------------------------------------------------------

    def _form(self, s: _Session, ident: dict[str, str], r: dict[str, Any]) -> None:
        path = ident["login_path"]
        host = s.host
        plain = s.send("GET", "http", path, note="login page over plain HTTP")
        if plain is not None:
            to_https = (plain.location or "").startswith(f"https://{host}")
            r["login_over_http"] = (
                not to_https and plain.status == 200 and login_form(page(plain.body)) is not None
            )
        else:
            r["login_over_http"] = False  # plain HTTP refused: fine
        signed = sign_in_form(s, ident)
        pre, set_at_login, jar, landing = (
            signed.pre,
            signed.set_at_login,
            signed.jar,
            signed.landing,
        )
        r["cookies"] = [a for _, _, a in set_at_login]
        r["rotated"] = bool(set_at_login) and all(
            pre.get(n) != v for n, v, _ in set_at_login if n in pre
        )
        if not set_at_login and pre:
            r["rotated"] = False
        if landing == path:
            landing = "/"
        home = s.send("GET", "https", landing, jar=jar, note="signed-in page")
        r["authenticated"] = (
            home is not None and home.status == 200 and login_form(page(home.body)) is None
        )
        if not r["authenticated"] or home is None:
            return
        logout = next(
            (
                urlsplit(urljoin(f"https://{host}{landing}", href))
                for href, text in page(home.body).links
                if LOGOUT.search(text) or LOGOUT.search(href)
            ),
            None,
        )
        r["logout_found"] = logout is not None and logout.hostname == host
        if not r["logout_found"] or logout is None:
            return
        s.send("GET", "https", logout.path or "/", jar=jar, note="log out (GET link)")
        again = s.send("GET", "https", landing, jar=jar, note="old session after logout")
        still = again is not None and again.status == 200 and login_form(page(again.body)) is None
        r["logout_invalidates"] = not still
