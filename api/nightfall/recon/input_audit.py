"""Profile B playbook 6: Safe Injection Surface Assessment (design §4.6).

  1. Map up to 20 pages of the target over GET, starting at / and following links on the
     same host only (other hosts are never fetched).
  2. List the inputs: query parameters seen in links, and forms.
  3. Send each input one payload from the fixed, reviewed corpus below: a unique marker,
     wrapped in characters that show whether output is encoded. Nothing else is ever sent:
     no SQL, no scripts that run, no time delays, no file uploads, no callbacks.
  4. Record whether the marker comes back unencoded (a likely cross-site scripting point a
     person must confirm), and whether the response shows a stack trace or a database error
     that the same page didn't show before.

POST is used only for forms whose action path the operator marked safe at launch (owner
decision 5: e.g. a search form), because a contact or sign-up form would create records.
Every other form is tested with GET only if it is a GET form, and skipped otherwise.

Limits and stop conditions are playbook 7's: at most 200 requests, 1 per second, 30
minutes; stops on a 429, three server errors in a row, or any sign of a locked account.
The evidence keeps paths, parameter names, statuses and yes/no results; never bodies.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections import deque
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from nightfall.core.db.models import Confidence, RiskClass
from nightfall.recon.auth_audit import StopRun, _Session, _set_cookies, page
from nightfall.recon.collectors import CollectorResult, Network, RunContext
from nightfall.recon.safe_http import Exchange, SafeHttp

CORPUS_VERSION = "janus-markers/1"
# The whole payload corpus: one marker per input, followed by characters whose encoding
# shows whether the page escapes output. Inert in every context: no tag closes, nothing runs.
WRAP = "'\"<jns>"
MAX_PAGES = 20
MAX_INPUTS = 120
ERRORS = {
    "python-traceback": re.compile(rb"Traceback \(most recent call last\)"),
    "java-stack": re.compile(rb"(?:Exception|Error) in thread|\bat [a-z]+(?:\.[a-zA-Z_$]+){2,}\("),
    "php-error": re.compile(rb"<b>(?:Fatal error|Warning|Parse error)</b>:"),
    "dotnet-error": re.compile(rb"Server Error in '/' Application|System\.\w+Exception"),
    "sql-error": re.compile(
        rb"You have an error in your SQL syntax|ORA-\d{5}|PG::\w+Error|SQLSTATE\[|"
        rb"unterminated quoted string|SQLite3?::|Microsoft OLE DB Provider for SQL Server",
        re.IGNORECASE,
    ),
}


def payload(marker: str) -> str:
    return f"{marker}{WRAP}"


def _errors(body: bytes) -> set[str]:
    return {k for k, rx in ERRORS.items() if rx.search(body)}


class InputAudit:
    key = "input-audit"
    label = "Safe injection surface assessment (Profile B)"
    risk_class = RiskClass.MODERATE
    method = (
        "Map up to 20 same-host pages over GET; send each input one inert marker from a "
        "fixed corpus; POST only to operator-marked safe forms"
    )

    def __init__(
        self,
        make_client: Callable[[list[Network]], SafeHttp] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        markers: Callable[[], str] = lambda: "jns" + secrets.token_hex(5),
    ) -> None:
        self.make_client = make_client or (lambda nets: SafeHttp(excluded_networks=nets))
        self.sleep, self.clock, self.markers = sleep, clock, markers

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        from nightfall.recon.access_audit import valid_paths

        raw_safe = ctx.params.get("safe_forms") or []
        safe = set(valid_paths(raw_safe)) if raw_safe else set()
        s = _Session(
            self.make_client(list(ctx.excluded_networks)), target, None, "", self.sleep,
            self.clock,
        )  # fmt: skip
        jar: dict[str, str] = {}
        result: dict[str, Any] = {
            "corpus": CORPUS_VERSION,
            "safe_forms": sorted(safe),
            "pages": [],
            "inputs": [],
            "stopped": None,
        }

        def get(path: str, note: str) -> Exchange | None:
            ex = s.send("GET", "https", path, jar=jar, note=note)
            if ex is not None:
                jar.update({n: v for n, v, _ in _set_cookies(ex)})
            return ex

        try:
            # 1-2. Map pages and collect inputs.
            queue: deque[str] = deque(["/"])
            seen: set[str] = set()
            baselines: dict[str, set[str]] = {}
            query_inputs: dict[tuple[str, str], dict[str, str]] = {}
            form_inputs: list[dict[str, Any]] = []
            while queue and len(seen) < MAX_PAGES:
                path = queue.popleft()
                if path in seen:
                    continue
                seen.add(path)
                ex = get(path, "map")
                result["pages"].append({"path": path, "status": ex.status if ex else None})
                if ex is None or ex.status != 200:
                    continue
                baselines[path] = _errors(ex.body)
                parsed = page(ex.body)
                base = f"https://{target}{path}"
                for href, _ in parsed.links:
                    u = urlsplit(urljoin(base, href))
                    if u.scheme not in ("http", "https") or u.hostname != target:
                        continue  # other hosts are never fetched
                    p = u.path or "/"
                    params = dict(parse_qsl(u.query, keep_blank_values=True))
                    for name in params:
                        query_inputs.setdefault((p, name), params)
                    if p not in seen:
                        queue.append(p)
                for f in parsed.forms:
                    action = urlsplit(urljoin(base, f["action"] or path))
                    if action.hostname != target:
                        continue
                    form_inputs.append({"page": path, "action": action.path or "/", **f})
            # 3-4. One marker per input.
            tested = 0

            def check(entry: dict[str, Any], ex: Exchange | None, marker: str, page_path: str):  # type: ignore[no-untyped-def]  # noqa: E501
                if ex is None:
                    entry["error"] = True
                    return
                body = ex.body
                entry["status"] = ex.status
                entry["reflected_unencoded"] = payload(marker).encode() in body
                entry["reflected"] = marker.encode() in body
                new = sorted(_errors(body) - baselines.get(page_path, set()))
                entry["error_disclosure"] = new
                result["inputs"].append(entry)

            for (path, name), params in sorted(query_inputs.items()):
                if tested >= MAX_INPUTS:
                    break
                marker = self.markers()
                q = {**params, name: payload(marker)}
                ex = get(f"{path}?{urlencode(q)}", f"marker in query parameter {name}")
                check({"where": "query", "path": path, "name": name}, ex, marker, path)
                tested += 1
            for f in form_inputs:
                fields = [i for i in f["inputs"] if i["name"]]
                text = [i for i in fields if i["type"] in ("text", "search", "email", "url", "")]
                post = f["method"] == "post"
                if post and f["action"] not in safe:
                    result["inputs"].append(
                        {
                            "where": "form",
                            "path": f["action"],
                            "skipped": "POST form not marked safe",
                        }
                    )
                    continue
                for target_input in text:
                    if tested >= MAX_INPUTS:
                        break
                    marker = self.markers()
                    data = {
                        i["name"]: (payload(marker) if i is target_input else i["value"] or "test")
                        for i in fields
                        if i["type"] not in ("submit", "button", "file", "password")
                    }
                    entry = {"where": "form", "method": f["method"], "path": f["action"],
                             "name": target_input["name"]}  # fmt: skip
                    if post:
                        ex = s.send(
                            "POST", "https", f["action"], jar=jar,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            body=urlencode(data).encode(), note="marker in a safe form",
                        )  # fmt: skip
                    else:
                        ex = get(f"{f['action']}?{urlencode(data)}", "marker in a GET form")
                    check(entry, ex, marker, f["page"])
                    tested += 1
        except StopRun as exc:
            result["stopped"] = str(exc)
        result["requests"] = len(s.log)
        raw = json.dumps({"target": target, "inputs_audit": result, "requests": s.log}, indent=2)
        return CollectorResult(
            raw=raw.encode(),
            content_type="application/json",
            tool_name=self.key,
            tool_version=f"janus-input-audit/1; {CORPUS_VERSION}",
            source=self.key,
            confidence=Confidence.HIGH,
            posture={"inputs": result},
        )
