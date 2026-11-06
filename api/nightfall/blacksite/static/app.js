// JANUS BLACKSITE operator console. Served only by the host-only BLACKSITE listener.
// Every value from the API (and everything a target sent back) is inserted as text with
// DOM APIs; nothing is ever parsed as HTML. The server is the only authority on access.
"use strict";

const state = { me: null, ws: null, status: null, tab: "probes", targets: [], asset: null,
  project: null, probes: [], selected: null, compare: [], timer: null };

// --- DOM helpers ------------------------------------------------------------------
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "class") node.className = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
function replace(node, ...children) { node.replaceChildren(...children.flat().filter(Boolean)); }
function tag(text, kind) { return el("span", { class: `tag ${kind || ""}` }, text); }
const STATUS_KIND = { succeeded: "ok", queued: "info", running: "info", awaiting_approval: "warn",
  denied: "bad", failed: "bad", rejected: "bad", cancelled: "" };
function statusTag(s) { return tag(s.replaceAll("_", " "), STATUS_KIND[s] || ""); }
function when(iso) { return iso ? new Date(iso).toLocaleString() : "—"; }

// --- API ----------------------------------------------------------------------------
class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
async function call(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: opts.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => null);
  if (res.ok) return data;
  const d = data && data.detail;
  if (d && typeof d === "object" && !Array.isArray(d)) throw new ApiError(res.status, d.code || "error", d.message || "Request failed.");
  if (Array.isArray(d) && d.length) throw new ApiError(res.status, "validation_error", `${(d[0].loc || []).filter((p) => p !== "body").join(".")}: ${d[0].msg}`);
  throw new ApiError(res.status, "error", `Request failed (${res.status}).`);
}
async function api(path, opts) {
  try {
    return await call(path, opts);
  } catch (e) {
    if (e.code === "step_up_required" && (await stepUp())) return call(path, opts);
    if (e.status === 401) { state.me = null; render(); }
    throw e;
  }
}
const wsPath = (p) => `/api/workspaces/${state.ws}${p}`;

function stepUp() {
  return new Promise((resolve) => {
    const dlg = $("stepup"), form = $("stepup-form"), input = $("stepup-code"), err = $("stepup-error");
    input.value = ""; err.textContent = "";
    const done = (ok) => { form.onsubmit = null; $("stepup-cancel").onclick = null; dlg.close(); resolve(ok); };
    $("stepup-cancel").onclick = () => done(false);
    dlg.oncancel = () => done(false);
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      try {
        await call("/api/auth/mfa/verify", { method: "POST", body: { code: input.value.trim() } });
        done(true);
        refreshStatus();
      } catch (e) { err.textContent = e.message; }
    };
    dlg.showModal(); input.focus();
  });
}

// Runs an action, shows its error next to `out`, and (by default) refreshes the view.
async function act(out, fn, refresh = true) {
  out.textContent = "";
  try { await fn(); if (refresh) await reload(); } catch (e) { out.textContent = e.message; }
}

// --- Session ------------------------------------------------------------------------
async function boot() {
  try { state.me = await call("/api/auth/me"); } catch { state.me = null; }
  const owned = state.me ? state.me.workspaces.filter((w) => w.role === "owner") : [];
  state.ws = owned.length ? (owned.find((w) => w.id === state.ws) || owned[0]).id : null;
  render();
  if (state.ws) { await refreshStatus(); await reload(); }
}

async function refreshStatus() {
  try { state.status = await api(wsPath("/blacksite/status")); } catch { state.status = null; }
  renderSession();
}

function renderSession() {
  const s = $("session");
  if (!state.me) return replace(s);
  const owned = state.me.workspaces.filter((w) => w.role === "owner");
  const st = state.status;
  const fresh = st && st.mfa_verified_at ? new Date(new Date(st.mfa_verified_at).getTime() + 15 * 60000) : null;
  replace(s,
    owned.length > 1 ? el("select", { "aria-label": "Workspace", onchange: (e) => { state.ws = e.target.value; boot(); } },
      owned.map((w) => el("option", { value: w.id, selected: w.id === state.ws }, w.name))) : null,
    el("span", {}, state.me.user.display_name),
    st ? tag(st.review_recorded ? `Review: ${st.review_reference}` : "Review not recorded: execution off", st.review_recorded ? "ok" : "bad") : null,
    st ? tag(st.approval_policy === "single_operator" ? "Single operator" : "Two-person", "info") : null,
    fresh ? el("span", { class: "muted" }, `2FA fresh until ${fresh.toLocaleTimeString()}`) : null,
    el("button", { class: "small", onclick: async () => { await call("/api/auth/logout", { method: "POST" }).catch(() => {}); boot(); } }, "Sign out"),
    el("button", { class: "small", onclick: async () => { if (confirm("Sign out every session of your account?")) { await call("/api/auth/logout-all", { method: "POST" }).catch(() => {}); boot(); } } }, "Sign out everywhere"),
  );
}

function signInView() {
  const err = el("p", { class: "error", role: "alert" });
  const email = el("input", { type: "email", autocomplete: "username", required: true });
  const password = el("input", { type: "password", autocomplete: "current-password", required: true });
  const code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, required: true });
  return el("div", { class: "panel", style: null },
    el("h1", {}, "Sign in to BLACKSITE"),
    el("p", { class: "muted" }, "Workspace owners only. Reached through the SSH tunnel on this machine's loopback address."),
    el("form", { onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = "";
      try {
        await call("/api/auth/login", { method: "POST", body: { email: email.value, password: password.value, totp_code: code.value.trim() } });
        boot();
      } catch (e) { err.textContent = e.message; }
    } },
      el("div", { class: "row" }, el("label", {}, "Email", email), el("label", {}, "Password", password), el("label", {}, "Authenticator code", code)),
      err, el("button", { class: "primary", type: "submit" }, "Sign in")));
}

// --- Rendering ------------------------------------------------------------------------
function render() {
  renderSession();
  const app = $("app");
  if (!state.me) return replace(app, signInView());
  if (!state.ws) return replace(app, el("div", { class: "panel" }, el("h1", {}, "Restricted"), el("p", { class: "muted" }, "BLACKSITE is limited to workspace owners.")));
  const tabs = [["probes", "Probe deck"], ["approvals", "Approvals"], ["playbooks", "Lab playbooks"]];
  replace(app,
    el("div", { class: "tabs", role: "tablist" }, tabs.map(([k, label]) =>
      el("button", { role: "tab", "aria-selected": String(state.tab === k), onclick: () => { state.tab = k; render(); reload(); } }, label))),
    el("div", { id: "view" }));
}

async function reload() {
  if (!state.ws || !$("view")) return;
  clearTimeout(state.timer);
  try {
    if (state.tab === "probes") await renderProbes();
    else if (state.tab === "approvals") await renderApprovals();
    else await renderPlaybooks();
  } catch (e) {
    replace($("view"), el("p", { class: "error", role: "alert" }, e.message));
  }
}

// Polls only the given part of the page, so forms being filled in are never replaced.
function scheduleRefresh(busy, fn) {
  clearTimeout(state.timer);
  if (busy) state.timer = setTimeout(fn, 3000);
}

// --- Probe deck -----------------------------------------------------------------------
async function renderProbes() {
  const [targets, probes] = await Promise.all([api(wsPath("/blacksite/targets")), api(wsPath("/blacksite/probes"))]);
  state.targets = targets; state.probes = probes;
  replace($("view"), el("div", { class: "grid two" },
    el("div", {}, targetsPanel(), composerPanel()),
    el("div", {}, el("div", { id: "history" }, historyPanel()), el("div", { id: "result" }))));
  if (state.selected) showResult(state.selected);
  scheduleRefresh(probes.some((p) => ["queued", "running"].includes(p.status)), pollProbes);
}

async function pollProbes() {
  if (state.tab !== "probes" || !$("history")) return;
  try {
    state.probes = await api(wsPath("/blacksite/probes"));
    replace($("history"), historyPanel());
    if (state.selected) await showResult(state.selected);
  } catch { /* the next manual action shows errors */ }
  scheduleRefresh(state.probes.some((p) => ["queued", "running"].includes(p.status)), pollProbes);
}

function targetsPanel() {
  const items = state.targets.flatMap((p) => p.assets.map((a) => ({ p, a })));
  return el("section", { class: "panel", "aria-label": "Lab targets" },
    el("h2", {}, "Lab targets"),
    items.length === 0
      ? el("p", { class: "muted" }, "No registered lab assets. Register the lab address in the hosted app's Target Registry, in a project with an authorized lab scope.")
      : el("ul", { class: "targets" }, items.map(({ p, a }) => el("li", {},
          el("button", { "aria-pressed": String(state.asset && state.asset.id === a.id), disabled: !a.in_scope,
            onclick: () => { state.asset = a; state.project = p; renderProbes(); } },
            el("span", { class: "mono" }, a.value), " · ", `${p.organization_name} — ${p.name}`, " ",
            a.in_scope ? el("span", { class: "muted" }, `ports ${a.allowed_ports.join(", ")} · ${a.max_rps}/s · ${a.daily_budget}/day`)
              : tag(a.reason || "Not in scope", "bad"))))));
}

function composerPanel() {
  const a = state.asset;
  if (!a) return el("section", { class: "panel" }, el("h2", {}, "New probe"), el("p", { class: "muted" }, "Pick a lab target first. Targets are chosen from the registry only."));
  const err = el("p", { class: "error", role: "alert" });
  const type = el("select", { "aria-label": "Probe type" }, ["http", "tcp", "tls"].map((t) => el("option", { value: t }, t.toUpperCase())));
  const scheme = el("select", {}, ["http", "https"].map((s) => el("option", { value: s }, s)));
  const method = el("select", {}, ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].map((m) => el("option", { value: m }, m)));
  const path = el("input", { value: "/", maxlength: 2001 });
  const port = el("select", {}, el("option", { value: "" }, "default"), a.allowed_ports.map((p) => el("option", { value: p }, p)));
  const ports = el("fieldset", { class: "row" }, el("legend", { class: "muted" }, "TCP ports"),
    a.allowed_ports.map((p) => el("label", { class: "check" }, el("input", { type: "checkbox", value: p, checked: true }), String(p))));
  const headers = el("textarea", { placeholder: "Header-Name: value (one per line)", spellcheck: "false" });
  const body = el("textarea", { placeholder: "Request body (POST/PUT/PATCH/DELETE only)", spellcheck: "false" });
  const confirmState = el("input", { type: "checkbox" });
  const approve = el("input", { type: "checkbox", checked: true });
  const httpOnly = [scheme, method, path, headers, body];
  const sync = () => {
    const t = type.value;
    for (const f of httpOnly) f.closest("label").hidden = t !== "http";
    port.closest("label").hidden = t === "tcp"; ports.hidden = t !== "tcp";
    confirmState.closest("label").hidden = !(t === "http" && !["GET", "HEAD", "OPTIONS"].includes(method.value));
  };
  type.onchange = sync; method.onchange = sync;
  const form = el("form", { onsubmit: (ev) => { ev.preventDefault(); act(err, async () => {
    const spec = { type: type.value };
    if (type.value === "tcp") spec.ports = [...ports.querySelectorAll("input:checked")].map((i) => Number(i.value));
    else if (port.value) spec.port = Number(port.value);
    if (type.value === "http") {
      Object.assign(spec, { scheme: scheme.value, method: method.value, path: path.value });
      const hs = {};
      for (const line of headers.value.split("\n").map((l) => l.trim()).filter(Boolean)) {
        const i = line.indexOf(":");
        if (i < 1) throw new Error(`Header line needs "Name: value": ${line.slice(0, 40)}`);
        hs[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      }
      spec.headers = hs;
      if (body.value) spec.body = body.value;
    }
    const op = await api(wsPath("/blacksite/probes"), { method: "POST", body: {
      project_id: state.project.id, asset_id: a.id, spec, approve: approve.checked, confirm_state_change: confirmState.checked } });
    state.selected = op.id;
  }); } },
    el("div", { class: "row" }, el("label", {}, "Type", type), el("label", {}, "Scheme", scheme), el("label", {}, "Method", method), el("label", {}, "Port", port)),
    el("label", {}, "Path", path), ports, el("label", {}, "Headers (Host, User-Agent and hop-by-hop headers are refused)", headers), el("label", {}, "Body", body),
    el("label", { class: "check" }, confirmState, "I confirm this request can change state on the lab target"),
    el("label", { class: "check" }, approve, "Approve now (single operator; recorded as my approval)"),
    err, el("button", { class: "primary", type: "submit" }, "Send probe"));
  const panel = el("section", { class: "panel", "aria-label": "New probe" },
    el("h2", {}, "New probe → ", el("span", { class: "mono" }, a.value)),
    el("p", { class: "muted" }, `Scope v${state.project.scope_version}. Redirects are recorded, never followed. Authorization and Cookie values are redacted in evidence.`),
    form);
  sync();
  return panel;
}

function historyPanel() {
  const err = el("p", { class: "error", role: "alert" });
  const rows = state.probes.map((p) => {
    const actions = [];
    if (p.status === "awaiting_approval") {
      actions.push(el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/operations/${p.id}/approve`), { method: "POST", body: { reason: "Approved in BLACKSITE" } })) }, "Approve"));
      actions.push(el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/operations/${p.id}/reject`), { method: "POST", body: { reason: "" } })) }, "Reject"));
    }
    if (["awaiting_approval", "queued"].includes(p.status)) actions.push(el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/operations/${p.id}/cancel`), { method: "POST" })) }, "Cancel"));
    if (!["awaiting_approval", "queued", "running"].includes(p.status)) actions.push(el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/blacksite/probes/${p.id}/replay`), { method: "POST", body: {} })) }, "Replay"));
    const cmp = el("input", { type: "checkbox", "aria-label": "Select for compare", checked: state.compare.includes(p.id), disabled: p.status !== "succeeded",
      onchange: (e) => { state.compare = e.target.checked ? [...state.compare, p.id].slice(-2) : state.compare.filter((x) => x !== p.id); replace($("history"), historyPanel()); } });
    return el("tr", { class: state.selected === p.id ? "selected" : null },
      el("td", {}, cmp), el("td", { class: "mono" }, p.target), el("td", {}, p.risk_class), el("td", {}, statusTag(p.status)),
      el("td", { class: "muted" }, when(p.queued_at)),
      el("td", {}, el("button", { class: "small", onclick: () => { state.selected = p.id; showResult(p.id); } }, "View"), actions));
  });
  return el("section", { class: "panel", "aria-label": "Probe history" },
    el("div", { class: "row" }, el("h2", {}, "History"),
      el("button", { class: "small", disabled: state.compare.length !== 2, onclick: () => compare(err) }, "Compare selected")),
    err,
    state.probes.length === 0 ? el("p", { class: "muted" }, "No probes yet.")
      : el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {}, ["", "Target", "Risk", "Status", "Requested", ""].map((h) => el("th", {}, h)))), el("tbody", {}, rows))));
}

function decodeBody(b64) {
  try {
    const bytes = Uint8Array.from(atob(b64 || ""), (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 65536));
  } catch { return "(not decodable)"; }
}

async function showResult(id) {
  const box = $("result");
  if (!box) return;
  try {
    const { operation: op, record } = await api(wsPath(`/blacksite/probes/${id}/result`));
    const parts = [el("h2", {}, "Result ", statusTag(op.status))];
    if (op.denial_reason) parts.push(el("p", { class: "error" }, `Refused: ${op.denial_reason}`));
    if (op.error) parts.push(el("p", { class: "error" }, `Failed: ${op.error}`));
    if (record) {
      const r = record.result || {};
      const spec = record.spec || {};
      parts.push(el("p", { class: "mono" }, `${spec.type === "http" ? `${spec.method} ` : ""}${record.target} → ${record.connected_ip}`));
      if (spec.type === "http") {
        parts.push(el("p", {}, "HTTP ", el("strong", {}, String(r.status)), ` · ${r.elapsed_ms} ms · ${r.body_bytes} bytes${r.body_truncated ? " (truncated)" : ""}`,
          r.location ? el("span", {}, " · Location (not followed): ", el("span", { class: "mono" }, r.location)) : null));
        parts.push(el("h3", {}, "Response headers"), el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, (r.headers || []).map(([k, v]) => el("tr", {}, el("td", { class: "mono" }, k), el("td", { class: "mono" }, v)))))));
        if (r.tls) parts.push(el("h3", {}, "TLS"), el("pre", {}, JSON.stringify(r.tls, null, 2)));
        parts.push(el("h3", {}, "Body (shown as text, never rendered)"), el("pre", {}, decodeBody(r.body_base64)), el("p", { class: "muted mono" }, `sha256 ${r.body_sha256}`));
      } else {
        parts.push(el("pre", {}, JSON.stringify(r, null, 2)));
      }
      if (op.status === "succeeded" && ["http", "tls"].includes(spec.type)) {
        const out = el("div");
        const err = el("p", { class: "error", role: "alert" });
        parts.push(el("h3", {}, "BLACK ICE"),
          el("p", { class: "muted" }, "Runs the deterministic finding rules over this result. Findings start unverified; existing ones are linked, not duplicated."),
          el("button", { onclick: () => act(err, async () => {
            const res = await api(wsPath(`/blacksite/probes/${op.id}/submit`), { method: "POST" });
            replace(out, res.findings.length === 0 ? el("p", { class: "muted" }, `No rule matched (${res.ruleset}).`)
              : el("ul", {}, res.findings.map((f) => el("li", {}, tag(f.severity, f.severity === "high" || f.severity === "critical" ? "bad" : f.severity === "medium" ? "warn" : "info"), " ", f.title, " ", el("span", { class: "muted" }, `· ${f.validation_status} · ${f.change.replace("_", " ")}`)))));
          }, false) }, "Submit to BLACK ICE"), err, out);
      }
    } else if (["awaiting_approval", "queued", "running"].includes(op.status)) {
      parts.push(el("p", { class: "muted" }, "No result yet. The lab worker runs approved probes; this page refreshes while one is queued."));
    }
    replace(box, el("section", { class: "panel", "aria-label": "Probe result" }, parts));
  } catch (e) { replace(box, el("p", { class: "error" }, e.message)); }
}

async function compare(err) {
  try {
    const [a, b] = state.compare;
    const out = await api(wsPath(`/blacksite/probes/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`));
    replace($("result"), el("section", { class: "panel", "aria-label": "Comparison" },
      el("h2", {}, "Compare"), el("p", { class: "mono" }, out.target),
      Object.keys(out.differences).length === 0 ? el("p", { class: "muted" }, "No differences.") : el("pre", {}, JSON.stringify(out.differences, null, 2))));
  } catch (e) { err.textContent = e.message; }
}

// --- Approvals ------------------------------------------------------------------------
async function renderApprovals() {
  const [ops, runs] = await Promise.all([api(wsPath("/operations?status=awaiting_approval")), api(wsPath("/blackops/runs?limit=50"))]);
  const waitingRuns = runs.filter((r) => r.status === "awaiting_approval");
  const err = el("p", { class: "error", role: "alert" });
  const reason = el("input", { maxlength: 1000, placeholder: "Reason (recorded with each decision)" });
  replace($("view"), el("section", { class: "panel" },
    el("h2", {}, "Waiting for a decision"),
    el("p", { class: "muted" }, "Lab work is decided here only. Each decision needs a two-factor code from the last 15 minutes and is recorded under your name."),
    el("label", {}, "Reason", reason), err,
    el("h3", {}, "Operations"),
    ops.length === 0 ? el("p", { class: "muted" }, "Nothing waiting.") : el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, ops.map((o) => el("tr", {},
      el("td", {}, o.tool_label), el("td", { class: "mono" }, o.target), el("td", {}, o.risk_class), el("td", { class: "muted" }, `${o.project_name} · scope v${o.scope_version}`),
      el("td", {}, el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/operations/${o.id}/approve`), { method: "POST", body: { reason: reason.value } })) }, "Approve"),
        el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/operations/${o.id}/reject`), { method: "POST", body: { reason: reason.value } })) }, "Reject"))))))),
    el("h3", {}, "Playbook runs"),
    waitingRuns.length === 0 ? el("p", { class: "muted" }, "Nothing waiting.") : el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, waitingRuns.map((r) => el("tr", {},
      el("td", {}, `${r.playbook_name} v${r.playbook_version}`), el("td", { class: "mono" }, r.target), el("td", {}, `${r.steps.length} step(s)`),
      el("td", {}, el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/blackops/runs/${r.id}/approve`), { method: "POST", body: { reason: reason.value } })) }, "Approve"),
        el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/blackops/runs/${r.id}/reject`), { method: "POST", body: { reason: reason.value } })) }, "Reject")))))))),
    el("button", { onclick: () => reload() }, "Refresh"));
}

// --- Lab playbooks --------------------------------------------------------------------
async function renderPlaybooks() {
  const [lib, runs, targets] = await Promise.all([api(wsPath("/blackops/playbooks")), api(wsPath("/blackops/runs?limit=25")), api(wsPath("/blacksite/targets"))]);
  const labBooks = lib.playbooks.filter((p) => p.profiles.includes("lab") && p.availability === "available");
  const assets = targets.flatMap((p) => p.assets.filter((a) => a.in_scope).map((a) => ({ p, a })));
  const err = el("p", { class: "error", role: "alert" });
  const book = el("select", { "aria-label": "Playbook" }, labBooks.map((p) => el("option", { value: p.id }, `${p.name} v${p.version}`)));
  const target = el("select", { "aria-label": "Lab target" }, assets.map(({ p, a }, i) => el("option", { value: i }, `${a.value} · ${p.name}`)));
  const checks = el("div");
  let pre = null;
  const run = async () => act(err, async () => {
    const { p, a } = assets[Number(target.value)];
    pre = await api(wsPath(`/blackops/projects/${p.id}/preflight`), { method: "POST", body: { playbook_id: book.value, target: a.value } });
    replace(checks, el("ul", { class: "checks" }, pre.checks.map((c) => el("li", {}, tag(c.status === "pass" ? "✓ pass" : c.status === "fail" ? "✕ fail" : "ℹ note", c.status === "pass" ? "ok" : c.status === "fail" ? "bad" : "info"), " ", el("strong", {}, c.label), " — ", c.detail))),
      pre.allowed ? el("button", { class: "primary", onclick: () => act(err, async () => {
        if (!confirm(`Launch ${book.value} against ${pre.target} (scope v${pre.scope_version})?`)) return;
        await api(wsPath(`/blackops/projects/${p.id}/runs`), { method: "POST", body: { playbook_id: book.value, target: a.value, version: pre.version, definition_sha256: pre.definition_sha256 } });
        replace(checks);
      }) }, "Launch") : el("p", { class: "error" }, "Preflight failed: nothing can be launched."));
  }, false);
  replace($("view"), el("div", { class: "grid two" },
    el("section", { class: "panel", "aria-label": "Launch" }, el("h2", {}, "Launch a lab playbook"),
      labBooks.length && assets.length ? el("div", {}, el("div", { class: "row" }, el("label", {}, "Playbook", book), el("label", {}, "Target", target),
        el("button", { onclick: run }, "Run preflight")), err, checks)
        : el("p", { class: "muted" }, "Needs a lab-capable playbook that's enabled and an in-scope lab target.")),
    el("section", { class: "panel", "aria-label": "Runs" }, el("div", { class: "row" }, el("h2", {}, "Lab runs"), el("button", { class: "small", onclick: () => reload() }, "Refresh")),
      el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, runs.map((r) => el("tr", {},
        el("td", {}, `${r.playbook_name} v${r.playbook_version}`), el("td", { class: "mono" }, r.target), el("td", {}, statusTag(r.status)),
        el("td", {}, `${r.steps.filter((s) => s.status === "succeeded").length}/${r.steps.length}`), el("td", { class: "muted" }, when(r.created_at)),
        el("td", {}, ["awaiting_approval", "running"].includes(r.status) ? el("button", { class: "small", onclick: () => act(err, () => api(wsPath(`/blackops/runs/${r.id}/cancel`), { method: "POST" })) }, "Cancel") : null)))))))));
}

document.addEventListener("DOMContentLoaded", boot);
