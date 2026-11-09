# Lab tool pack 1: wider Nuclei template set, lab only (design for review)

Status: **approved for review 2026-11-07 (decisions in §11). Built 2026-11-07 and switched off: it can't run until
`NIGHTFALL_LAB_PACK1_REVIEW_REF` records an independent review and BLACKSITE is enabled.** §12 lists what the build does
differently from this text. Today JANUS runs 4 of its own Nuclei templates
(`api/nightfall/tools/nuclei/templates`), all low risk, GET only, on live and lab targets. This pack would add a reviewed,
pinned subset of the public `nuclei-templates` collection as a **moderate-risk tool for the isolated lab (Profile C)
only**.

## 1. Why

The lab exists to reproduce known weaknesses on deliberately vulnerable machines. Four templates can't show whether a
lab target has a known CVE, a default login or a common misconfiguration. Thousands of community templates can, but most
are written for detection on real systems, and some are intrusive. This design takes the useful part under the same
controls the current Nuclei adapter uses.

## 2. Gates: all must hold, checked by the API and again by the lab worker

1. **Lab only.**
   - The catalog marks the tool `moderate`, and moderate risk is already refused outside lab scopes. This applies to
     the database check (migration 0010), the collection route and the BLACK OPS catalog.
   - The pack is never registered for live or Profile B targets.
2. **BLACKSITE enabled**, with its review reference recorded (the existing gate). Runs come only from the lab worker,
   which can reach only the lab network.
3. **Its own review:**
   - `NIGHTFALL_LAB_PACK1_REVIEW_REF` must be non-empty. Without it the tool is listed as "unavailable".
   - Tests and self-review don't count as the review.
4. **Per-run approval**, as for every lab run today (lab approvals expire after 24 hours). The approval screen shows the
   pack version, the template count and the categories.

## 3. Templates: chosen by rules, pinned by hash

- **Source:** one tagged release of `projectdiscovery/nuclei-templates` (MIT licence), fetched at image build time, never
  at run time.
- **Import script** (`infra/tools/import-nuclei-pack.py`) applies fixed rules and writes a manifest:
  - **Kept:** `http` and `network` protocol templates tagged `cve`, `misconfig`, `exposure`, `default-login`,
    `takeover` or `tech`.
  - **Dropped:**
    - templates tagged `dos`, `fuzz`, `intrusive`, `bruteforce` or `osint`;
    - anything with `code`, `headless`, `javascript`, `file` or `dns` protocol;
    - workflows;
    - any template using interactsh (out-of-band callbacks) or `{{rand_*}}`-generated destructive bodies;
    - anything sending `PUT`, `DELETE` or `PATCH`.
  - Default-login templates are kept, because lab machines exist to be tested, but they are counted separately on the
    approval screen (owner decision 3).
- **Manifest** (`api/nightfall/tools/nuclei/pack1.json`, reviewed and committed):
  - the release tag;
  - one entry per template: path, SHA-256, id, the template's own severity and name (copied at import), protocol,
    methods and tags.
  - Adding or removing a template means changing the manifest, which means a code review.
- **At run time:**
  - Every template is passed by explicit path and verified against its manifest hash first, as now.
  - Nuclei runs with `-duc` (no update check), `-ni` (no interactsh), `-disable-redirects`, no code or headless
    protocols, `-rl` rate limit, `-c` concurrency limit and `-timeout`.
- **Where the templates live:** the templates themselves stay in the lab tool image (`infra/tools/Dockerfile`), not in
  the API package, so the hosted deployment never carries them. The manifest is small and in the repo.

## 4. Execution limits

- **Rate:** at most 10 requests per second and 10 concurrent templates, through the existing per-run egress proxy,
  pinned to the lab target's address.
- **Time and size:** at most 30 minutes per run and 3,000 templates per run (the pack is split into playbooks by
  category if needed).
- **Stop:** the run stops on operator cancel, approval expiry, scope change, or the proxy refusing a host. As now, a
  connection to anything but the target is refused and counted.
- **Output stays untrusted, as today:**
  - Only the template id and matched URL are kept, and only when the id is in the manifest and the URL's host is the
    target.
  - Titles and severities come from the manifest, never from the tool's output.

## 5. Findings

- Matches become **unverified lab findings**, labelled as lab results.
- BLACK ICE rules map manifest entries to finding rules (ruleset bump). The contradiction flags apply.
- CVE ids from the manifest are shown, with "detected by template, not exploited" wording. A person validates.

## 6. Playbook

Lab playbook "Known-weakness scan (lab)" v1.0.0 has one step, `nuclei-pack1`, and runs under Profile C only. It has its
own fingerprint and tests, like the existing five playbooks.

## 7. Threats and mitigations

| Threat | Mitigation |
|---|---|
| A template harms something outside the lab | Lab worker network confinement, egress proxy pinned to the target, lab-only scope rules (three layers, all existing) |
| A malicious or changed template | Fixed release tag, per-file SHA-256 in a reviewed manifest, verified before every run; no update check |
| Out-of-band data leaving the lab | Interactsh off; templates using it are excluded at import; proxy refuses other hosts |
| Tool output steering the UI or reports | Output reduced to id and URL; everything shown comes from the manifest |
| Pack enabled without review | Separate review reference required; tool listed as unavailable without it |

## 8. Tests required

- **Import:** fixed rules over a small fixture tree, covering every exclusion.
- **Manifest:** the hash check refuses a changed template, and an unlisted template is never passed to Nuclei.
- **Refusals:** the API, the database and the worker each refuse the tool for live scopes. The tool is unavailable
  without the review reference, and without BLACKSITE.
- **Execution:** argv contains the required flags and never `-u` lists from user input. The rate and time limits are
  passed.
- **Output:** matches for other hosts or unlisted ids are dropped.
- **End to end:** a run against the lab's sandbox test server with a fixture template.

## 9. Effort and cost

- No paid services.
- One ruleset bump. No migration is expected, because moderate risk in the lab is already allowed by the schema.
- The lab tool image grows by the pinned template subset (tens of MB).

## 10. Owner decisions needed

1. **Approve this design for review**, or change it.
2. **Who reviews it:** the value for `NIGHTFALL_LAB_PACK1_REVIEW_REF`.
3. **Default-login templates:** include them (lab machines only; recommended), or leave them out of v1.
4. **Limits:** 10 requests per second and 30 minutes per run (recommended), or different values.

## 11. Owner decisions (2026-11-07)

1. **Design:** approved for independent review, as written.
2. **Reviewer:** to be named later. Until a review is recorded, `NIGHTFALL_LAB_PACK1_REVIEW_REF` stays empty and the
   pack is listed as unavailable, even if it's built.
3. **Default-login templates:** included, lab only, and counted separately on the approval screen.
4. **Limits:** as recommended: 10 requests per second, 10 concurrent templates, 30 minutes and 3,000 templates per run.

## 12. As built (2026-11-07)

- **Release:** `nuclei-templates` v10.5.1 (commit `79fb6827…`, published 2026-10-23).
- **Manifest:** `api/nightfall/tools/nuclei/pack1.json` keeps **5,788** templates:

  | Category | Templates |
  |---|---|
  | CVE | 2,668 |
  | Exposure | 1,202 |
  | Technology detection | 1,185 |
  | Misconfiguration | 389 |
  | Default login | 269 |
  | Takeover | 75 |

  The import script records how many were dropped, and why, in the manifest's `counts`.
- **HTTP only:** network (TCP) templates aren't in v1, because the per-run egress proxy carries HTTP only. They would
  fail closed against the sandbox firewall anyway.
- **Three groups**, because 5,788 is over the 3,000-per-run limit. Each is its own moderate-risk tool and playbook step:
  - `nuclei-pack1-cve`: 2,668 templates;
  - `nuclei-pack1-config`: 1,935 templates (exposure, misconfiguration, takeover, and the 269 default-login templates,
    named in the step text the approver sees);
  - `nuclei-pack1-tech`: 1,185 templates.
- **Playbook** `known-weakness-scan-lab` v1.0.0: Profile C only, IP targets (lab scopes are addresses), three steps.
- **Image:** the lab tool image (`infra/tools/Dockerfile`) clones the pinned tag. `infra/tools/stage_nuclei_pack.py`
  checks the commit, copies only the listed templates and checks each hash, then puts them at `/opt/nuclei-pack1`.
  The worker checks every hash again before each run.
- **Findings:** new finding rule R17 (ruleset `findings/2026.11-4`), confidence medium, worded "detected, not
  exploited. Lab result". Names, severities and CVE ids come from the manifest.
- **Where the pack's tools appear:** they aren't offered as single collections on the recon page. In the playbook
  library and the BLACK ICE sources panel they show as unavailable until the gates hold.
- **Tests:** `api/tests/test_lab_pack1.py`. The import-rule test needs PyYAML, so it is skipped where only the API's
  dependencies are installed.

## 13. Import rules v2 (2026-11-09, playbook 1.1.0)

Preparing the self-review evidence turned up kept templates that confirm a weakness by **performing** the action:
`CVE-2020-36333` resets a WordPress database (ThemeGrill Demo Importer), `CVE-2024-6846` purges a plugin's logs,
`unauthenticated-varnish-cache-purge` sends an HTTP `PURGE`, and Drupal's `user/register` check creates an account.
Rules v1 only looked at tags and at PUT, DELETE and PATCH, so these got through. Rules v2 (`lab-pack1-rules/2`) add,
reading each request from the parsed template (structured `path:` entries and raw request lines, after `@`
annotations):

- **methods:** only GET, HEAD, POST and OPTIONS; anything else (PURGE, DEBUG, ...) is dropped;
- **state-changing targets:** no request whose path or query names delete, purge, remove, reset, truncate, wipe,
  destroy, drop, uninstall, shutdown, reboot, restart, kill, clear, register, signup or logout; and no **POST** whose
  target names a write: update, create, upload, insert, save, install, import, write, edit, add, new or set (e.g.
  Rank Math's `updateRedirection`, `createUser`, `newpassword`). Deliberately broad: it also drops harmless checks
  (mostly cross-site scripting checks whose URL happens to contain one of the words).
- **random values:** v1 caught `{{rand_…}}` only at the start of an expression; v2 also catches nested calls such as
  `{{to_lower(rand_text_alpha(5))}}` (44 more templates).

**Result:** 222 templates removed, **5,566** kept: CVE 2,464; exposure 1,198; technology 1,183; misconfiguration
377; default login 269; takeover 75. Groups: `nuclei-pack1-cve` 2,464, `nuclei-pack1-config` 1,919,
`nuclei-pack1-tech` 1,183. The playbook is now `known-weakness-scan-lab` **v1.1.0** (new fingerprint pinned). Re-running
the import against v10.5.1 reproduces the committed manifest byte for byte (SHA-256 `556b8437…`).

**What the rules can't promise.** Word rules catch the obvious cases, not all of them: a template can still change
state on a matching application through an endpoint whose name says nothing about it. Against Juice Shop almost no
CVE template matches anything; against other practice apps, treat the app as disposable and recreate its container
after a pack run (`docker compose --env-file lab.env up -d --force-recreate <app>`).

**Still accepted (not dropped):** the 269 default-login templates try vendor default passwords (they leave failed-login
records, and on some products could lock an account); many CVE checks send requests that prove remote code execution
with a harmless command or an arithmetic expression. Both are lab-only, against practice apps, as decided in §11.
