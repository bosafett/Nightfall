# Lab tool pack 1: evidence for the owner's self-review

> **This is evidence, not a review.** It was collected by the AI assistant that helped build the system, to save the
> reviewer time. It switches nothing on. The verdict, the answers to the packet's questions and any conditions are the
> owner's, recorded in `docs/reviews/<date>-lab-tool-pack-1-self-review.md` (template at the end). A self-review is
> **not independent**.

| | |
|---|---|
| Packet | `docs/reviews/packets/2-lab-tool-pack-1.md` |
| Collected | 2026-11-09 |
| Code | the commit that adds this file (import rules v2, playbook `known-weakness-scan-lab` 1.1.0) |
| Manifest | `api/nightfall/tools/nuclei/pack1.json`, SHA-256 `556b84370c5e6861752d37cd2de0b5a01f6be7a9811df8a290f67aaae7404e7f` |
| Source | `nuclei-templates` v10.5.1, commit `79fb682760ab3d5b0e22afbb44709353cbebf023` |

## What changed while collecting this evidence

Hand check 2 (sampling templates) found that rules v1 let through templates that **perform** the action they test
for. These were fixed **before** this review, and the fix is part of what's being reviewed:

| Found | What it does | Why v1 missed it |
|---|---|---|
| `CVE-2020-36333` (ThemeGrill Demo Importer) | resets a WordPress database | rules looked at tags and PUT/DELETE/PATCH only |
| `CVE-2024-6846` (SmartSearchWP) | purges the plugin's error logs | same |
| `unauthenticated-varnish-cache-purge` | sends HTTP `PURGE` (empties the cache) | PURGE wasn't a dropped method |
| `CVE-2018-7600` (Drupal `user/register`), BuddyPress, Pie Register | create accounts or sessions | same |
| `CVE-2020-11515` (Rank Math `updateRedirection`) | creates a redirect | random value nested inside `to_lower(...)`, which the random-value rule missed |

**Rules v2** (design §13): only GET, HEAD, POST and OPTIONS; no request naming a state-changing action; no POST
naming a write; random values caught inside other functions. **222 templates removed; 5,566 remain** (CVE 2,464;
exposure 1,198; technology 1,183; misconfiguration 377; default login 269; takeover 75).

## Automated tests (local Postgres 16, PyYAML installed so the import-rule test runs)

| Command | Result |
|---|---|
| Packet command: `test_lab_pack1.py test_nuclei.py test_egress.py` | **37 passed, 1 skipped** (`test_nuclei.py:183` needs a real Nuclei binary) |
| Related: `test_lab.py test_blackops.py test_warpath.py` | **41 passed** |
| Whole backend suite, ruff, mypy | all passed |

## Hand checks (packet §3)

| # | Check | Evidence | Status |
|---|---|---|---|
| 1 | Re-run the import and compare | Re-ran `import_nuclei_pack.py` against a fresh clone of v10.5.1 (commit `79fb6827…`): output is **byte-for-byte identical** to the committed manifest (same SHA-256), both before and after rules v2 | Evidence collected |
| 2 | Sample 30 random templates, and every default-login template | 30 sampled (seed 20261109): detection GETs, XSS/LFI/SQLi probes, config and secret exposures, one default login. One (CVE-2020-11515) wrote data; fixed by rules v2. Default login: 269 kept; most POST a vendor default password to a login form. All 269 pass rules v2, so none of their requests names a delete, reset or write action (the assistant didn't read all 269) | **Owner to judge** (see L2, L3) |
| 3 | Dropped counts; spot-check dropped `intrusive` templates | Manifest `counts.dropped`: category 2,965; not HTTP 1,892; other protocol 1,383; self-contained 938; out-of-band or random 554; dropped tag 344; state-changing request 175; unknown severity 59; method 13; fuzzing or method 8 | Evidence collected; spot-check is the owner's |
| 4 | Build the image; fails if a template is edited | Not built here (no Docker). Ran the image's staging step (`stage_nuclei_pack.py`) directly: it staged **5,566** templates from the pinned clone; with one template edited it stopped with `hash mismatch` (exit 1). The lab machine rebuilds the image anyway (`up -d --build`) | Staging verified; image build on the lab machine |
| 5 | Network templates excluded in v1 | Excluded: the egress proxy carries HTTP only | **Owner's opinion** |

## Findings for the owner to rate

- **L1 (fixed before review):** rules v1 kept templates that change state (table above). Fixed by rules v2; tests in
  `test_lab_pack1.py::test_import_rules_drop_what_the_design_excludes`.
- **L2 (residual):** word rules can't prove that no template changes state. A template can still write through an
  endpoint whose name says nothing about it. Mitigation in the design: lab only, practice apps, and recreate the app's
  container after a pack run. Suggested condition: accept for the lab, with that habit.
- **L3 (by design):** the 269 default-login templates try vendor default passwords. On a product with lockout they could
  lock the account. Lab only; approved in design §11 decision 3.

## Questions (packet §4): for the owner to answer

- Is any kept template capable of changing state on a target in a way that matters for a practice lab?
- Could a template reach a host other than the target despite the proxy and the lab network?
- Are 10 requests per second, 30 minutes and 3,000 templates per run reasonable for the lab machine?

## Recording the result

Save the owner's review as `docs/reviews/<date>-lab-tool-pack-1-self-review.md`, with: reviewer (owner, self-review,
not independent), this evidence file, the result (approved, approved with conditions, or not approved), the answers
above, and any conditions. Then, if approved, set in **both** `infra/lab/lab.env` and `infra/lab/blacksite.env`:

```
LAB_PACK1_REVIEW_REF=SELF:<date> owner, docs/reviews/<date>-lab-tool-pack-1-self-review.md      (lab.env)
NIGHTFALL_LAB_PACK1_REVIEW_REF=SELF:<date> owner, docs/reviews/<date>-lab-tool-pack-1-self-review.md   (blacksite.env)
```
