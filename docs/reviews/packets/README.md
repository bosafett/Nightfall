# Review packets: BLACKSITE, lab tool pack 1, Profile B

Three features are built and **switched off** until a review is recorded:

| Feature | Switch it unlocks | Packet |
|---|---|---|
| BLACKSITE (isolated lab; WARPATH depends on it) | `NIGHTFALL_BLACKSITE_REVIEW_REF` | [1-blacksite.md](1-blacksite.md) |
| Lab tool pack 1 (wider Nuclei templates, lab only) | `NIGHTFALL_LAB_PACK1_REVIEW_REF` | [2-lab-tool-pack-1.md](2-lab-tool-pack-1.md) |
| Profile B (controlled validation on real targets) | `NIGHTFALL_PROFILE_B_REVIEW_REF` | [3-profile-b.md](3-profile-b.md) |

Each packet says what's in scope and what isn't, which safety claims the system makes, where each one is
enforced (code and database), which test proves it, and what to check by hand. A reviewer works through the
checklist and fills in the report template below.

## Independent review or self-review

The project's rules (set by the owner) say automated tests and self-review are **not** independent sign-off,
and that restricted capabilities stay off until the appropriate review is recorded. At the time of writing the
owner is the only person on the project.

- **Self-review (owner):** useful. Work through the packet, fix what you find, and record the result in
  `docs/reviews/` as a *self-review*. It **doesn't** go into the `*_REVIEW_REF` variables: they mean an
  independent review.
- **Independent review:** someone who didn't build the system and isn't the owner or a second account of the
  owner. With a completed self-review and these packets, the job is small and bounded. Do the cheapest first
  (lab tool pack 1, then BLACKSITE, then Profile B).
- **Temporary self-review mode (owner decision, 2026-11-08):** while the owner is the only person on the project,
  a review reference starting `SELF:` (e.g. `SELF:2026-11-08 owner, docs/reviews/2026-11-08-blacksite-self-review.md`)
  switches a feature on, but **only** while `NIGHTFALL_SELF_REVIEW_UNTIL` is set to a date that hasn't passed. That
  date can be at most 90 days ahead. After it, self-reviews switch nothing on, with no action needed.
  - **It's never presented as independent.** Preflight checks, the BLACK OPS library, the BLACKSITE console and the
    audit trail (`review_kind: self`) all say "self-review, not independent".
  - **Every other gate is unchanged:** owner only, fresh two-factor, lab network, proof of control, sealed
    credentials, approvals, worker re-checks.
  - **To end it early,** unset `NIGHTFALL_SELF_REVIEW_UNTIL` or record an independent reference.

## Before you start

```bash
git clone https://github.com/bosafett/Nightfall && cd Nightfall
git log -1 --format='%H %cI'   # record this commit in your report
```

Run the suites (needs Postgres 16 with the dev roles; see `api/README` and `README.md`):

```bash
cd api && python -m venv .venv && .venv/bin/pip install -r requirements.lock -e . && .venv/bin/python -m pytest -q
```

```bash
cd web && npm ci && npx vitest run && npx playwright test --trace off
```

Each packet lists the specific test files for its feature, so you can run just those.

## Report template

Copy this to `docs/reviews/YYYY-MM-DD-<feature>-review.md`.

```markdown
# <Feature> review

| | |
|---|---|
| Reviewer | <name>, <independent / self-review> |
| Commit reviewed | <sha> (<date>) |
| Packet | docs/reviews/packets/<file> |
| Result | Approved / Approved with conditions / Not approved |
| Reference for the switch | <e.g. REV-2026-12-01> (independent reviews only) |

## What I checked
<Checklist items, each: OK / finding number / not checked (why)>

## Findings
### R1 (<severity>): <title>
What, where, why it matters, what would fix it.

## Conditions (if approved with conditions)
<What must be true before or while it's switched on>
```
