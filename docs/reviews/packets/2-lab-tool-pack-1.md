# Review packet 2: lab tool pack 1 (wider Nuclei templates, lab only)

**Unlocks:** `NIGHTFALL_LAB_PACK1_REVIEW_REF` on the lab machine. It also needs BLACKSITE (packet 1).
**Design:** [../../designs/2026-11-lab-tool-pack-1.md](../../designs/2026-11-lab-tool-pack-1.md) (§10–§12:
decisions and as built). **Smallest of the three reviews**: start here.

## 1. The question

> Are the 5,788 templates the right ones (nothing destructive, out-of-band or aimed at other hosts), pinned so they
> can't change unseen, and run only in the lab within the agreed limits?

**In scope:**
- the import rules (`infra/tools/import_nuclei_pack.py`);
- the manifest (`api/nightfall/tools/nuclei/pack1.json`);
- image staging (`infra/tools/stage_nuclei_pack.py`, `infra/tools/Dockerfile`);
- the runtime checks (`api/nightfall/tools/nuclei/pack1.py`, `NucleiPackScan` in `api/nightfall/recon/collectors.py`);
- finding rule R17.

**Out of scope:** BLACKSITE itself (packet 1); the four curated templates of Profile A (already in use).

## 2. Claims, enforcement and evidence

| # | Claim | Enforced in | Test(s) |
|---|---|---|---|
| P1 | Only HTTP templates in the kept categories. None tagged dos, fuzz, intrusive, bruteforce or osint; none self-contained, using JavaScript or code, flow or workflows; no interactsh, `{{rand_…}}`, PUT, DELETE or PATCH | `import_nuclei_pack.py` (`reason_to_drop`) | `test_lab_pack1.py::test_import_rules_drop_what_the_design_excludes` (skipped without PyYAML; run with it) |
| P2 | Every template is pinned by SHA-256 in a reviewed manifest from release v10.5.1, commit `79fb6827…` | `pack1.json`; the commit is checked by `stage_nuclei_pack.py` | `::test_manifest_rules_and_groups` |
| P3 | The image carries only listed templates, each hash-checked | `stage_nuclei_pack.py`, `Dockerfile` (`pack1` stage) | (build the image; see §3) |
| P4 | Every run re-checks every hash; one mismatch or missing file and nothing runs | `pack1.verified_paths` | `::test_pack_runs_only_with_review_and_verified_templates` |
| P5 | Unavailable without BLACKSITE and the pack's own review; never offered as a single collection | `pack1.unavailable_reason`, `blackops/routes.py` (`_unavailable_tools`), `recon/routes.py` (`PLAYBOOK_ONLY`) | `::test_registered_as_moderate_lab_only_and_never_a_single_collection`, `test_blackops.py::test_library_shows_availability_and_who_may_run` |
| P6 | Moderate risk, lab scopes only; groups of at most 3,000 templates | `blackops/catalog.py` (`check_catalog`), migration `0020` trigger | `::test_manifest_rules_and_groups`, `test_lab.py::test_moderate_risk_needs_a_lab_scope` |
| P7 | Limits: 10 requests per second, 10 at once, 30 minutes, no out-of-band callbacks, no redirects, HTTP only, through the scope proxy | `pack1.build_invocation`, `NucleiScan`/`EgressProxy` | `::test_invocation_limits_and_output_handling`, `test_egress.py::*` |
| P8 | Output is untrusted: only listed ids matched on the target are kept, and wording comes from the manifest | `tools/nuclei/__init__.py` (`parse` with `pack1.lookup`), `finding_rules._from_pack1` | `::test_invocation_limits_and_output_handling`, `::test_findings_use_manifest_wording` |

## 3. Things to check by hand

1. **Re-run the import yourself** and compare it with the committed manifest:
   ```bash
   git clone --depth 1 --branch v10.5.1 https://github.com/projectdiscovery/nuclei-templates.git /tmp/nt
   pip install pyyaml && python3 infra/tools/import_nuclei_pack.py /tmp/nt > /tmp/pack1.json
   diff /tmp/pack1.json api/nightfall/tools/nuclei/pack1.json && echo identical
   ```
2. **Sample the kept templates**: e.g. 30 random ones, plus every `default-login` template, which attempt vendor
   default passwords. Are any harmful to a lab app beyond a failed-login record? Any that should have been dropped?
3. **Look at the "dropped" counts** in the manifest header, and spot-check a few dropped `intrusive` templates to
   confirm the rules catch what they claim.
4. **Build the lab tool image** (`docker build -f infra/tools/Dockerfile .`) and confirm it fails if a template is
   edited.
5. **Network templates were excluded in v1**, because the egress proxy carries HTTP only. Agree or disagree.

## 4. Questions to answer in the report

- Is any kept template capable of changing state on a target in a way that matters for a practice lab?
- Could a template reach a host other than the target despite the proxy and the lab network?
- Are 10 requests per second, 30 minutes and 3,000 templates per run reasonable for the lab machines?

**Run these:**

```bash
cd api && .venv/bin/pip install pyyaml && .venv/bin/python -m pytest -q tests/test_lab_pack1.py tests/test_nuclei.py tests/test_egress.py
```
