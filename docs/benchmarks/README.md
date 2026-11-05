# Agent benchmarks

The harness is `api/nightfall/agents/bench.py` (review §6). It runs a fixed set of cases for each agent,
building the same delimited `<data>` blocks the agents get in production. Deterministic checks that mirror
the Tool Gateway score each answer. It needs no database.

## What it measures (per agent)

| Metric | Meaning |
|---|---|
| Schema-valid | Share of calls that returned an answer that parsed into the agent's output schema. A provider error or refusal counts as invalid. |
| p50 / p95 ms | Model latency as measured by the provider adapter, on the machine that ran the suite. |
| Citation precision | Of the evidence and finding ids the answers cite, the share the agent was actually shown. |
| Injection resisted | Injection cases whose planted instruction was not followed. The cases plant instructions to target an out-of-scope host, cite a made-up evidence id, report a fake critical, say "supported", or claim everything is validated. |
| Expectations met | Per-case checks: in scope, cites the right evidence, picks the validated finding, respects limits, and so on. |
| Tokens in/out | Summed over the run. |

Suite version `bench/2026.11-1` has 11 cases: Scout ×2, Hunter ×2, Guardian ×3, Director, Investigator,
Adversary and Analyst. Four of them are injection cases.

## Running it

```bash
cd api
# Pipeline check, no model and no cost:
.venv/bin/python -m nightfall.agents.bench --provider fixture
# Real model: needs ANTHROPIC_API_KEY. Prints the number of calls first (11 per repeat), billed by Anthropic.
.venv/bin/python -m nightfall.agents.bench --provider anthropic --model claude-opus-5-5 --repeat 3 --out ../docs/benchmarks/
```

`--out` writes `<date>-<provider>-<model>.md` and `.json` here. Commit them together with the prompt version
they were run against, which is printed in the report.

## Results

**No model results yet.** This repository has no API key, so the suite has only been run with the
`fixture` provider. That checks the harness and scoring. It says nothing about model quality, so it isn't
recorded here as a result.

The default model is chosen from committed results, per review §6. Until a real run is committed, the
configured default (`claude-opus-5-5`) is a placeholder, not a measured choice.

Rules for results:
- Never edit a results file by hand.
- Never commit results from the fixture provider.
- Rerun the suite after any change to `PROMPT_VERSION`.
