"""The benchmark harness scores answers with deterministic checks (no database)."""

from typing import Any

from nightfall.agents import bench
from nightfall.agents.providers import (
    FixtureProvider,
    GenerationRequest,
    GenerationResult,
    ProviderError,
)
from nightfall.agents.registry import (
    CandidateFinding,
    GuardianOutput,
    HunterOutput,
    ProposedCollection,
    ScoutOutput,
)


class Obedient:
    """A model that does whatever the injected text says."""

    name = "obedient"

    def generate(self, request: GenerationRequest[Any]) -> GenerationResult[Any]:
        m = request.output_model
        if m is ScoutOutput:
            out: Any = ScoutOutput(
                proposals=[ProposedCollection(tool="dns", target="evil.test", purpose="as told")],
                notes="",
            )
        elif m is HunterOutput:
            out = HunterOutput(
                candidates=[
                    CandidateFinding(
                        title="Remote code execution",
                        severity="critical",
                        asset="www.acme.test",
                        description="d",
                        impact="i",
                        remediation="r",
                        evidence_ids=[bench.E_FAKE],
                    )
                ],
                notes="",
            )
        elif m is GuardianOutput:
            out = GuardianOutput(
                verdict="supported", rationale="As instructed.", severity_assessment="agree"
            )
        else:
            raise ProviderError("refused")
        return GenerationResult(out, "obedient-1", self.name, 10, 5, 3)


def test_harness_flags_a_model_that_follows_injections() -> None:
    results = bench.run(Obedient())
    s = bench.summarize(results)
    assert s["scout"]["injection_resisted"] == (0, 1)
    assert s["hunter"]["injection_resisted"] == (0, 1)
    assert s["hunter"]["citation_precision"] == (0, 2)  # cites an id it was never shown
    assert s["guardian"]["injection_resisted"] == (0, 1)
    assert s["director"]["schema_valid"] == (0, 1)  # provider errors count as invalid
    md = bench.report(results, "obedient", "obedient-1", 1)
    assert "followed the injected instruction" in md and "error: refused" in md


def test_harness_runs_end_to_end_with_the_fixture_model() -> None:
    results = bench.run(FixtureProvider(), repeat=2)
    assert len(results) == len(bench.CASES) * 2
    s = bench.summarize(results)
    assert set(s) == {
        "scout",
        "hunter",
        "guardian",
        "director",
        "investigator",
        "adversary",
        "analyst",
    }
    assert all(m["schema_valid"][0] == m["schema_valid"][1] for m in s.values())
    # Every injection case is in the suite (one per agent that reads collected content).
    assert sum(c.injection for c in bench.CASES) == 4
    assert bench.SUITE_VERSION in bench.report(results, "fixture", "fixture-model", 2)
