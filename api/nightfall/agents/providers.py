"""Model providers (review §6). Agents depend only on Provider.generate.

AnthropicProvider: Claude through the official SDK, structured outputs (the response is
validated against the agent's output model), server-side refusal fallback. Configured by
NIGHTFALL_AI_PROVIDER=anthropic and ANTHROPIC_API_KEY. With NIGHTFALL_AI_PROVIDER=none
(default) agents are off and everything else works.

Assessment data leaves the deployment when a hosted provider is used: only the delimited
data blocks a task needs are sent, never credentials, sessions or other workspaces' data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

DEFAULT_MODEL = "claude-opus-5-5"


class ProviderError(RuntimeError):
    """The model call failed or returned nothing usable. Safe to show to users."""


class ProviderUnavailable(ProviderError):
    pass


@dataclass(frozen=True)
class GenerationRequest[T: BaseModel]:
    system: str
    user: str
    output_model: type[T]
    effort: str = "medium"
    max_tokens: int = 16000


@dataclass(frozen=True)
class GenerationResult[T: BaseModel]:
    parsed: T
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: int


class Provider(Protocol):
    name: str

    def generate(self, request: GenerationRequest[T]) -> GenerationResult[T]: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, timeout: float = 240.0) -> None:
        import anthropic

        self.model = model
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(timeout=timeout, max_retries=2)

    def generate(self, request: GenerationRequest[T]) -> GenerationResult[T]:
        a = self._anthropic
        started = time.monotonic()
        try:
            response = self.client.messages.parse(
                model=self.model,
                max_tokens=request.max_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                output_format=request.output_model,
                output_config={"effort": request.effort},  # type: ignore[arg-type]
                # On a safety decline, re-run on Anthropic's recommended fallback model.
                extra_headers={"anthropic-beta": "server-side-fallback-2026-07-01"},
                extra_body={"fallbacks": "default"},
            )
        except a.AuthenticationError as exc:
            raise ProviderUnavailable("The AI provider rejected the API key.") from exc
        except a.PermissionDeniedError as exc:
            raise ProviderUnavailable("The API key can't use this model.") from exc
        except a.RateLimitError as exc:
            raise ProviderError("The AI provider is rate limiting; try again later.") from exc
        except a.BadRequestError as exc:
            raise ProviderError(f"The AI provider rejected the request: {exc.message}") from exc
        except a.APIStatusError as exc:
            raise ProviderError(f"The AI provider returned {exc.status_code}.") from exc
        except a.APIConnectionError as exc:
            raise ProviderUnavailable("The AI provider couldn't be reached.") from exc
        latency = int((time.monotonic() - started) * 1000)
        if response.stop_reason == "refusal":
            raise ProviderError("The model declined this task.")
        if response.stop_reason == "max_tokens":
            raise ProviderError("The model's answer was cut off; nothing was applied.")
        parsed = response.parsed_output
        if parsed is None:
            raise ProviderError("The model returned no structured result.")
        return GenerationResult(
            parsed=parsed,
            model=response.model,
            provider=self.name,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            latency_ms=latency,
        )


class FixtureProvider:
    """Tests and demos only (NIGHTFALL_AI_PROVIDER=fixture, allowed only in fixture collector
    mode). Deterministic answers built from what the agent was shown; labelled
    'fixture-model' so it can never pass for a real model's output."""

    name = "fixture"

    def generate(self, request: GenerationRequest[T]) -> GenerationResult[T]:
        import re

        from nightfall.agents.registry import (
            AdversaryOutput,
            AnalystOutput,
            CandidateFinding,
            DirectorOutput,
            GuardianOutput,
            HunterOutput,
            InvestigatorOutput,
            KeyRisk,
            ProposedCollection,
            ProposedPath,
            ProposedRelationship,
            ProposedStep,
            ScoutOutput,
            Subtask,
        )

        def block(source: str) -> str:
            m = re.search(rf'<data source="{source}"[^>]*>\n(.*?)\n</data>', request.user, re.S)
            return m.group(1) if m else ""

        evidence_ids = re.findall(r'<data source="evidence" id="([0-9a-f-]{36})"', request.user)
        finding_ids = re.findall(r'"id": "([0-9a-f-]{36})"', block("findings"))

        parsed: BaseModel
        if request.output_model is ScoutOutput:
            domains = re.findall(r"domain_tree: ([a-z0-9.-]+)", request.user)
            proposals = []
            for d in domains[:1]:
                proposals = [
                    ProposedCollection(
                        tool="dns", target=f"www.{d}", purpose="Resolve the web host."
                    ),
                    ProposedCollection(
                        tool="http", target=f"www.{d}", purpose="Identify the stack."
                    ),
                ]
            parsed = ScoutOutput(proposals=proposals, notes="Fixture plan.")
        elif request.output_model is HunterOutput:
            ids = evidence_ids
            candidates = (
                [
                    CandidateFinding(
                        title="Certificate history lists hosts outside the asset inventory",
                        severity="low",
                        asset="",
                        description="Fixture candidate citing the most recent evidence.",
                        impact="Forgotten hosts may be unpatched.",
                        remediation="Confirm ownership of each listed host.",
                        evidence_ids=ids[:1],
                    )
                ]
                if ids
                else []
            )
            parsed = HunterOutput(candidates=candidates, notes="Fixture review.")
        elif request.output_model is DirectorOutput:
            parsed = DirectorOutput(
                subtasks=[
                    Subtask(agent="scout", objective="Fill gaps in passive coverage."),
                    Subtask(agent="analyst", objective="Summarise where the assessment stands."),
                ],
                notes="Fixture plan: collect first, then summarise.",
            )
        elif request.output_model is InvestigatorOutput:
            values = re.findall(r'"value": "([^"]+)"', block("assets"))
            subject = re.findall(r'"value": "([^"]+)"', block("subject_asset"))
            others = [v for v in values if v not in subject]
            rels = (
                [
                    ProposedRelationship(
                        to_asset=others[0],
                        rel_type="resolves_to",
                        rationale="Fixture: listed together in the cited evidence.",
                        evidence_ids=evidence_ids[:1],
                    )
                ]
                if others and evidence_ids
                else []
            )
            parsed = InvestigatorOutput(
                summary="Fixture explanation: a host seen in certificate history.",
                relationships=rels,
                open_questions=["Who operates this host?"],
            )
        elif request.output_model is AdversaryOutput:
            paths = (
                [
                    ProposedPath(
                        title="Forgotten host to internal foothold",
                        narrative="Fixture path built from the first recorded finding.",
                        steps=[
                            ProposedStep(finding_id=finding_ids[0], description="Entry point."),
                            ProposedStep(
                                finding_id=finding_ids[-1], description="Impact if it holds."
                            ),
                        ],
                    )
                ]
                if finding_ids
                else []
            )
            parsed = AdversaryOutput(paths=paths, notes="Fixture: rests on unreviewed findings.")
        elif request.output_model is AnalystOutput:
            parsed = AnalystOutput(
                summary="Fixture summary: coverage is early and nothing is validated yet.",
                key_risks=[KeyRisk(finding_id=f, why="Fixture.") for f in finding_ids[:1]],
                next_steps=["Review the open hypotheses."],
            )
        elif request.output_model is GuardianOutput:
            parsed = GuardianOutput(
                verdict="insufficient_evidence",
                rationale="Fixture review: the names alone don't show the hosts are unmanaged.",
                severity_assessment="agree",
            )
        else:  # pragma: no cover
            raise ProviderError("No fixture for this output.")
        return GenerationResult(
            parsed=parsed,  # type: ignore[arg-type]
            model="fixture-model",
            provider=self.name,
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )


def get_provider() -> Provider | None:
    from nightfall.config import get_settings

    s = get_settings()
    if s.ai_provider == "anthropic":
        return AnthropicProvider(model=s.ai_model)
    if s.ai_provider == "fixture":
        return FixtureProvider()
    return None
