"""BLACK OPS playbook catalog (Addendum 4 §5, §9).

A playbook is a reviewed definition in code: an ordered list of steps, each one a
registered collector (nightfall.recon.collectors.TOOLS). There is no other kind of step:
no shell commands, scripts, URLs or parameters from the user or a model. Adding or changing
a playbook is a code change, reviewed like any other.

Each definition is fingerprinted (SHA-256 of its canonical JSON). A run records the version
and fingerprint it was launched with, and tests pin every published fingerprint
(tests/golden/playbooks.json), so a definition can't change without a version bump.

Execution profiles (Addendum 4 §4):
  A  live        authorized real targets, passive and low-risk (read-only) steps only
  B  validation  not built: needs designated test identities and its own review
  C  lab         the isolated lab network only (lab scopes, the lab worker)
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from nightfall.core.db.models import RiskClass
from nightfall.recon.collectors import LAB_TOOLS, TOOLS


class Profile(enum.StrEnum):
    LIVE = "live"
    VALIDATION = "validation"
    LAB = "lab"


class Category(enum.StrEnum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    CONTROLLED_VALIDATION = "controlled_validation"
    ADVERSARY_SIMULATION = "adversary_simulation"


class TargetType(enum.StrEnum):
    DOMAIN = "domain"  # a registrable name with subdomains (certificate-log search)
    HOSTNAME = "hostname"
    IP = "ip"


@dataclass(frozen=True)
class ProfileInfo:
    code: str
    label: str
    description: str
    available: bool
    unavailable_reason: str | None = None


PROFILES: dict[Profile, ProfileInfo] = {
    Profile.LIVE: ProfileInfo(
        "A",
        "Live assessment",
        "Authorized real targets. Passive collection and bounded, read-only requests; "
        "nothing that changes state.",
        True,
    ),
    Profile.VALIDATION: ProfileInfo(
        "B",
        "Controlled validation",
        "Designated test accounts and controlled input testing on authorized targets.",
        False,
        "Not built. It needs designated test identities, ownership verification of the "
        "target and its own independent authorization review (review F2, F3).",
    ),
    Profile.LAB: ProfileInfo(
        "C",
        "Isolated lab",
        "Practice targets on the isolated lab network only, run by the lab worker.",
        True,
    ),
}

_RISK_ORDER = [RiskClass.PASSIVE, RiskClass.LOW, RiskClass.MODERATE, RiskClass.HIGH]


@dataclass(frozen=True)
class Dependency:
    name: str
    license: str
    pinned: str


# What each step tool depends on, for the library's dependency and license view.
TOOL_DEPENDENCIES: dict[str, tuple[Dependency, ...]] = {
    "ct": (
        Dependency("crt.sh (public certificate-log search)", "Service terms (Sectigo)", "-"),
        Dependency("httpx", "BSD-3-Clause", "api/requirements.lock"),
    ),
    "dns": (Dependency("dnspython", "ISC", "api/requirements.lock"),),
    "http": (Dependency("httpx", "BSD-3-Clause", "api/requirements.lock"),),
    "nuclei": (
        Dependency("Nuclei (ProjectDiscovery)", "MIT", "infra/tools/Dockerfile (by digest)"),
        Dependency("NIGHTFALL check templates", "Proprietary (DRE)", "SHA-256 per template"),
    ),
    "tls": (
        Dependency("Python ssl / OpenSSL", "PSF-2.0 / Apache-2.0", "runtime image"),
        Dependency("cryptography", "Apache-2.0 OR BSD-3-Clause", "api/requirements.lock"),
    ),
    "headers": (Dependency("httpx", "BSD-3-Clause", "api/requirements.lock"),),
    **{
        f"nuclei-pack1-{g}": (
            Dependency("Nuclei (ProjectDiscovery)", "MIT", "infra/tools/Dockerfile (by digest)"),
            Dependency(
                "nuclei-templates v10.5.1 (lab pack 1 subset)",
                "MIT",
                "api/nightfall/tools/nuclei/pack1.json (SHA-256 per template)",
            ),
        )
        for g in ("cve", "config", "tech")
    },
}


@dataclass(frozen=True)
class Step:
    tool: str
    purpose: str


@dataclass(frozen=True)
class Change:
    version: str
    date: str
    note: str


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    version: str
    category: Category
    summary: str
    description: str
    steps: tuple[Step, ...]
    profiles: tuple[Profile, ...]
    target_types: tuple[TargetType, ...]
    expected_duration: str
    limits: tuple[str, ...]
    outputs: tuple[str, ...]
    cleanup: str
    tests: tuple[str, ...]  # automated tests that exercise this playbook (tests/...::name)
    changelog: tuple[Change, ...]

    @property
    def risk_class(self) -> RiskClass:
        return max((TOOLS[s.tool][1] for s in self.steps), key=_RISK_ORDER.index)

    @property
    def tools(self) -> list[str]:
        return [s.tool for s in self.steps]

    def needs_approval(self, profile: Profile) -> bool:
        return profile is Profile.LAB or self.risk_class is not RiskClass.PASSIVE

    def dependencies(self) -> list[Dependency]:
        seen: dict[str, Dependency] = {}
        for tool in self.tools:
            for d in TOOL_DEPENDENCIES.get(tool, ()):
                seen.setdefault(d.name, d)
        return list(seen.values())

    def definition(self) -> dict[str, Any]:
        """Everything that decides what a run does, in canonical form."""
        return {
            "id": self.id,
            "version": self.version,
            "category": self.category.value,
            "steps": [{"tool": s.tool, "purpose": s.purpose} for s in self.steps],
            "profiles": [p.value for p in self.profiles],
            "target_types": [t.value for t in self.target_types],
            "limits": list(self.limits),
            "cleanup": self.cleanup,
        }

    @property
    def sha256(self) -> str:
        canonical = json.dumps(self.definition(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


_V1 = (Change("1.0.0", "2026-11-06", "First reviewed version."),)
_READ_ONLY = "None needed: every step is read-only and leaves nothing on the target."

PLAYBOOKS: dict[str, Playbook] = {
    p.id: p
    for p in (
        Playbook(
            id="surface-mapper",
            name="Surface Mapper",
            version="1.0.0",
            category=Category.RECONNAISSANCE,
            summary="Subdomains from certificate logs, plus the domain's DNS records.",
            description="Searches public certificate-transparency logs for names under the "
            "domain and resolves the domain's DNS records. Never contacts the target. "
            "In-scope names become assets with their relationships; out-of-scope names stay in "
            "the evidence only.",
            steps=(
                Step("ct", "Names under the domain from certificate-transparency logs"),
                Step("dns", "A, AAAA, CNAME, MX, NS and TXT records of the domain"),
            ),
            profiles=(Profile.LIVE,),
            target_types=(TargetType.DOMAIN,),
            expected_duration="Under 2 minutes (crt.sh can be slow)",
            limits=(
                "Contacts crt.sh and the DNS resolver only, never the target",
                "At most 5000 names kept; 5 MiB evidence cap",
            ),
            outputs=("Hostname and IP assets", "subdomain_of / resolves_to / cname_to links"),
            cleanup=_READ_ONLY,
            tests=("tests/test_blackops.py::test_passive_playbook_runs_without_approval",),
            changelog=_V1,
        ),
        Playbook(
            id="service-fingerprinter",
            name="Service Fingerprinter",
            version="1.0.0",
            category=Category.RECONNAISSANCE,
            summary="DNS resolution and web technology identification for one host.",
            description="Resolves the host, then identifies the web server and application "
            "technologies from one response to / (HTTPS, falling back to HTTP). Version "
            "disclosures and HTTPS problems become unverified findings.",
            steps=(
                Step("dns", "Resolve the host and record its addresses"),
                Step("http", "Identify server and application technologies from GET /"),
            ),
            profiles=(Profile.LIVE,),
            target_types=(TargetType.HOSTNAME,),
            expected_duration="Under 1 minute",
            limits=(
                "At most 3 GET requests to / on ports 443 and 80",
                "Redirects recorded, never followed; 10 s timeout; 512 KiB body cap",
                "Resolved once; private, metadata and excluded addresses refused",
            ),
            outputs=("Technologies with versions", "Findings R1-R5"),
            cleanup=_READ_ONLY,
            tests=("tests/test_blackops.py::test_low_risk_run_needs_explicit_approval",),
            changelog=_V1,
        ),
        Playbook(
            id="web-exposure-audit",
            name="Web Exposure Audit",
            version="1.0.0",
            category=Category.VULNERABILITY_ASSESSMENT,
            summary="NIGHTFALL's curated, GET-only exposure checks (Nuclei).",
            description="Runs the reviewed, hash-pinned check templates (exposed .git "
            "metadata, directory listing, public server-status, missing HSTS) in the tool "
            "sandbox. All traffic goes through the per-run scope proxy.",
            steps=(Step("nuclei", "Curated GET-only exposure checks through the scope proxy"),),
            profiles=(Profile.LIVE, Profile.LAB),
            target_types=(TargetType.HOSTNAME, TargetType.IP),
            expected_duration="Under 5 minutes",
            limits=(
                "Pinned templates only, GET only, fixed paths, no payloads",
                "5 requests/s, 2 concurrent, no redirects, no out-of-band callbacks",
                "Only the operation's target is reachable through the proxy",
            ),
            outputs=("Curated check matches", "Finding R6 per matched check"),
            cleanup=_READ_ONLY,
            tests=("tests/test_blackops.py::test_lab_profile_routes_to_the_lab_worker",),
            changelog=_V1,
        ),
        Playbook(
            id="tls-configuration-audit",
            name="TLS Configuration Audit",
            version="1.0.0",
            category=Category.VULNERABILITY_ASSESSMENT,
            summary="Protocol versions, certificate validity, key and signature strength.",
            description="Offers each TLS version from 1.0 to 1.3 in turn, plus one handshake "
            "with certificate validation. Records which versions the server accepts and the "
            "certificate's validity, names, key and signature. No HTTP request is sent.",
            steps=(Step("tls", "TLS handshakes on port 443, one per protocol version"),),
            profiles=(Profile.LIVE, Profile.LAB),
            target_types=(TargetType.HOSTNAME, TargetType.IP),
            expected_duration="Under 1 minute",
            limits=(
                "At most 5 TLS handshakes on port 443; no application data",
                "Resolved once; private, metadata and excluded addresses refused",
            ),
            outputs=("Accepted protocol versions", "Certificate summary", "Findings R2, R4-R10"),
            cleanup=_READ_ONLY,
            tests=(
                "tests/test_posture.py::test_tls_audit_against_a_local_server",
                "tests/test_blackops.py::test_low_risk_run_needs_explicit_approval",
            ),
            changelog=_V1,
        ),
        Playbook(
            id="http-security-assessment",
            name="HTTP Security Assessment",
            version="1.0.0",
            category=Category.VULNERABILITY_ASSESSMENT,
            summary="Security headers, cookie flags and HTTP-to-HTTPS redirect.",
            description="Reads the response to / over HTTPS and over plain HTTP, and assesses "
            "HSTS, Content-Security-Policy, framing protection, nosniff, Referrer-Policy, "
            "cookie attributes and whether HTTP redirects to HTTPS. Cookie values are never "
            "stored.",
            steps=(Step("headers", "Security headers and cookie attributes from GET /"),),
            profiles=(Profile.LIVE, Profile.LAB),
            target_types=(TargetType.HOSTNAME, TargetType.IP),
            expected_duration="Under 1 minute",
            limits=(
                "At most 3 GET requests to / on ports 443 and 80",
                "Redirects recorded, never followed; cookie values and bodies not stored",
            ),
            outputs=("Header and cookie posture", "Findings R11-R16"),
            cleanup=_READ_ONLY,
            tests=(
                "tests/test_posture.py::test_header_audit_against_a_local_server",
                "tests/test_blackops.py::test_approved_run_executes_and_reaches_black_ice",
            ),
            changelog=_V1,
        ),
        Playbook(
            id="known-weakness-scan-lab",
            name="Known-weakness scan (lab)",
            version="1.0.0",
            category=Category.VULNERABILITY_ASSESSMENT,
            summary="Lab tool pack 1: known CVEs, exposures, misconfigurations, default logins "
            "and technology detection on a lab machine.",
            description="Runs the reviewed subset of the public Nuclei templates (release "
            "v10.5.1, filtered by fixed rules, every file checked against its pinned hash) in "
            "three groups. Lab machines only: the lab worker, the lab network and BLACKSITE, "
            "plus the pack's own recorded review. Matches become unverified lab findings; "
            "nothing is exploited.",
            steps=(
                Step("nuclei-pack1-cve", "2,668 known-CVE detection templates"),
                Step(
                    "nuclei-pack1-config",
                    "1,935 exposure, misconfiguration and takeover templates, including 269 "
                    "default-login templates (they try vendor default passwords)",
                ),
                Step("nuclei-pack1-tech", "1,185 technology detection templates"),
            ),
            profiles=(Profile.LAB,),
            target_types=(TargetType.IP,),
            expected_duration="Up to 30 minutes per step",
            limits=(
                "HTTP only, through the scope proxy pinned to the lab target",
                "10 requests per second, 10 templates at once, 30 minutes per step",
                "No out-of-band callbacks, no PUT, DELETE or PATCH, redirects not followed",
            ),
            outputs=("Unverified lab findings (rule R17)",),
            cleanup="None expected: templates are detection checks. Default-login templates "
            "may leave failed-login records on the lab machine.",
            tests=(
                "tests/test_lab_pack1.py::test_manifest_rules_and_groups",
                "tests/test_lab_pack1.py::test_pack_runs_only_with_review_and_verified_templates",
            ),
            changelog=_V1,
        ),
    )
}


def check_catalog() -> None:
    """Fails loudly if a definition refers to anything that isn't a registered tool."""
    for p in PLAYBOOKS.values():
        if not p.steps or len(p.steps) > 20:
            raise ValueError(f"{p.id}: 1 to 20 steps")
        for s in p.steps:
            if s.tool not in TOOLS:
                raise ValueError(f"{p.id}: unknown tool {s.tool!r}")
            if Profile.LAB in p.profiles and s.tool not in LAB_TOOLS:
                raise ValueError(f"{p.id}: {s.tool!r} can't run in the lab")
        if Profile.VALIDATION in p.profiles:
            raise ValueError(f"{p.id}: profile B isn't available")
        if p.risk_class is RiskClass.HIGH:
            raise ValueError(f"{p.id}: high-risk steps are never allowed")
        if p.risk_class is RiskClass.MODERATE and p.profiles != (Profile.LAB,):
            raise ValueError(f"{p.id}: moderate risk is lab-only")


check_catalog()
