# ruff: noqa: F811  (pytest fixtures imported from test_ownership)
"""BLACK OPS Profile B step 2: sealed test identities and the run gates (G1-G5)."""

import uuid
from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.blackops import profile_b
from nightfall.blackops.catalog import (
    PLAYBOOKS,
    Category,
    Playbook,
    Profile,
    Step,
    TargetType,
    check_catalog,
)
from nightfall.config import ConfigError, get_settings, load_settings
from nightfall.core.db.models import Role
from tests.conftest import audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_ownership import FakeProbes, env, probes  # noqa: F401 - fixtures

PUBLIC, PRIVATE = profile_b.generate_keypair()
CANARY = "canary-Pa55word-7f3e"
TARGET = "app.example.com"

TEST_PLAYBOOK = Playbook(
    id="profile-b-test",
    name="Profile B test",
    version="0.0.1",
    category=Category.CONTROLLED_VALIDATION,
    summary="Test only.",
    description="Test only.",
    steps=(Step("headers", "Read headers"),),
    profiles=(Profile.VALIDATION,),
    target_types=(TargetType.HOSTNAME,),
    expected_duration="",
    limits=(),
    outputs=(),
    cleanup="",
    tests=(),
    changelog=(),
    identities=1,
)


@pytest.fixture
def gates_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_ENABLED", "true")
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_REVIEW_REF", "PB-REVIEW-1")
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_PUBLIC_KEY", PUBLIC)
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_PRIVATE_KEY", PRIVATE)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_playbook(monkeypatch: pytest.MonkeyPatch) -> Playbook:
    monkeypatch.setitem(PLAYBOOKS, TEST_PLAYBOOK.id, TEST_PLAYBOOK)
    return TEST_PLAYBOOK


def W(env: dict) -> str:  # noqa: N802
    return f"/api/workspaces/{env['ws']}"


def register(client: TestClient, env: dict, **over) -> dict:  # type: ignore[no-untyped-def]
    body = {
        "origin": f"https://{TARGET}",
        "label": "low-priv customer",
        "role_description": "Customer with no admin rights",
        "login_method": "form",
        "login_path": "/login",
        "username": "qa-customer@example.com",
        "password": CANARY,
        "attestation": "Created for testing; holds no real person's data.",
        "attest": True,
        **over,
    }
    return client.post(f"{W(env)}/test-identities", json=body)  # type: ignore[return-value]


def prove(client: TestClient, env: dict, probes: FakeProbes) -> None:
    claim = client.post(
        f"{W(env)}/ownership/claims", json={"name": "example.com", "method": "dns"}
    ).json()
    probes.txt_records["_janus-verify.example.com"] = [claim["token"]]
    r = client.post(f"{W(env)}/scopes/{env['scope']['id']}/ownership/{claim['id']}/check")
    assert r.json()["ok"] is True


# --- Sealing and configuration ---------------------------------------------------------------


def test_sealing_binds_the_credential_to_its_row_and_the_worker_key() -> None:
    i, w = uuid.uuid4(), uuid.uuid4()
    blob = profile_b.seal(PUBLIC, {"username": "u", "password": CANARY}, i, w)
    assert CANARY.encode() not in blob
    assert profile_b.unseal(PRIVATE, blob, i, w) == {"username": "u", "password": CANARY}
    other_pub, other_priv = profile_b.generate_keypair()
    for bad in (
        lambda: profile_b.unseal(other_priv, blob, i, w),  # another worker's key
        lambda: profile_b.unseal(PRIVATE, blob, uuid.uuid4(), w),  # copied to another row
        lambda: profile_b.unseal(PRIVATE, blob, i, uuid.uuid4()),  # another workspace
        lambda: profile_b.unseal(PRIVATE, blob[:-1] + bytes([blob[-1] ^ 1]), i, w),  # tampered
    ):
        with pytest.raises(profile_b.SealError):
            bad()


def test_private_key_never_on_the_hosted_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_PRIVATE_KEY", PRIVATE)
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    monkeypatch.setenv("NIGHTFALL_WORKER_DATABASE_URL", "postgresql://w@localhost/db")
    with pytest.raises(ConfigError, match="self-hosted worker only"):
        load_settings()
    monkeypatch.delenv("NIGHTFALL_ON_DEMAND_WORKER")
    monkeypatch.setenv("NIGHTFALL_PROFILE_B_PUBLIC_KEY", "not-a-key")
    with pytest.raises(ConfigError, match="PUBLIC_KEY"):
        load_settings()


def test_each_gate_switches_profile_b_off_on_its_own(gates_on: None) -> None:
    import dataclasses

    s = get_settings()
    assert profile_b.unavailable_reason(s) is None
    for change, words in (
        ({"profile_b_enabled": False}, "switched off"),
        ({"profile_b_review_ref": None}, "independent review"),
        ({"on_demand_worker": True}, "self-hosted worker"),
        ({"profile_b_public_key": None}, "worker key"),
    ):
        assert words in (profile_b.unavailable_reason(dataclasses.replace(s, **change)) or "")


def test_shipped_catalog_has_only_the_reviewed_profile_b_playbooks() -> None:
    assert [p.id for p in PLAYBOOKS.values() if Profile.VALIDATION in p.profiles] == [
        "authentication-configuration-audit"
    ]
    check_catalog({TEST_PLAYBOOK.id: TEST_PLAYBOOK})  # a validation-only definition is valid
    mixed = Playbook(**{**TEST_PLAYBOOK.__dict__, "profiles": (Profile.LIVE, Profile.VALIDATION)})
    with pytest.raises(ValueError, match="only Profile B"):
        check_catalog({mixed.id: mixed})


# --- Identities ------------------------------------------------------------------------------


def test_identities_are_sealed_owner_only_and_never_returned(
    client: TestClient, env: dict, owner_db: Session, app_engine: Engine, gates_on: None
) -> None:
    use(client, env["admin"])
    assert register(client, env).status_code == 403
    use(client, env["owner"])
    assert register(client, env, attest=False).status_code == 422
    assert register(client, env, origin="http://app.example.com").status_code == 422
    assert register(client, env, origin="https://10.0.0.5").status_code == 422
    r = register(client, env, origin="https://APP.example.com:443/")
    assert r.status_code == 201, r.text
    ident = r.json()
    assert ident["origin"] == f"https://{TARGET}" and ident["credential"] == "set"
    assert register(client, env, origin=f"https://{TARGET}").status_code == 409  # same label

    # Nowhere in API responses or the audit trail.
    listing = client.get(f"{W(env)}/test-identities")
    assert CANARY not in listing.text and CANARY not in r.text
    assert listing.json()["unavailable_reason"] is None
    audit = owner_db.execute(text("SELECT data::text FROM audit_events")).scalars().all()
    assert not any(CANARY in d for d in audit)
    assert "test_identity.registered" in audit_actions(owner_db)

    # Stored sealed; only the worker's key opens it.
    blob = owner_db.execute(text("SELECT secret_sealed FROM test_identities")).scalar_one()
    assert CANARY.encode() not in bytes(blob)
    opened = profile_b.unseal(PRIVATE, bytes(blob), uuid.UUID(ident["id"]), env["ws"])
    assert opened["password"] == CANARY

    # The app role can't read the sealed column, edit an identity or revive a retired one.
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        for stmt in (
            "SELECT secret_sealed FROM test_identities",
            "UPDATE test_identities SET origin = 'https://evil.example'",
            "UPDATE test_identities SET lockout_test_allowed = true",
            "DELETE FROM test_identities",
        ):
            with pytest.raises(DBAPIError):
                with conn.begin():
                    conn.execute(text(stmt))
    r = client.post(f"{W(env)}/test-identities/{ident['id']}/retire")
    assert r.status_code == 200 and r.json()["retired_at"]
    assert client.post(f"{W(env)}/test-identities/{ident['id']}/retire").status_code == 409


def test_without_a_worker_key_nothing_is_stored(client: TestClient, env: dict) -> None:
    r = register(client, env)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_worker_key"


# --- Gates in preflight, launch, database and worker -----------------------------------------


def _pre(client: TestClient, env: dict, ids: list[str]) -> dict:
    r = client.post(
        f"{W(env)}/blackops/projects/{env['pid']}/preflight",
        json={"playbook_id": TEST_PLAYBOOK.id, "target": TARGET, "identity_ids": ids},
    )
    assert r.status_code == 200, r.text
    return {c["key"]: c for c in r.json()["checks"]}


def _launch(client: TestClient, env: dict, ids: list[str]):  # type: ignore[no-untyped-def]
    return client.post(
        f"{W(env)}/blackops/projects/{env['pid']}/runs",
        json={
            "playbook_id": TEST_PLAYBOOK.id,
            "target": TARGET,
            "identity_ids": ids,
            "version": TEST_PLAYBOOK.version,
            "definition_sha256": TEST_PLAYBOOK.sha256,
        },
    )


def test_gates_off_refuse_profile_b(client: TestClient, env: dict, test_playbook: Playbook) -> None:
    checks = _pre(client, env, [])
    assert checks["profile"]["status"] == "pass"
    assert (
        checks["profile_b"]["status"] == "fail" and "switched off" in checks["profile_b"]["detail"]
    )
    assert _launch(client, env, []).status_code == 422


def test_every_gate_then_launch_then_worker_recheck(
    client: TestClient,
    env: dict,
    owner_db: Session,
    probes: FakeProbes,
    test_playbook: Playbook,
    gates_on: None,
) -> None:
    ident = register(client, env).json()
    other = register(client, env, origin="https://other.test", label="elsewhere").json()

    # G1: no proof yet.
    checks = _pre(client, env, [ident["id"]])
    assert checks["profile_b"]["status"] == "pass"
    assert checks["control"]["status"] == "fail"
    prove(client, env, probes)
    # G2: an identity for another origin, or none, is refused.
    checks = _pre(client, env, [other["id"]])
    assert checks["control"]["status"] == "pass"
    assert (
        checks["identities"]["status"] == "fail" and "other.test" in checks["identities"]["detail"]
    )
    assert _pre(client, env, [])["identities"]["status"] == "fail"  # needs 1
    checks = _pre(client, env, [ident["id"]])
    assert all(c["status"] != "fail" for c in checks.values()), checks
    assert "24 hours" in checks["approval"]["detail"]

    r = _launch(client, env, [ident["id"]])
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    row = owner_db.execute(
        text("SELECT profile, identity_ids, ownership_check_ids FROM playbook_runs WHERE id=:i"),
        {"i": run_id},
    ).one()
    assert row.profile == "validation" and [str(x) for x in row.identity_ids] == [ident["id"]]
    assert len(row.ownership_check_ids) == 1
    assert owner_db.execute(text("SELECT status FROM operations")).scalar_one() == (
        "awaiting_approval"
    )

    # G4: approved (single-operator owner, fresh two-factor); then the identity is retired
    # before the worker starts: the worker refuses.
    use(client, env["owner"])
    owner_db.execute(text("UPDATE workspaces SET approval_policy = 'single_operator'"))
    owner_db.commit()
    r = client.post(f"{W(env)}/blackops/runs/{run_id}/approve", json={"reason": "Test window"})
    assert r.status_code == 200, r.text
    client.post(f"{W(env)}/test-identities/{ident['id']}/retire")
    w = make_worker()
    while w.run_once():
        pass
    op = owner_db.execute(text("SELECT status, denial_reason FROM operations")).one()
    assert op.status == "denied" and "retired" in op.denial_reason


def test_worker_refuses_stale_proof_and_old_approval(
    client: TestClient,
    env: dict,
    owner_db: Session,
    probes: FakeProbes,
    test_playbook: Playbook,
    gates_on: None,
) -> None:
    ident = register(client, env).json()
    prove(client, env, probes)
    run_id = _launch(client, env, [ident["id"]]).json()["id"]
    owner_db.execute(text("UPDATE workspaces SET approval_policy = 'single_operator'"))
    owner_db.commit()
    client.post(f"{W(env)}/blackops/runs/{run_id}/approve", json={"reason": "ok"})
    # The proof ages past 24 hours before the worker starts (as the database owner could).
    owner_db.execute(
        text("UPDATE ownership_checks SET checked_at = checked_at - :d"),
        {"d": timedelta(hours=25)},
    )
    owner_db.commit()
    w = make_worker()
    while w.run_once():
        pass
    op = owner_db.execute(text("SELECT status, denial_reason FROM operations")).one()
    assert op.status == "denied" and "Proof of control" in op.denial_reason

    from nightfall.control.approvals import approval_expired
    from nightfall.core.clock import utcnow

    now = utcnow()
    assert approval_expired(now - timedelta(hours=25), False, now) is None  # live: 72 h
    assert "Profile B" in (approval_expired(now - timedelta(hours=25), False, now, True) or "")


def test_database_refuses_profile_b_runs_without_fresh_proof(
    client: TestClient, env: dict, owner_db: Session, app_engine: Engine, gates_on: None
) -> None:
    ident = register(client, env).json()
    owner = owner_db.execute(text("SELECT id FROM users LIMIT 1")).scalar_one()
    base = (
        "INSERT INTO playbook_runs (workspace_id, project_id, scope_id, playbook_id, "
        "playbook_version, definition_sha256, profile, target_value, requested_by_user_id, "
        "identity_ids, ownership_check_ids) VALUES (:w, :p, :s, 'x', '1', :sha, 'validation', "
        ":t, :u, :ids, :checks)"
    )
    params = {
        "w": env["ws"], "p": env["pid"], "s": env["scope"]["id"], "sha": "0" * 64, "t": TARGET,
        "u": owner, "ids": [uuid.UUID(ident["id"])],
    }  # fmt: skip
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        for checks in ([], [uuid.uuid4()]):  # no proof; a proof that doesn't exist
            with pytest.raises(DBAPIError):
                with conn.begin():
                    conn.execute(text(base), {**params, "checks": checks})
    _ = Role
