import time
import uuid

import pyotp
import pytest
from cryptography.exceptions import InvalidTag

from nightfall.core.db.models import Role
from nightfall.core.identity import security
from nightfall.core.identity.throttle import SlidingWindow
from nightfall.core.tenancy.permissions import (
    MFA_REQUIRED_ROLES,
    ROLE_PERMISSIONS,
    Permission,
    can_assign,
    can_manage,
)


def test_password_hash_roundtrip_and_mismatch() -> None:
    h = security.hash_password("a long enough password")
    assert h.startswith("$argon2id$")
    assert security.verify_password(h, "a long enough password")
    assert not security.verify_password(h, "wrong password here")
    assert not security.verify_password(None, "anything at all")
    assert not security.verify_password("not-a-hash", "anything at all")


@pytest.mark.parametrize("pw", ["short", "x" * 11, "x" * 1025])
def test_password_policy_rejects(pw: str) -> None:
    with pytest.raises(security.PasswordPolicyError):
        security.check_password_policy(pw)


def test_tokens_are_random_and_hashed() -> None:
    raw1, d1 = security.new_token()
    raw2, d2 = security.new_token()
    assert raw1 != raw2 and d1 != d2
    assert security.hash_token(raw1) == d1 and len(d1) == 32


def test_totp_window_and_replay() -> None:
    secret = security.new_totp_secret()
    now = time.time()
    step = int(now // 30)
    code = pyotp.TOTP(secret).at(step * 30)
    assert security.verify_totp(secret, code, None, now) == step
    assert security.verify_totp(secret, code, step, now) is None  # replay
    old = pyotp.TOTP(secret).at((step - 3) * 30)
    assert security.verify_totp(secret, old, None, now) is None  # outside drift window
    assert security.verify_totp(secret, "12345", None, now) is None
    assert security.verify_totp(secret, "abcdef", None, now) is None


def test_secret_encryption_bound_to_user() -> None:
    key = b"\x02" * 32
    uid = uuid.uuid4()
    blob = security.encrypt_secret(key, "JBSWY3DPEHPK3PXP", uid)
    assert security.decrypt_secret(key, blob, uid) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidTag):
        security.decrypt_secret(key, blob, uuid.uuid4())


def test_permission_matrix() -> None:
    assert ROLE_PERMISSIONS[Role.VIEWER] == {Permission.READ}
    assert Permission.MEMBERS_MANAGE not in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.OPERATIONS_APPROVE in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.OPERATIONS_APPROVE not in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.SCOPE_AUTHORIZE in ROLE_PERMISSIONS[Role.ADMIN]
    assert {Role.OWNER, Role.ADMIN, Role.OPERATOR} == MFA_REQUIRED_ROLES
    for role in Role:
        assert Permission.READ in ROLE_PERMISSIONS[role]


def test_role_assignment_rules() -> None:
    assert can_assign(Role.OWNER, Role.OWNER)
    assert not can_assign(Role.ADMIN, Role.OWNER)
    assert not can_assign(Role.ADMIN, Role.ADMIN)
    assert can_assign(Role.ADMIN, Role.OPERATOR)
    assert can_manage(Role.OWNER, Role.OWNER)
    assert not can_manage(Role.ADMIN, Role.ADMIN)
    assert can_manage(Role.ADMIN, Role.VIEWER)


def test_sliding_window() -> None:
    w = SlidingWindow(limit=2, window_seconds=60)
    assert not w.blocked("k")
    w.hit("k")
    w.hit("k")
    assert w.blocked("k") and not w.blocked("other")
    w.reset("k")
    assert not w.blocked("k")
