"""Scope engine: normal matching plus the bypass attempts listed in review §16.10."""

from datetime import UTC, datetime, timedelta

import pytest

from nightfall.core.db.models import ScopeEntryKind as K
from nightfall.core.db.models import ScopeStatus
from nightfall.scope import normalize
from nightfall.scope.engine import Entry, ScopeSnapshot, evaluate, normalize_entry
from nightfall.scope.normalize import NormalizationError

NOW = datetime(2026, 11, 4, 12, tzinfo=UTC)


def snap(targets, exclusions=(), status=ScopeStatus.ACTIVE, valid_from=None, valid_until=None):
    return ScopeSnapshot(
        status=status,
        valid_from=valid_from,
        valid_until=valid_until,
        targets=tuple(Entry(k, normalize_entry(k, v)) for k, v in targets),
        exclusions=tuple(Entry(k, normalize_entry(k, v)) for k, v in exclusions),
    )


SCOPE = snap(
    [
        (K.DOMAIN_TREE, "example.com"),
        (K.HOST, "portal.partner.net"),
        (K.CIDR, "192.0.2.0/24"),
        (K.IP, "2001:db8::10"),
    ],
    [(K.HOST, "mail.example.com"), (K.DOMAIN_TREE, "legacy.example.com"), (K.IP, "192.0.2.99")],
)


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "www.example.com",
        "a.b.c.example.com",
        "WWW.Example.COM.",
        " www.example.com ",
        "portal.partner.net",
        "192.0.2.1",
        "192.0.2.254",
        "2001:db8::10",
        "2001:0db8:0:0::10",
        "::ffff:192.0.2.5",  # IPv4-mapped IPv6 is the same address
    ],
)
def test_allowed(target: str) -> None:
    assert evaluate(SCOPE, target, NOW).allowed, target


@pytest.mark.parametrize(
    "target,why",
    [
        ("badexample.com", "suffix without label boundary"),
        ("example.com.evil.net", "scope domain as a prefix"),
        ("evil.net", "unrelated"),
        ("partner.net", "parent of an exact host entry"),
        ("www.portal.partner.net", "child of an exact host entry"),
        ("mail.example.com", "excluded host"),
        ("MAIL.EXAMPLE.COM.", "excluded host, different spelling"),
        ("old.legacy.example.com", "inside an excluded tree"),
        ("legacy.example.com", "excluded tree root"),
        ("192.0.2.99", "excluded IP inside an allowed range"),
        ("192.0.3.1", "outside the range"),
        ("0177.0.0.1", "octal notation is rejected"),
        ("3221225985", "decimal notation is rejected"),
        ("0xC0000201", "hex notation is rejected"),
        ("192.0.2", "short notation is rejected"),
        ("http://www.example.com/", "URL instead of host"),
        ("www.example.com:443", "port suffix"),
        ("*.example.com", "wildcard is not a target"),
        ("exa mple.com", "space"),
        ("localhost", "single label"),
        ("", "empty"),
        ("2001:db8::11", "different IPv6 address"),
    ],
)
def test_denied(target: str, why: str) -> None:
    assert not evaluate(SCOPE, target, NOW).allowed, why


def test_unicode_hostnames_match_their_punycode() -> None:
    s = snap([(K.DOMAIN_TREE, "bücher.example")])
    assert evaluate(s, "shop.xn--bcher-kva.example", NOW).allowed
    assert evaluate(s, "SHOP.BÜCHER.example", NOW).allowed
    assert not evaluate(s, "shop.bucher.example", NOW).allowed  # lookalike ASCII


def test_hostnames_never_match_ip_entries_and_vice_versa() -> None:
    s = snap([(K.CIDR, "0.0.0.0/0")])
    assert not evaluate(s, "www.example.com", NOW).allowed
    s = snap([(K.DOMAIN_TREE, "example.com")])
    assert not evaluate(s, "192.0.2.1", NOW).allowed


def test_status_and_validity_window() -> None:
    assert not evaluate(None, "example.com", NOW).allowed
    draft = snap([(K.DOMAIN_TREE, "example.com")], status=ScopeStatus.DRAFT)
    assert not evaluate(draft, "example.com", NOW).allowed
    old = snap([(K.DOMAIN_TREE, "example.com")], status=ScopeStatus.SUPERSEDED)
    assert not evaluate(old, "example.com", NOW).allowed
    future = snap([(K.DOMAIN_TREE, "example.com")], valid_from=NOW + timedelta(days=1))
    assert "hasn't started" in evaluate(future, "example.com", NOW).reason
    expired = snap([(K.DOMAIN_TREE, "example.com")], valid_until=NOW)
    assert "ended" in evaluate(expired, "example.com", NOW).reason


@pytest.mark.parametrize(
    "bad",
    [
        "-a.example.com",
        "a-.example.com",
        "a..example.com",
        "a" * 64 + ".com",
        "example.123",
        "under_score.example.com",
    ],
)
def test_hostname_validation(bad: str) -> None:
    with pytest.raises(NormalizationError):
        normalize.hostname(bad)


def test_network_requires_zero_host_bits() -> None:
    with pytest.raises(NormalizationError):
        normalize.network("192.0.2.1/24")
    assert str(normalize.network("192.0.2.0/24")) == "192.0.2.0/24"
