"""crt.sh is often overloaded: transient errors are retried, then fail with a clear reason."""

import json

import httpx
import pytest

from nightfall.recon.collectors import CertificateTransparency


def collector(statuses: list[int]) -> tuple[CertificateTransparency, list[str], list[float]]:
    calls: list[str] = []
    slept: list[float] = []
    body = json.dumps([{"name_value": "www.metis.test\napi.metis.test"}]).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        status = statuses[min(len(calls), len(statuses)) - 1]
        return httpx.Response(status, content=body if status == 200 else b"Bad Gateway")

    ct = CertificateTransparency()
    ct.transport = httpx.MockTransport(handler)
    ct.sleep = slept.append  # type: ignore[method-assign]
    return ct, calls, slept


def test_transient_502_is_retried_then_succeeds() -> None:
    ct, calls, slept = collector([502, 503, 200])
    result = ct.run("metis.test", None)  # type: ignore[arg-type]
    assert len(calls) == 3 and slept == [2.0, 5.0]
    assert b"www.metis.test" in result.raw


def test_persistent_outage_fails_with_a_plain_reason() -> None:
    ct, calls, _ = collector([502])
    with pytest.raises(
        RuntimeError, match=r"crt.sh .* unavailable right now \(HTTP 502, 3 attempts\)"
    ):
        ct.run("metis.test", None)  # type: ignore[arg-type]
    assert len(calls) == 3


def test_client_errors_are_not_retried() -> None:
    ct, calls, _ = collector([404])
    with pytest.raises(httpx.HTTPStatusError):
        ct.run("metis.test", None)  # type: ignore[arg-type]
    assert len(calls) == 1
