import os
import time

import pytest

from nightfall.recon.safe_http import Refused
from nightfall.tools import runner
from nightfall.tools.runner import Sandbox, run


def test_environment_is_empty_apart_from_basics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIGHTFALL_SECRET_KEY", "must-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://worker-proxy")
    res = run(["/usr/bin/env"], sandbox=Sandbox(), timeout=10)
    keys = {line.split("=", 1)[0] for line in res.stdout.decode().splitlines()}
    assert keys <= {"PATH", "HOME", "TMPDIR", "PWD"}
    assert b"must-not-leak" not in res.stdout


def test_timeout_kills_the_whole_process_group() -> None:
    started = time.monotonic()
    res = run(["/bin/sh", "-c", "sleep 30 & sleep 30"], sandbox=Sandbox(), timeout=1)
    assert res.timed_out and time.monotonic() - started < 10


def test_output_is_capped() -> None:
    res = run(["/bin/sh", "-c", "head -c 6000000 /dev/zero"], sandbox=Sandbox(), timeout=20)
    assert res.stdout_truncated and len(res.stdout) == 4 * 1024 * 1024


def test_files_are_collected_and_workdir_removed() -> None:
    res = run(
        ["/bin/sh", "-c", 'echo hi > out.txt; ln -s /etc/passwd link; echo "$HOME"'],
        sandbox=Sandbox(),
        timeout=10,
        collect=("out.txt", "link"),
    )
    assert res.workdir_files == {"out.txt": b"hi\n"}  # symlinks are never followed
    assert not os.path.exists(res.stdout.decode().strip())


def test_tools_are_refused_where_the_sandbox_cannot_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BLACKSITE imports this module on a Windows lab machine; tools must never start there.
    monkeypatch.setattr(runner, "_POSIX", False)
    with pytest.raises(Refused):
        run(["/usr/bin/env"], sandbox=Sandbox(), timeout=1)
    with pytest.raises(Refused):
        Sandbox(mode="uid", user="nftool").verify_lock()


def test_relative_binary_is_refused() -> None:
    with pytest.raises(ValueError):
        run(["nuclei"], sandbox=Sandbox(), timeout=1)


def test_lock_check_refuses_without_uid_sandbox() -> None:
    with pytest.raises(Refused):
        Sandbox(mode="none").verify_lock()
