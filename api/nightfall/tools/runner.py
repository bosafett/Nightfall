"""Runs a third-party tool binary with nothing it doesn't need (review §13).

* argv list, never a shell. Arguments come from adapters, built from enum-typed values.
* Empty environment apart from PATH, HOME and TMPDIR (a fresh per-run directory): the
  tool never sees database URLs, keys or the worker's own proxy settings.
* Own process group, killed as a whole on timeout. CPU-time, file-size, open-file and
  core-dump limits. stdout and stderr captured with a size cap.
* Sandbox "uid": the tool runs as a separate unprivileged user whose only permitted
  network destination is the egress proxy port (kernel firewall rule installed by
  infra/tools/egress-lock.sh). Before the first run the lock is verified: the tool user
  must fail to reach a canary port on loopback. Live runs of network tools refuse to
  start without a verified lock.
* Sandbox "none": development and tests only. Isolation then rests on the proxy alone,
  and the worker refuses to use it in live mode.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from nightfall.recon.safe_http import Refused

MAX_STREAM = 4 * 1024 * 1024


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    timed_out: bool
    workdir_files: dict[str, bytes]


# Tools only run on POSIX (the worker container). Elsewhere, such as BLACKSITE on a Windows
# lab machine, this module still has to import, but the sandbox doesn't exist there, so
# verify_lock and run refuse before anything starts.
_POSIX = os.name == "posix"
_NOT_POSIX = "External tools only run in the Linux worker; nothing was run."

# Loaded in the parent: the child runs between fork and exec while proxy threads exist,
# where dlopen isn't safe.
if _POSIX:
    import resource

    _LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4


def _drop_privileges() -> None:  # pragma: no cover - runs in the child before exec
    """The worker holds CAP_SETUID/CAP_SETGID as ambient capabilities so it can start tools
    as the tool user. Without this the tool would inherit them, could switch to another
    uid and leave the uid-based network lock. Clearing the ambient set means exec grants
    nothing; no_new_privs blocks setuid binaries and file capabilities."""
    libc = _LIBC
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        if err != errno.EINVAL:  # EINVAL: kernel without ambient capabilities
            raise OSError(err, "PR_CAP_AMBIENT_CLEAR_ALL failed")
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")


def _limits(  # pragma: no cover - runs in child
    cpu_seconds: int, max_file: int, umask: int | None
) -> None:
    _drop_privileges()
    if umask is not None:
        os.umask(umask)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _drain(stream: object, sink: bytearray, cap: int, flags: dict[str, bool]) -> None:
    read = stream.read  # type: ignore[attr-defined]
    while chunk := read(65536):
        room = cap - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > room:
            flags["truncated"] = True


@dataclass(frozen=True)
class Sandbox:
    mode: str = "none"  # "uid" | "none"
    user: str | None = None  # tool user for mode "uid"

    def verify_lock(self) -> None:
        """Raises Refused unless, as the tool user: loopback is unreachable (and so, by the
        same firewall rule, everything except the proxy port), and switching to another
        user (root included) fails."""
        if not _POSIX:
            raise Refused(_NOT_POSIX)
        if self.mode != "uid" or not self.user:
            raise Refused("The tool sandbox is not active, so external tools can't run.")
        canary = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        canary.bind(("127.0.0.1", 0))
        canary.listen(1)
        port = canary.getsockname()[1]
        probe = (
            "import os,socket,sys\n"
            "for uid in (0, os.getuid() + 1):\n"
            "    try:\n"
            "        os.setuid(uid); sys.exit(4)\n"
            "    except PermissionError:\n"
            "        pass\n"
            "s=socket.socket(); s.settimeout(2)\n"
            f"sys.exit(0 if s.connect_ex(('127.0.0.1',{port}))==0 else 3)\n"
        )
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv
                [sys.executable, "-I", "-c", probe],
                user=self.user,
                env={"PATH": "/usr/bin:/bin"},
                preexec_fn=_drop_privileges,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Refused(f"Couldn't start the tool sandbox: {type(exc).__name__}.") from exc
        finally:
            canary.close()
        if result.returncode == 4:
            raise Refused("The tool user can change identity; the sandbox is unsafe.")
        if result.returncode != 3:
            raise Refused("The tool sandbox's network lock isn't active; nothing was run.")


def run(
    argv: list[str],
    *,
    sandbox: Sandbox,
    timeout: float,
    cpu_seconds: int = 600,
    max_file: int = 32 * 1024 * 1024,
    collect: tuple[str, ...] = (),
    max_collect: int = 8 * 1024 * 1024,
) -> RunResult:
    """Runs argv in a fresh temporary directory, which is also HOME. Files named in
    `collect` are read back (capped) before the directory is removed."""
    if not _POSIX:
        raise Refused(_NOT_POSIX)
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("argv[0] must be an absolute path")
    workdir = Path(tempfile.mkdtemp(prefix="nf-tool-"))
    try:
        uid_mode = sandbox.mode == "uid"
        if uid_mode:
            if not sandbox.user:
                raise ValueError("sandbox user missing")
            # The worker has no CAP_CHOWN. The run directory (random name, removed after
            # the run) is opened up instead, and the tool runs with umask 0 so the worker
            # can read and delete whatever it writes.
            workdir.chmod(0o777)  # noqa: S103
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(workdir), "TMPDIR": str(workdir)}
        proc = subprocess.Popen(  # noqa: S603 - argv list from adapters, no shell
            argv,
            cwd=workdir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            process_group=0,
            user=sandbox.user if sandbox.mode == "uid" else None,
            preexec_fn=lambda: _limits(cpu_seconds, max_file, 0 if uid_mode else None),
            close_fds=True,
        )
        out, err = bytearray(), bytearray()
        flags = {"truncated": False}
        errflags = {"truncated": False}
        readers = [
            threading.Thread(target=_drain, args=(proc.stdout, out, MAX_STREAM, flags)),
            threading.Thread(target=_drain, args=(proc.stderr, err, 256 * 1024, errflags)),
        ]
        for t in readers:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        else:
            # The tool exited; make sure nothing it spawned outlives it.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        for t in readers:
            t.join(timeout=5)
        files: dict[str, bytes] = {}
        for name in collect:
            path = workdir / name
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as fh:
                    files[name] = fh.read(max_collect)
        return RunResult(
            returncode=proc.returncode,
            stdout=bytes(out),
            stderr=bytes(err),
            stdout_truncated=flags["truncated"],
            timed_out=timed_out,
            workdir_files=files,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
