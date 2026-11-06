"""Launch a registered application behind a verified namespace and lease gate.

The application cannot exec before the durable consumer lease exists. The
privileged parent stays alive to reap the child and release its exited lease.
This is a cooperating-process launch contract, not a hostile-root boundary.
"""

from __future__ import annotations

import os
from pathlib import Path
import select
import subprocess
import sys

from nord_tools_internal.nordvpn_application_plan import plan_application
from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError, read_private_json
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_runtime_consumers import (
    reserve_staged_consumer,
    release_exited_consumer,
)


def _namespace_for_profile(journal_path: str, profile: str) -> str:
    journal = validate_journal(read_private_json(journal_path))
    candidates = [
        item["identifier"]
        for item in journal["allocations"]["resources"]
        if item["profile"] == profile and item["kind"] == "namespace"
    ]
    if len(candidates) != 1:
        raise ConsumerReferenceError("application allocation has no unique namespace")
    return candidates[0]


def launch_provisioned_application(
    policy: dict,
    application: str,
    arguments: tuple[str, ...],
    *,
    runtime_consumers: str,
    journal_path: str,
    bindings_path: str,
    intent_path: str,
    observe,
    uid: int,
    gid: int,
    ready_timeout: float = 10.0,
) -> int:
    """Block until the registered program exits; refuse unverified execution.

    The caller must be root, with an explicit non-root target identity. The
    gate blocks inside the namespace until ownership and the durable lease are
    verified; a failed verification closes its pipe without executing the app.
    """
    if os.geteuid() != 0 or type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise ConsumerReferenceError("privileged launcher requires a non-root target uid and gid")
    if not intent_path:
        raise ConsumerReferenceError("application launch requires a pinned operation intent store")
    plan = plan_application(policy, application, arguments)
    kernel_profile = kernel_profile_for_allocation(plan.allocation_key, plan.profile, plan.sharing)
    namespace = _namespace_for_profile(journal_path, kernel_profile)
    # Resolve the interpreter before creating the child. It is only the trusted
    # gate; the registered executable is never run by a shell.
    interpreter = str(Path(sys.executable).resolve(strict=True))
    gate_script = str(Path(__file__).with_name("nordvpn_launch_gate.py").resolve(strict=True))
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    release_r, release_w = os.pipe2(os.O_CLOEXEC)
    process = None
    reserved = False
    try:
        # pass_fds clears CLOEXEC only for the gate's descriptors.
        process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                interpreter,
                "-I",
                gate_script,
                str(ready_w),
                str(release_r),
                str(uid),
                str(gid),
                plan.executable,
                *plan.arguments,
            ],
            pass_fds=(ready_w, release_r),
            close_fds=True,
        )
        os.close(ready_w)
        ready_w = -1
        os.close(release_r)
        release_r = -1
        readable, _, _ = select.select([ready_r], [], [], ready_timeout)
        if not readable or os.read(ready_r, 1) != b"R" or process.poll() is not None:
            raise ConsumerReferenceError("application gate did not reach its pre-exec barrier")
        reserve_staged_consumer(
            runtime_consumers,
            policy,
            application,
            process.pid,
            namespace=namespace,
            staging_executable=interpreter,
            journal_path=journal_path,
            bindings_path=bindings_path,
            intent_path=intent_path,
            observe=observe,
        )
        reserved = True
        os.write(release_w, b"G")
        os.close(release_w)
        release_w = -1
        return process.wait()
    finally:
        for fd in (ready_r, ready_w, release_r, release_w):
            if fd >= 0:
                os.close(fd)
        if process is not None:
            if process.poll() is None:
                process.terminate()
            process.wait()
        if reserved:
            release_exited_consumer(runtime_consumers, policy, application)
