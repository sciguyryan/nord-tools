"""Journal-gated experimental provisioning execution.

The caller supplies an already validated lifecycle journal and a narrowly scoped
operation callback. This adapter records a durable intent before invoking it.
Neither the journal nor the outcome grants authority to retire kernel resources.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_operation_store import read_intents, update_intent
from nord_tools_internal.nordvpn_registry import RegistryError

T = TypeVar("T")


class ProvisioningUncertainError(RuntimeError):
    """An operation may have changed the kernel and needs operator review."""


def execute_recorded_creation(
    store_path: str | Path,
    journal: object,
    allocation_id: str,
    operation: Callable[[], T],
    verify: Callable[[T], bool],
) -> T:
    """Run an experimental creation only after a pending intent is durable.

    An existing store is mandatory. The callback must be restricted to disposable
    resources with independent creation-time authority. Do not use this adapter
    for production provisioning or resource deletion.
    """
    if not callable(operation) or not callable(verify):
        raise RegistryError("operation and verifier must be callable")
    validated = validate_journal(journal)
    # Refuse absent or corrupt stores before any mutation. An unresolved record
    # remains a hard stop, including after a previous process was interrupted.
    read_intents(store_path, validated)
    started = update_intent(store_path, validated, allocation_id=allocation_id, action="create")
    operation_id = started["operations"][-1]["operation_id"]
    try:
        result = operation()
        if verify(result) is not True:
            raise ProvisioningUncertainError("creation could not be independently verified")
    except BaseException:
        # Even an exception before an observed mutation does not prove that the
        # kernel was unchanged. Preserve uncertainty rather than claim failure.
        try:
            update_intent(store_path, validated, operation_id=operation_id, outcome="uncertain")
        except Exception:
            pass  # The original exception must not be concealed.
        raise
    try:
        update_intent(store_path, validated, operation_id=operation_id, outcome="completed")
    except Exception as exc:
        raise ProvisioningUncertainError("creation succeeded but its completion could not be recorded") from exc
    return result
