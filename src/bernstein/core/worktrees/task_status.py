"""Read a task's terminal status straight from the task log (#5112).

``bernstein worktrees gc`` classifies a worktree as reapable using process
liveness and trace-file age (:mod:`bernstein.core.worktrees.classifier`) --
never the task record's actual status. Both heuristics can be wrong in either
direction: a PID can outlive the task it served (reparented, wedged, or simply
slow to exit after its last write), and a trace file can go stale while the
task is still legitimately running. Reading the task's own recorded status is
authoritative where either heuristic is a guess.

This module does not open the full async :class:`~bernstein.core.tasks.task_store_core.TaskStore`
-- that machinery exists to serve a live orchestrator, with hooks, locks, and
an event loop a one-shot CLI read has no use for. Task persistence is itself
an append-only JSONL log, replayed to the latest record per task id
(``TaskStore.__init__`` does exactly this on startup); this module does the
same replay, read-only, for one purpose: "what does the log say this task's
status is right now."
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from bernstein.core.orchestration.run_stall import TERMINAL_STATUSES

if TYPE_CHECKING:
    from pathlib import Path

#: Relative to the project root's ``.sdd`` directory. Mirrors the paths
#: ``TaskStore`` is constructed with elsewhere (e.g. ``context_cmd.py``,
#: ``maintenance_cmd.py``): the live log first, the archive second, so a task
#: that has been rotated out of the live log is still found.
_TASK_LOG_RELPATHS: tuple[str, ...] = ("runtime/tasks.jsonl", "archive/tasks.jsonl")


def _replay_task_statuses(path: Path) -> dict[str, str]:
    """Return ``{task_id: status}`` from one JSONL task log, last record wins.

    A damaged line is skipped, not fatal -- the same tolerance
    ``TaskStore.__init__`` applies to its own log, for the same reason: one
    torn line from a crash mid-write must not make every other task's status
    unreadable.
    """
    statuses: dict[str, str] = {}
    if not path.is_file():
        return statuses
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        task_id = record.get("id")
        status = record.get("status")
        if isinstance(task_id, str) and task_id and isinstance(status, str) and status:
            statuses[task_id] = status
    return statuses


def read_task_statuses(sdd_dir: Path) -> dict[str, str]:
    """Return ``{task_id: status}`` for every task the on-disk logs know about.

    Reads the live task log first, then the archive; a task id present in
    both keeps the live log's value only if the archive has no entry for it
    -- an archived task's own record is its last known status before
    archival, so archive entries are applied where the live log is silent
    rather than the other way around.

    Args:
        sdd_dir: The project's ``.sdd`` directory.

    Returns:
        Mapping from task id to its most recently recorded status string.
        Empty when neither log exists.
    """
    merged: dict[str, str] = {}
    for relpath in reversed(_TASK_LOG_RELPATHS):
        merged.update(_replay_task_statuses(sdd_dir / relpath))
    return merged


def task_is_terminal(sdd_dir: Path, task_id: str) -> bool | None:
    """Return whether *task_id*'s recorded status is terminal.

    Args:
        sdd_dir: The project's ``.sdd`` directory.
        task_id: Task identifier to look up.

    Returns:
        ``True`` when the task log's latest record for *task_id* is a
        terminal status (see :data:`bernstein.core.orchestration.run_stall.TERMINAL_STATUSES`),
        ``False`` when it is recorded and not terminal, and ``None`` when no
        log knows this task id at all -- undecidable, not "not terminal".
    """
    status = read_task_statuses(sdd_dir).get(task_id)
    if status is None:
        return None
    return status in TERMINAL_STATUSES


__all__ = ["read_task_statuses", "task_is_terminal"]
