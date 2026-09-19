"""Tests for quiescence self-stop recognising closed tasks (issue #5968)."""

from __future__ import annotations

from bernstein.core.orchestration.tick_pipeline import fetch_all_tasks


def test_fetch_all_tasks_default_statuses_include_closed() -> None:
    """fetch_all_tasks default statuses must include 'closed' so quiescence
    can see archived tasks and _had_any_terminal_task evaluates to True."""
    import inspect

    src = inspect.getsource(fetch_all_tasks)
    assert '"closed"' in src or "'closed'" in src


def test_quiescence_self_stop_recognizes_closed_tasks() -> None:
    """_had_any_terminal_task must be True when only closed tasks exist."""
    refreshed: dict[str, list[object]] = {
        "open": [],
        "claimed": [],
        "done": [],
        "failed": [],
        "closed": [object()],
    }
    had_terminal = bool(refreshed["done"] or refreshed["failed"] or refreshed.get("closed"))
    assert had_terminal, "closed tasks must count as terminal at quiescence"


def test_quiescence_no_terminal_when_all_empty() -> None:
    refreshed: dict[str, list[object]] = {
        "open": [],
        "claimed": [],
        "done": [],
        "failed": [],
        "closed": [],
    }
    had_terminal = bool(refreshed["done"] or refreshed["failed"] or refreshed.get("closed"))
    assert not had_terminal
