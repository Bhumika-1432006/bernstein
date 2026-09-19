"""Tests for dynamic server URL rendering in spawn_prompt (issue #5964)."""

from __future__ import annotations

import os

from bernstein.core.agents.spawn_prompt import _legacy_completion_instructions
from bernstein.core.tasks.models import Task


def _make_task(task_id: str = "t-1", title: str = "Test") -> Task:
    return Task(id=task_id, title=title, description="desc", role="backend")


def test_spawn_prompt_renders_dynamic_server_port(monkeypatch: object) -> None:
    """curl examples use BERNSTEIN_SERVER_URL when set."""
    import pytest

    monkeypatch.setenv("BERNSTEIN_SERVER_URL", "http://127.0.0.1:19876")
    tasks = [_make_task("t-42")]
    result = _legacy_completion_instructions(tasks)
    assert "http://127.0.0.1:19876" in result
    assert "8052" not in result


def test_legacy_completion_instructions_falls_back_to_default(monkeypatch: object) -> None:
    """curl examples fall back to 8052 when BERNSTEIN_SERVER_URL is unset."""
    monkeypatch.delenv("BERNSTEIN_SERVER_URL", raising=False)
    tasks = [_make_task("t-1")]
    result = _legacy_completion_instructions(tasks)
    assert "http://127.0.0.1:8052" in result
