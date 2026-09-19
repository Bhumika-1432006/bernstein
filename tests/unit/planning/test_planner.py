"""Tests for _post_task_to_server in planner.py."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from bernstein.core.planning.planner import _post_task_to_server
from bernstein.core.tasks.models import CompletionSignal, Task


def _make_task(**kwargs: Any) -> Task:
    defaults: dict[str, Any] = {
        "id": "t-1",
        "title": "Test task",
        "description": "desc",
        "role": "backend",
    }
    defaults.update(kwargs)
    return Task(**defaults)


@pytest.mark.asyncio
@respx.mock
async def test_post_task_to_server_forwards_completion_signals() -> None:
    server_url = "http://localhost:9999"
    signals = [
        CompletionSignal(type="file_exists", value="src/foo.py"),
        CompletionSignal(type="test_passes", value="pytest tests/test_foo.py"),
    ]
    task = _make_task(completion_signals=signals)

    route = respx.post(f"{server_url}/tasks").mock(return_value=httpx.Response(201, json={"id": "server-t-1"}))

    async with httpx.AsyncClient() as client:
        task_id = await _post_task_to_server(client, server_url, task)

    assert task_id == "server-t-1"
    sent = json.loads(route.calls[0].request.content)
    assert sent["completion_signals"] == [
        {"type": "file_exists", "value": "src/foo.py"},
        {"type": "test_passes", "value": "pytest tests/test_foo.py"},
    ]


@pytest.mark.asyncio
@respx.mock
async def test_post_task_to_server_omits_completion_signals_when_empty() -> None:
    server_url = "http://localhost:9999"
    task = _make_task(completion_signals=[])

    respx.post(f"{server_url}/tasks").mock(return_value=httpx.Response(201, json={"id": "server-t-2"}))

    async with httpx.AsyncClient() as client:
        task_id = await _post_task_to_server(client, server_url, task)

    assert task_id == "server-t-2"
    route = respx.calls.last
    sent = json.loads(route.request.content)
    assert "completion_signals" not in sent
