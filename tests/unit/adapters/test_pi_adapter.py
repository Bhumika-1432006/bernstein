"""A spawned Pi worker is isolated from the operator's own Pi configuration (#5965).

Pi's MCP support is a built-in extension. Started without ``-ne``
(``--no-extensions``), every worker connects to every server in the operator's
global Pi configuration, so a run with N concurrent workers launches N private
copies of each of them and fills each worker's context with tools the task never
asked for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from bernstein.core.models import ModelConfig

from bernstein.adapters.pi import PiAdapter
from tests.unit._adapter_test_helpers import inner_cmd, make_popen_mock

if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("no_watchdog_threads")

_PROMPT = "fix the bug"


def _spawn_argv(
    tmp_path: Path,
    *,
    model: str = "auto",
    mcp_config: dict[str, Any] | None = None,
) -> list[str]:
    """Spawn a Pi worker against a mocked ``Popen`` and return the argv Pi would see."""
    adapter = PiAdapter()
    with patch("bernstein.adapters.pi.subprocess.Popen", return_value=make_popen_mock(pid=900)) as popen:
        adapter.spawn(
            prompt=_PROMPT,
            workdir=tmp_path,
            model_config=ModelConfig(model=model, effort="high"),
            session_id="pi-iso",
            mcp_config=mcp_config,
        )
    return inner_cmd(popen.call_args.args[0])


def test_pi_spawn_includes_mcp_isolation_flags(tmp_path: Path) -> None:
    """The worker is started with extensions, and so Pi's built-in MCP support, off."""
    argv = _spawn_argv(tmp_path)

    assert "-ne" in argv


def test_isolation_flag_precedes_the_prompt(tmp_path: Path) -> None:
    """Pi takes the prompt as its positional argument, so an option has to come before it."""
    argv = _spawn_argv(tmp_path)

    assert argv[:2] == ["pi", "-ne"]
    assert argv[-1] == _PROMPT


def test_isolation_is_kept_when_a_model_is_selected(tmp_path: Path) -> None:
    """Choosing a model adds ``--model``; it must not displace the isolation flag."""
    argv = _spawn_argv(tmp_path, model="provider/model-name")

    assert argv == ["pi", "-ne", "--model", "provider/model-name", _PROMPT]


@pytest.mark.parametrize(
    "mcp_config",
    [
        {"mcpServers": {"notes": {"command": "notes-mcp"}}},
        # The spawner folds non-server keys (sampling, heartbeat dirs) into the same
        # dict, so a non-empty config is not evidence that servers were declared.
        {"temperature": 0.2},
    ],
)
def test_an_mcp_config_does_not_lift_the_isolation(tmp_path: Path, mcp_config: dict[str, Any]) -> None:
    """``PiAdapter`` never passes ``mcp_config`` to Pi, so it cannot be a reason to un-isolate.

    Un-isolating on it would hand the worker the operator's whole global server set,
    not the servers the task declared, which is the pollution this guards against.
    """
    argv = _spawn_argv(tmp_path, mcp_config=mcp_config)

    assert "-ne" in argv
