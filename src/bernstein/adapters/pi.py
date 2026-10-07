"""Pi (pi-coding-agent) CLI adapter."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.models import ModelConfig

from bernstein.adapters.base import DEFAULT_TIMEOUT_SECONDS, CLIAdapter, SpawnResult, build_worker_cmd
from bernstein.adapters.env_isolation import build_filtered_env

#: Pi flags that keep a spawned worker off the operator's own Pi setup.
#:
#: ``-ne`` (``--no-extensions``) disables discovered, configured and built-in
#: extensions. Pi's MCP support is a built-in extension, so without this every
#: worker connects to every server in the operator's global Pi configuration:
#: dozens of private background MCP processes across concurrent runs, and their
#: tools in the worker's context that the task never asked for (#5965).
#: ``-ne`` is the short form of ``--no-extensions`` in Pi's CLI reference; a Pi
#: too old to know it reports an unknown option and exits.
_ISOLATION_FLAGS: tuple[str, ...] = ("-ne",)


class PiAdapter(CLIAdapter):
    """Spawn and monitor Pi (``pi-coding-agent``) CLI sessions.

    Pi is an npm-distributed coding agent
    (``@mariozechner/pi-coding-agent``).  The CLI takes the task prompt
    as a positional argument; ``-c`` exists for resume but is not used
    when spawning a fresh session.  See
    https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent.

    Workers are spawned with extension discovery off (``-ne``), so they do
    not inherit the operator's global MCP servers or other extensions.
    """

    def spawn(
        self,
        *,
        prompt: str,
        workdir: Path,
        model_config: ModelConfig,
        session_id: str,
        mcp_config: dict[str, Any] | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        task_scope: str = "medium",
        budget_multiplier: float = 1.0,
        system_addendum: str = "",
        multimodal_context: Any | None = None,
    ) -> SpawnResult:
        """Launch a Pi coding-agent session.

        Args:
            prompt: Task prompt passed as the single positional argument.
            workdir: Working directory for the agent process.
            model_config: Model and effort configuration. The selected model
                is passed through to Pi when it is not ``auto``.
            session_id: Unique session identifier used for the log file.
            mcp_config: Unused. Pi manages its own integrations, and the worker
                is started with extensions off so it does not pick up the
                operator's global MCP servers.
            timeout_seconds: Watchdog timeout in seconds.
            task_scope: Unused scope hint.
            budget_multiplier: Unused budget multiplier.
            system_addendum: Unused system-prompt addendum.

        Returns:
            :class:`SpawnResult` describing the launched process.

        Raises:
            RuntimeError: If the ``pi`` binary is missing or not
                executable.
        """
        self.refuse_multimodal_if_needed(multimodal_context)
        log_path = workdir / ".sdd" / "runtime" / f"{session_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["pi", *_ISOLATION_FLAGS]
        if model_config.model and model_config.model.lower() != "auto":
            cmd.extend(["--model", model_config.model])
        cmd.append(prompt)

        pid_dir = workdir / ".sdd" / "runtime" / "pids"
        wrapped_cmd = build_worker_cmd(
            cmd,
            role=session_id.rsplit("-", 1)[0],
            session_id=session_id,
            pid_dir=pid_dir,
            workdir=workdir,
            log_path=log_path,
            model=model_config.model,
        )

        env = build_filtered_env(
            ["PI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"],
        )
        with log_path.open("w") as log_file:
            try:
                proc = subprocess.Popen(
                    wrapped_cmd,
                    cwd=workdir,
                    env=env,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                msg = (
                    "pi not found in PATH. Install: npm install -g @mariozechner/pi-coding-agent "
                    "or see https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent"
                )
                raise RuntimeError(msg) from exc
            except PermissionError as exc:
                raise RuntimeError(f"Permission denied executing pi: {exc}") from exc

        result = SpawnResult(pid=proc.pid, log_path=log_path, proc=proc)
        if timeout_seconds > 0:
            result.timeout_timer = self._start_timeout_watchdog(proc.pid, timeout_seconds, session_id)
        return result

    def name(self) -> str:
        """Return the human-readable adapter name."""
        return "Pi"
