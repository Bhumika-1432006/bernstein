## Ordinary crash/timeout retries now record a checkpoint before restarting

Checkpointed retries (#2359/#2403) decide warm/fork/cold from the latest
recorded checkpoint, but the only production caller of
`record_task_checkpoint` was `SteeringController._pause` -- an
operator-issued pause. A session that died to a crash, a failed janitor
gate, a heartbeat timeout, or a transport failure never had a checkpoint
recorded for it, so `retry_or_fail_task` always fell back to a cold
retry regardless of whether the worktree it died in was still resumable.

Each of the six `retry_or_fail_task` call sites in `agent_lifecycle.py`
that still has the dying session in scope now records a best-effort
checkpoint (adapter, session id, worktree hash) immediately beforehand.
The checkpoint attempt never raises and never blocks the retry: a
worktree that can't be located or hashed just leaves the retry cold, the
prior behaviour.
