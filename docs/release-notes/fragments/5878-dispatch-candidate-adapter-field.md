## Dispatch candidates now carry the real adapter name

`build_dispatch_candidates` read a task's adapter override off a nonexistent
`adapter` attribute instead of the actual `cli` field on `Task`, so
`DispatchCandidate.adapter` was always empty. Because the knob-matrix resolver
gates batch lane and prompt-cache warm-up on the adapter name, this silently
kept every task on the interactive lane with no cache warm-up, regardless of
what the pinned knob matrix granted. Dispatch candidates now read the task's
`cli` field, so batch-capable and cache-capable adapters get the lane and
cache economics the matrix actually declares for them (#5878).
