"""CoSAI Principles for Secure-by-Design Agentic Systems & Risk Map control map.

Operators running compliance-sensitive agentic workloads need to show,
from their own run evidence, which CoSAI (Coalition for Secure AI, OASIS
Open Project) Principles for Secure-by-Design Agentic Systems and Risk Map controls
a Bernstein run covers. This module provides the CoSAI analogue of the EU
AI Act, OWASP ASI/AST, and ISO/IEC 42001 control maps in
``evidence_pack.py``.

The map is structured around the three core principles published by the
CoSAI Technical Steering Committee (TSC) in *CoSAI Principles for Secure-by-Design
Agentic Systems* (``cosai-oasis/cosai-tsc``, ``security-principles-for-agentic-systems.md``):
* ``human-governed-accountable``: Human-governed and Accountable.
* ``bounded-resilient``: Bounded and Resilient.
* ``transparent-verifiable``: Transparent and Verifiable.

Sub-clause identifiers (e.g. ``human-governed-accountable.oversight``) are
Bernstein's internal control IDs organized under the TSC's three top-level
principles. Where the CoSAI Risk Map (``cosai-oasis/secure-ai-tooling``,
``risk-map/yaml/controls.yaml``) defines a corresponding control, its
upstream identifier (e.g. ``controlAgentPluginUserControl``) is cited. Where
no direct Risk Map control exists, no Risk Map ID is asserted.

Three-state honesty rule:
* ``"mapped"``  - the chain contains records that satisfy the control;
                  the ``selector`` names the concrete audit evidence.
* ``"partial"`` - the chain covers part of the control; ``requirement``
                  states what is missing.
* ``"todo"``    - the control is recognized in the catalogue but not yet
                  enforced or chained by the orchestrator today.

The block is consumed by ``evidence_pack.build_evidence_pack`` under the
``cosai`` standard. It mirrors the ``_STANDARD_MAPS`` shape exactly:

    {
        "regulation": <str>,
        "controls": [ {control_id, requirement, artefact, selector, status}, ... ],
        "deferred": [ <str>, ... ],
    }

CoSAI TSC guidance documents (cosai-oasis/cosai-tsc) are published under CC BY 4.0;
Risk Map controls (cosai-oasis/secure-ai-tooling) are published under Apache-2.0.
Principle titles are quoted with attribution to the CoSAI TSC and control descriptions
are paraphrased.

MCP threat classes (``mcp-threats.*``)
--------------------------------------
The second block of rows maps the twelve threat classes (``MCP-T1`` to ``MCP-T12``) of
the CoSAI *Model Context Protocol (MCP) Security* white paper (see :data:`MCP_PAPER` for
the version and date these rows follow). Each row carries the paper's own class name in
its requirement text and a stable ``mcp-threats.tN-...`` identifier of Bernstein's own,
because the paper's numbering may still change.

The same three-state honesty rule applies, and it matters more here than elsewhere: the
MCP signing and scan gate (:mod:`bernstein.core.protocols.mcp.mcp_signing_policy`) is
enforced by ``MCPManager`` before a third-party server is spawned, but its verdicts are
not written to the audit chain, so a class that depends on them is ``partial`` and says
what is missing. Only event types that production code emits are cited as selectors;
``mcp.task_handle`` is not, because ``record_mcp_task_handle`` has no production caller.
The paper is a CoSAI Non-Standards Track Work Product; the rows paraphrase it and quote
only its class titles, under the permissions in its copyright notice (reproduced in
``docs/compliance/cosai-mapping.md``).
"""

from __future__ import annotations

from typing import Any

#: Standard id used on the ``--standard`` flag and in manifests.
STANDARD_ID: str = "cosai"

#: Human-readable catalogue name emitted into ``controls.json``.
REGULATION: str = "CoSAI Principles for Secure-by-Design Agentic Systems & Risk Map Controls"

#: The CoSAI white paper the ``mcp-threats.*`` rows follow. The paper is a draft and its
#: numbering may still change, so the version and date are recorded with the rows. ``version``
#: is the identifier printed on the paper's cover (a revision hash); ``date`` is the date on
#: the cover; ``announced`` is the OASIS Open release announcement.
MCP_PAPER: dict[str, str] = {
    "title": "Model Context Protocol (MCP) Security",
    "publisher": "Coalition for Secure AI (CoSAI), an OASIS Open Project; Workstream 4: Secure Design Patterns",
    "version": "7ec1306f2f55563f6eeef9d36a6bb2b531491ceb",
    "date": "8 January 2026",
    "status": "Draft",
    "announced": "27 January 2026",
    "url": "https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf",
}

# ---------------------------------------------------------------------------
# CoSAI TSC principles & Risk Map control map
# ---------------------------------------------------------------------------
#
# Each entry maps a Bernstein control identifier under the CoSAI TSC principles to:
#   * ``control_id``  - Internal principle sub-clause identifier.
#   * ``requirement`` - Paraphrased requirement text, Risk Map ID (if any), and mechanism.
#   * ``artefact``    - Bundle file carrying the evidence.
#   * ``selector``    - Literal event_type tokens or attribute selectors.
#   * ``status``      - "mapped", "partial", or "todo".

CONTROLS: list[dict[str, Any]] = [
    # -----------------------------------------------------------------------
    # Principle 1: Human-governed and Accountable
    # -----------------------------------------------------------------------
    {
        "control_id": "human-governed-accountable.oversight",
        "requirement": (
            "Human oversight and user control (Risk Map: controlAgentPluginUserControl): "
            "Sensitive agent actions require human approval; approval states, resolver identities, "
            "and auto-approval decisions are cryptographically recorded in the audit chain."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "approval_pending,approval_resolved,auto_approve_decision,human_approval_decision",
        "status": "mapped",
    },
    {
        "control_id": "human-governed-accountable.dual-control",
        "requirement": (
            "Dual authorization for critical operations: Multi-party approval policies enforce "
            "quorum requirements for high-risk actions. Multi-party resolution signatures and "
            "quorum validation are not yet emitted to the audit chain."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "todo",
    },
    {
        "control_id": "human-governed-accountable.identity",
        "requirement": (
            "Agent identity and integrity management (Risk Map: controlAgentIntegrityManagement): "
            "Delegation minting between parent and subagents is recorded in the audit chain; "
            "agent card signing (detached JWS, Ed25519) is not chained."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "delegation_minted",
        "status": "partial",
    },
    {
        "control_id": "human-governed-accountable.mandate",
        "requirement": (
            "Payment mandate and consent governance: User spending mandates and consent boundaries "
            "are checked before task execution, and mandate consent or revocation events are chained."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "mandate.consent_receipt,mandate.revocation",
        "status": "mapped",
    },
    # -----------------------------------------------------------------------
    # Principle 2: Bounded and Resilient
    # -----------------------------------------------------------------------
    {
        "control_id": "bounded-resilient.least-privilege",
        "requirement": (
            "Least privilege and plugin permissions (Risk Map: controlAgentPluginPermissions): "
            "Lethal-trifecta matrix bounds agent agency across private data, untrusted input, and external egress. "
            "Unauthorized capability expansion is denied and recorded."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "capability_matrix_refusal",
        "status": "mapped",
    },
    {
        "control_id": "bounded-resilient.sandboxing",
        "requirement": (
            "Execution sandboxing and bounds: Tool and command execution runs under restricted sandbox "
            "profiles with strict command allowlists; runtime enforcement occurs at the policy layer "
            "without chained escape event records."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "bounded-resilient.resource-bounds",
        "requirement": (
            "Resource and cost bounding (Risk Map: controlAgentExecutionBounds): "
            "Recorded spend vs budget: cost ledger snapshots track spent and budget amounts."
        ),
        "artefact": "costs/cost_history.jsonl",
        "selector": "spent_usd,budget_usd",
        "status": "mapped",
    },
    {
        "control_id": "bounded-resilient.codeguard",
        "requirement": (
            "CoSAI CodeGuard rule set preset: Automated guardrail preset loaded with CoSAI CodeGuard rules. "
            "CodeGuard (cosai-oasis/project-codeguard) is not currently loaded as a pre-configured guardrail "
            "preset in Bernstein."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "todo",
    },
    # -----------------------------------------------------------------------
    # Principle 3: Transparent and Verifiable
    # -----------------------------------------------------------------------
    {
        "control_id": "transparent-verifiable.supply-chain",
        "requirement": (
            "Supply chain component verification: Skill packages and catalog entries carry "
            "verified Ed25519 signatures prior to installation; fetch, install, upgrade, "
            "and uninstall operations are audited."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "skill.catalog.install,skill.catalog.fetch,skill.catalog.upgrade,skill.catalog.uninstall",
        "status": "mapped",
    },
    {
        "control_id": "transparent-verifiable.audit-trail",
        "requirement": (
            "Agent observability and tamper-evident audit logging (Risk Map: controlAgentObservability): "
            "All task transitions and agent lifecycle state changes are logged into an "
            "RFC 2104 HMAC-chained audit log with offline verification."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "task.transition,agent.transition",
        "status": "mapped",
    },
    {
        "control_id": "transparent-verifiable.lineage-provenance",
        "requirement": (
            "Model and data integrity management (Risk Map: controlModelAndDataIntegrityManagement): "
            "Content-addressed lineage log records SHA-256 digests and parent provenance for all produced artifacts, "
            "detecting tampering against recorded hashes."
        ),
        "artefact": "lineage/log.jsonl",
        "selector": "content_hash,parent_hashes",
        "status": "mapped",
    },
    {
        "control_id": "transparent-verifiable.replay-reproducibility",
        "requirement": (
            "Deterministic trajectory reconstruction: Task and agent lifecycle transitions in the HMAC "
            "audit chain record coarse execution flow (task.transition, agent.transition). Fine-grained "
            "step-level deterministic replay execution is tracked in local runtime journals (.sdd/runtime/) "
            "rather than emitted directly as audit-chain events."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "task.transition,agent.transition",
        "status": "partial",
    },
    {
        "control_id": "transparent-verifiable.context-integrity",
        "requirement": (
            "Input validation, sanitization, and context integrity (Risk Map: controlInputValidationAndSanitization): "
            "Screening and audit recording of prompt injection and context capsules. Detection of "
            "semantic memory poisoning across multiple sessions remains partial."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "context.capsule,capability_matrix_refusal",
        "status": "partial",
    },
    # -----------------------------------------------------------------------
    # MCP threat classes: CoSAI "Model Context Protocol (MCP) Security" (see MCP_PAPER)
    # -----------------------------------------------------------------------
    {
        "control_id": "mcp-threats.t1-authentication-identity",
        "requirement": (
            "MCP-T1 Improper Authentication and Identity Management: The streamable HTTP transport refuses "
            "to bind a non-loopback host with no authentication or no bearer token, and the server publishes "
            "OAuth 2 protected-resource metadata so a client can find its authorization server. A third-party "
            "server's publisher is checked by an Ed25519 manifest signature before it is spawned. No "
            "authentication decision and no manifest verdict is written to the audit chain."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t2-access-control",
        "requirement": (
            "MCP-T2 Missing or Improper Access Control: The lethal-trifecta capability matrix refuses a spawn "
            "that would combine private data, untrusted input and external egress, and the refusal is "
            "recorded in the audit chain. The tool surface a client sees is tiered. Object-level and "
            "per-user authorization inside a third-party MCP server is outside what Bernstein enforces."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "capability_matrix_refusal",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t3-input-validation",
        "requirement": (
            "MCP-T3 Input Validation / Sanitization Failures: Every tool call to the Bernstein MCP server is "
            "validated against a registered schema before its handler runs, deny-by-default: unknown tools "
            "and properties, oversize or deeply nested payloads and control characters are rejected. The "
            "client contains responses that violate their schema. The static scanner flags path-traversal "
            "and shell-injection patterns in a third-party server's source. A refused call and a scanner "
            "finding are not written to the audit chain."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t4-instruction-boundary",
        "requirement": (
            "MCP-T4 Input / Instruction Boundary Distinction Failure: Prompt-injection screening and context "
            "capsules are recorded in the audit chain, and the capability matrix bounds what an injected "
            "instruction can reach. Poisoned tool descriptions and schemas are not scanned: the supply-chain "
            "scanner covers four code-level attack classes and capability-drift detection hashes tool names "
            "only."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "context.capsule",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t5-data-protection",
        "requirement": (
            "MCP-T5 Inadequate Data Protection and Confidentiality Controls: Log records and persisted traces "
            "are redacted for credential shapes and personal data (email, phone, SSN and card "
            "numbers) before they are written. Where a third-party server stores its own credentials and how "
            "it protects data at rest is outside what Bernstein controls, and no redaction event is written "
            "to the audit chain."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t6-integrity-verification",
        "requirement": (
            "MCP-T6 Missing Integrity / Verification Controls: A third-party server's manifest is verified "
            "(Ed25519 over a JCS-canonical body, trusted-publisher check, optional content hash) before "
            "MCPManager spawns it, and a change in a server's declared tool set is written to the audit chain "
            "as mcp.capability_drift when a capability store and chain are configured. The drift digest "
            "covers tool names only, so a changed description or schema under the same names is not "
            "detected, and the manifest verdict is not chained."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "mcp.capability_drift",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t7-session-transport",
        "requirement": (
            "MCP-T7 Session and Transport Security Failures: The streamable HTTP transport is stateless: it "
            "keeps no per-client session store and issues no session identifier, so there is no session to "
            "fixate or hijack, and each call's place in a run is anchored in the audit chain as "
            "mcp.stateless_call. Clear-text CORS origins are accepted only when pinned to a loopback host. "
            "The transport is an ASGI application; TLS for its listener is provided by the server it is "
            "mounted on, not by Bernstein."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "mcp.stateless_call",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t8-network-isolation",
        "requirement": (
            "MCP-T8 Network Binding / Isolation Failures: The HTTP transport enforces an Origin allow-list "
            "and the MCP-Protocol-Version header (each with a one-release opt-out), refuses a non-loopback "
            "bind without authentication, and the task server binds to 127.0.0.1 unless the operator opts "
            "in to a wider bind. None of these decisions is written to the audit chain."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t9-trust-boundary",
        "requirement": (
            "MCP-T9 Trust Boundary and Privilege Design Failures: The capability matrix refuses "
            "lethal-trifecta combinations and records the refusal; the tool-surface scorer rates a server's "
            "untrusted-input, sensitive-data and egress reach and flags wildcard scopes; the client checks "
            "that a tool is declared in the server's capability card before calling it. Trust between a "
            "third-party server and the services behind it is not modelled."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "capability_matrix_refusal",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t10-resource-limits",
        "requirement": (
            "MCP-T10 Resource Management / Rate-Limiting Absence: Spend against budget is recorded per "
            "server per task, a budget cap transition is written to the audit chain as cost.budget_halt, and "
            "tool-call payload size and nesting are bounded before a handler runs. There is no per-server "
            "call-rate quota or token cap on a third-party server's responses."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "cost.budget_halt",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t11-supply-chain",
        "requirement": (
            "MCP-T11 Supply Chain and Lifecycle Security Failures: MCPManager verifies an Ed25519 manifest "
            "signature, scans the server source for four attack classes and checks a known-bad package list "
            "before spawning a third-party server; enforcement is strict by default for new environments and "
            "warn-only for upgraded ones. These verdicts are not written to the audit chain, and Bernstein "
            "does not yet inventory MCP servers deployed outside its own configuration."
        ),
        "artefact": "n/a",
        "selector": "n/a",
        "status": "partial",
    },
    {
        "control_id": "mcp-threats.t12-audit-logging",
        "requirement": (
            "MCP-T12 Insufficient Logging, Monitoring, and Auditability: Stateless MCP calls and tool-set "
            "changes are written to the audit chain as mcp.stateless_call and mcp.capability_drift, so call "
            "order and drift verify offline. Server connections, authorization decisions, refused inputs and "
            "the signing and scan verdicts are not chained."
        ),
        "artefact": "audit-chain/events.jsonl",
        "selector": "mcp.stateless_call,mcp.capability_drift",
        "status": "partial",
    },
]

#: Controls whose full implementation or signal chaining is deferred.
DEFERRED: list[str] = [
    "human-governed-accountable.dual-control: multi-party quorum signatures and verification are not chained.",
    "bounded-resilient.sandboxing: sandbox execution is enforced at runtime without chained escape events.",
    "bounded-resilient.codeguard: CoSAI CodeGuard rule set preset not yet bundled as a guardrail preset.",
    (
        "transparent-verifiable.replay-reproducibility: step-level replay journal is local to .sdd/runtime/ "
        "rather than audit-chained."
    ),
    "transparent-verifiable.context-integrity: cross-session semantic memory poisoning detection is not yet chained.",
    "mcp-threats.t1-authentication-identity: transport authentication and manifest verdicts are not chained.",
    "mcp-threats.t3-input-validation: refused tool-call inputs and scanner findings are not chained.",
    "mcp-threats.t4-instruction-boundary: tool descriptions and schemas are not scanned for poisoning.",
    "mcp-threats.t5-data-protection: redaction is not chained; data at rest in third-party servers is out of scope.",
    "mcp-threats.t6-integrity-verification: the manifest verdict is not chained; drift hashes tool names only.",
    "mcp-threats.t8-network-isolation: Origin, protocol-version and bind refusals are not chained.",
    "mcp-threats.t10-resource-limits: no per-server call-rate quota or response-size cap for third-party servers.",
    "mcp-threats.t11-supply-chain: signing and scan verdicts are not chained; no inventory of deployed servers.",
    "mcp-threats.t12-audit-logging: server connections, authorization decisions and refusals are not chained.",
]


def control_map() -> dict[str, Any]:
    """Return the CoSAI control-map block in ``_STANDARD_MAPS`` shape.

    The list is copied so a caller mutating the returned dict cannot
    corrupt the module-level catalogue.
    """
    return {
        "regulation": REGULATION,
        "controls": [c.copy() for c in CONTROLS],
        "deferred": DEFERRED.copy(),
    }


__all__ = [
    "CONTROLS",
    "DEFERRED",
    "MCP_PAPER",
    "REGULATION",
    "STANDARD_ID",
    "control_map",
]
