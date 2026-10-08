# CoSAI Principles for Secure-by-Design Agentic Systems evidence pack

`bernstein audit export --standard cosai` maps the CoSAI (Coalition for Secure AI, OASIS Open Project) Principles for Secure-by-Design Agentic Systems and Risk Map controls onto the same HMAC-chained audit events, lineage log, and cost ledger that back the `ai-act`, `owasp-asi`, `owasp-skills`, and `iso-42001` packs. Source: `src/bernstein/compliance/cosai.py`, registered in `src/bernstein/compliance/evidence_pack.py`.

## What this is not

Bernstein cannot certify anybody, and CoSAI guidance does not constitute a formal certification framework. This pack does not claim third-party compliance certification. It provides an operator with per-control evidence derived directly from their own run records, so compliance posture is demonstrated from verifiable execution evidence rather than asserted in spreadsheets.

## Three-state honesty rule

Every mapped control resolves to exactly one of three states. `todo` rows remain explicitly visible in the map so gaps are transparent to operators and auditors.

| Status | Meaning |
|---|---|
| `mapped` | The chain contains records that satisfy the control; the pack cites the concrete artefact and selector. |
| `partial` | The chain covers part of the control; the requirement states what is missing. |
| `todo` | The control is identified in the standard but not currently enforced or chained in Bernstein. |

A map that marked unimplemented controls `mapped` or omitted them entirely would mislead an auditor. Honest accounting is the deliverable.

## Coverage

The control map is organized under the three core principles published by the CoSAI Technical Steering Committee (TSC) in *CoSAI Principles for Secure-by-Design Agentic Systems* ([cosai-oasis/cosai-tsc](https://github.com/cosai-oasis/cosai-tsc), `security-principles-for-agentic-systems.md`). Where the CoSAI Risk Map ([cosai-oasis/secure-ai-tooling](https://github.com/cosai-oasis/secure-ai-tooling), `risk-map/yaml/controls.yaml`) defines a corresponding control, its upstream identifier is listed in the Risk Map ID column; where no direct Risk Map control exists, `n/a` is stated. Sub-clause IDs (e.g. `human-governed-accountable.oversight`) are Bernstein's internal control identifiers mapping against the TSC principles.

### Principle 1: Human-governed and Accountable

Agents operate under human oversight, verified cryptographic identities, and bounded user mandates.

| Control ID | Risk Map ID | Requirement (short) | Implementation module | Exercising test | Artefact | Status |
|---|---|---|---|---|---|---|
| `human-governed-accountable.oversight` | `controlAgentPluginUserControl` | Human approval and user control for sensitive actions | `src/bernstein/core/security/approval.py` | `tests/unit/test_approval.py` | `audit-chain/events.jsonl` | `mapped` |
| `human-governed-accountable.dual-control` | n/a | Multi-party quorum enforcement for critical operations | n/a | n/a | n/a | `todo` |
| `human-governed-accountable.identity` | `controlAgentIntegrityManagement` | Delegation minting is chained; agent card signing is not (no audit event) | `src/bernstein/core/security/agent_card_signer.py` | `tests/unit/test_agent_card_signer.py` | `audit-chain/events.jsonl` | `partial` |
| `human-governed-accountable.mandate` | n/a | Explicit payment mandate and consent tracking | `src/bernstein/core/payments/mandate.py` | `tests/unit/test_payment_mandate_audit_chain.py` | `audit-chain/events.jsonl` | `mapped` |

### Principle 2: Bounded and Resilient

Agency is strictly bounded through capability controls, sandboxing, resource budgets, and supply chain verification.

| Control ID | Risk Map ID | Requirement (short) | Implementation module | Exercising test | Artefact | Status |
|---|---|---|---|---|---|---|
| `bounded-resilient.least-privilege` | `controlAgentPluginPermissions` | Capability matrix bounding plugin permissions against the lethal trifecta | `src/bernstein/core/security/capability_matrix.py` | `tests/unit/test_capability_matrix.py` | `audit-chain/events.jsonl` | `mapped` |
| `bounded-resilient.sandboxing` | n/a | Sandboxed execution environments and command allowlists | `src/bernstein/core/security/command_policy.py` | `tests/unit/test_command_policy.py` | n/a | `partial` |
| `bounded-resilient.resource-bounds` | `controlAgentExecutionBounds` | Recorded spend vs budget | `src/bernstein/core/cost/cost_tracker.py` | `tests/unit/test_budget_killswitch.py` | `costs/cost_history.jsonl` | `mapped` |
| `bounded-resilient.codeguard` | n/a | Automated CoSAI CodeGuard rule set preset | n/a | n/a | n/a | `todo` |

### Principle 3: Transparent and Verifiable

Every execution step, artifact state, and trajectory transition produces tamper-evident, verifiable proof.

| Control ID | Risk Map ID | Requirement (short) | Implementation module | Exercising test | Artefact | Status |
|---|---|---|---|---|---|---|
| `transparent-verifiable.supply-chain` | n/a | Ed25519 signature verification for skill packages | `src/bernstein/core/skills/catalog/signature.py` | `tests/unit/core/skills/test_catalog_verify.py` | `audit-chain/events.jsonl` | `mapped` |
| `transparent-verifiable.audit-trail` | `controlAgentObservability` | RFC 2104 HMAC-chained audit log across all lifecycle events | `src/bernstein/core/security/audit_chain.py` | `tests/unit/test_audit_chain_memory_write.py` | `audit-chain/events.jsonl` | `mapped` |
| `transparent-verifiable.lineage-provenance` | `controlModelAndDataIntegrityManagement` | Content-addressed artifact transparency log with tamper detection | `src/bernstein/core/lineage/store.py` | `tests/unit/lineage/test_store.py` | `lineage/log.jsonl` | `mapped` |
| `transparent-verifiable.replay-reproducibility` | n/a | Trajectory logging in audit chain; step journal local to .sdd/runtime/ | `src/bernstein/core/replay/journal.py` | `tests/unit/core/replay/test_journal_identity.py` | `audit-chain/events.jsonl` | `partial` |
| `transparent-verifiable.context-integrity` | `controlInputValidationAndSanitization` | Input validation and context capsule logging; semantic drift remains partial | `src/bernstein/core/security/owasp_asi_detectors.py` | `tests/unit/test_owasp_asi_detectors.py` | `audit-chain/events.jsonl` | `partial` |

### MCP threat classes

Operators filling in a vendor security questionnaire are usually asked which published MCP threat taxonomy the controls map to. The CoSAI white paper [*Model Context Protocol (MCP) Security*](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) (Workstream 4: Secure Design Patterns for Agentic Systems) defines twelve threat classes, `MCP-T1` to `MCP-T12`. The rows below follow the paper's version `7ec1306f2f55563f6eeef9d36a6bb2b531491ceb`, dated 8 January 2026 and marked *Draft*, announced by OASIS Open on 27 January 2026. The paper's numbering may still change, so each row carries a stable `mcp-threats.tN-...` identifier of Bernstein's own as well as the paper's class name. A later revision of the paper (Version 2.0) has been announced; these rows have not been checked against it.

None of the twelve is `mapped`. The signing and scan gate is enforced by `MCPManager` before a third-party server is spawned, but its verdicts are not written to the audit chain, and neither are transport authentication decisions or refused inputs. A class that depends on one of those is `partial`, and its requirement text says what is missing. Only chain events that production code emits are cited: `mcp.stateless_call`, `mcp.capability_drift`, `cost.budget_halt`, `context.capsule` and `capability_matrix_refusal`. `mcp.task_handle` is deliberately absent, because its recorder has no production caller yet.

| Control ID | Risk Map ID | Requirement (short) | Implementation module | Exercising test | Artefact | Status |
|---|---|---|---|---|---|---|
| `mcp-threats.t1-authentication-identity` | n/a | MCP-T1 Improper Authentication and Identity Management: bearer required off loopback; manifest signature; neither chained | `src/bernstein/mcp/remote_transport.py` | `tests/unit/test_mcp_remote_transport.py` | n/a | `partial` |
| `mcp-threats.t2-access-control` | n/a | MCP-T2 Missing or Improper Access Control: capability matrix refusals chained; no object-level control in third-party servers | `src/bernstein/core/security/capability_matrix.py` | `tests/unit/test_capability_matrix.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t3-input-validation` | n/a | MCP-T3 Input Validation / Sanitization Failures: deny-by-default tool-call schemas; refusals and scanner findings not chained | `src/bernstein/mcp/input_validation.py` | `tests/unit/test_mcp_input_validation.py` | n/a | `partial` |
| `mcp-threats.t4-instruction-boundary` | n/a | MCP-T4 Input / Instruction Boundary Distinction Failure: injection screening chained; tool descriptions not scanned | `src/bernstein/core/security/owasp_asi_detectors.py` | `tests/unit/test_owasp_asi_detectors.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t5-data-protection` | n/a | MCP-T5 Inadequate Data Protection and Confidentiality Controls: log and trace redaction; not chained | `src/bernstein/core/observability/log_redact.py` | `tests/unit/test_log_redact.py` | n/a | `partial` |
| `mcp-threats.t6-integrity-verification` | n/a | MCP-T6 Missing Integrity / Verification Controls: manifest signature; tool-set drift chained by name only | `src/bernstein/core/protocols/mcp/mcp_verifier.py` | `tests/unit/test_mcp_signing.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t7-session-transport` | n/a | MCP-T7 Session and Transport Security Failures: stateless transport, calls anchored in the chain; listener TLS is the host server's | `src/bernstein/mcp/remote_transport.py` | `tests/unit/test_mcp_remote_transport.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t8-network-isolation` | n/a | MCP-T8 Network Binding / Isolation Failures: Origin allow-list, protocol-version check, loopback default; not chained | `src/bernstein/mcp/remote_transport.py` | `tests/unit/test_mcp_remote_hardening.py` | n/a | `partial` |
| `mcp-threats.t9-trust-boundary` | n/a | MCP-T9 Trust Boundary and Privilege Design Failures: capability matrix, tool-surface risk scoring, capability-card check | `src/bernstein/mcp/tool_surface.py` | `tests/unit/mcp/test_tool_surface.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t10-resource-limits` | n/a | MCP-T10 Resource Management / Rate-Limiting Absence: budget halts chained; no per-server rate quota | `src/bernstein/core/cost/spend_ledger.py` | `tests/unit/cost/test_budget_halt_receipt.py` | `audit-chain/events.jsonl` | `partial` |
| `mcp-threats.t11-supply-chain` | n/a | MCP-T11 Supply Chain and Lifecycle Security Failures: signature, scan and denylist before spawn; verdicts not chained, no inventory | `src/bernstein/core/protocols/mcp/mcp_signing_policy.py` | `tests/unit/test_mcp_signing.py` | n/a | `partial` |
| `mcp-threats.t12-audit-logging` | n/a | MCP-T12 Insufficient Logging, Monitoring, and Auditability: stateless calls and drift chained; connections and decisions not | `src/bernstein/core/protocols/mcp/stateless_core.py` | `tests/unit/test_mcp_remote_transport.py` | `audit-chain/events.jsonl` | `partial` |

7 `mapped`, 16 `partial`, 2 `todo` - 25 of 25 controls counted across the three principles and the twelve MCP threat classes.

## Licensing and Attribution

CoSAI Technical Steering Committee documents ([cosai-oasis/cosai-tsc](https://github.com/cosai-oasis/cosai-tsc)) are published under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Principle titles are quoted with attribution to the OASIS Open CoSAI Technical Steering Committee (*CoSAI Principles for Secure-by-Design Agentic Systems*); requirement summaries are paraphrased.

CoSAI Risk Map controls ([cosai-oasis/secure-ai-tooling](https://github.com/cosai-oasis/secure-ai-tooling)) are published under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

The MCP threat-class rows quote only the class titles of the CoSAI white paper *Model Context Protocol (MCP) Security* and paraphrase the rest. That paper is a Non-Standards Track Work Product, and its copyright notice reads:

> Copyright © OASIS Open 2025. All Rights Reserved. This document has been produced under the process and license terms stated in the OASIS Open Project rules: <https://www.oasis-open.org/policies-guidelines/open-projects-process>.
>
> This document and translations of it may be copied and furnished to others, and derivative works that comment on or otherwise explain it or assist in its implementation may be prepared, copied, published, and distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice and this section are included on all such copies and derivative works. The limited permissions granted above are perpetual and will not be revoked by OASIS or its successors or assigns. This document and the information contained herein is provided on an "AS IS" basis and OASIS DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. OASIS AND ITS MEMBERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THIS DOCUMENT OR ANY PART THEREOF. The name "OASIS" is a trademark of OASIS, the owner and developer of this document, and should be used only to refer to the organization and its official outputs. OASIS welcomes reference to, and implementation and use of, documents, while reserving the right to enforce its marks against misleading uses. Please see <https://www.oasis-open.org/policies-guidelines/trademark/> for above guidance.
>
> This is a Non-Standards Track Work Product. The patent provisions of the OASIS IPR Policy do not apply.

## Building a pack

```bash
bernstein audit export --standard cosai --out cosai-evidence.zip
```

Produces the standard deterministic zip bundle (`manifest.json`, `controls.json`, `audit-chain/`, `lineage/`, `costs/`, `README.md`) with `manifest.json` reporting `controls_mapped`, `controls_partial`, and `controls_todo` matching the control map.
