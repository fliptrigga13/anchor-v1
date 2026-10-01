# Anchor Research Dossier: OWASP ACS (Agent Control System) Hardened Guardian Architecture

**Target**: Anchor v1 Guardian Integration (`anchor_v1.acs_guardian`)  
**Standard**: OWASP Agent Control System (ACS) v1.0.0 (Released 2026-09-01)  
**Classification**: P0 Architecture Specification & Security Blueprint  

---

## 1. Executive Summary & Landscape

On September 1, 2026, OWASP released the Agent Control System (ACS) specification. ACS was formulated to address the fragmentation across autonomous agent execution frameworks (LangChain, AutoGen, CrewAI, Hermes, Claude Computer-Use) by standardizing an out-of-process **Guardian** interface. 

The core thesis of ACS is that agents cannot be trusted to self-police within the same process memory space where prompt injections and jailbreaks execute. However, the OWASP reference guardian implementation exhibits fatal architectural vulnerabilities:
1. **Fail-Open Default**: Uncaught exceptions or timeouts in the policy evaluator result in uninspected tool execution.
2. **Missing Wire Authentication**: Guardian RPC endpoints default to unauthenticated HTTP/JSON-RPC, making them vulnerable to SSRF and spoofed interception events.
3. **Stateless Allow/Deny Semantics**: The reference guardian returns boolean decisions (`ALLOW`/`DENY`) rather than unforgeable execution capabilities, leaving the system vulnerable to Time-Of-Check to Time-Of-Use (TOCTOU) exploitation.

**Anchor's Strategic Positioning**: Anchor does not compete with ACS at the protocol layer. Instead, **Anchor positions itself as the world's most hardened, mathematically verified ACS Guardian implementation**. Anchor transforms the loose ACS protocol into a zero-trust, cryptographically enforced pipeline:
$$\text{ACS Event} \longrightarrow \text{ActionEnvelope} \longrightarrow \text{Deterministic Authority} \longrightarrow \text{One-Use Capability} \longrightarrow \text{Isolated PEP} \longrightarrow \text{SCITT Proof}$$

---

## 2. Complete Breakdown of the 19 ACS Lifecycle Interception Hooks

The ACS specification defines 19 distinct lifecycle hooks spanning 4 execution phases. Anchor maps each hook to an internal invariant:

### Phase I: Ingestion & Planning
1. `on_session_start`: Validates agent identity, binds upstream SPIFFE SVID or OIDC identity to an active Mandate.
2. `on_prompt_received`: Scans incoming user/external context for adversarial prompts; records cryptographic content digest in session Merkle tree.
3. `on_context_assemble`: Audits retrieved RAG chunks against data provenance policies (`anchor_v1.provenance`).
4. `on_model_request_pre`: Sanitizes outgoing model payload; strips ambient credentials.
5. `on_model_response_post`: Inspects raw LLM output before parsing; detects jailbreak signatures.

### Phase II: Action & Tool Proposal (The Pre-Execution Gap)
6. `on_tool_call_proposed`: **CRITICAL P0 HOOK**. Intercepts the raw proposed tool name and parameters. Anchor packages this into a canonical `ActionEnvelope` ($H(\text{ActionEnvelope})$) and evaluates against the active `Constitution`.
7. `on_tool_call_prepare`: Executes state-binding read pass. Records `EffectPreview` digest (Git HEAD SHA, HTTP ETag, database row version).
8. `on_capability_mint`: Mints single-use, holder-of-key Ed25519 capability token bound to the specific `action_digest`.
9. `on_approval_stepup_required`: Triggers out-of-band hardware WebAuthn / FIDO2 quorum challenge (`anchor_v1.stepup`) if policy marks action high-impact.
10. `on_tool_call_denied`: Emits signed rejection receipt and records violation to the append-only audit trail.

### Phase III: Execution & Enforcement (PEP Isolation)
11. `on_pep_dispatch`: Delivers capability token to the out-of-process Policy Enforcement Point (PEP).
12. `on_capability_consume`: Atomically validates token signature, checks epoch, verifies nonce is unspent, and marks `CONSUMED` in SQLite/Postgres.
13. `on_tool_execution_pre`: Verifies state binding (checks whether world state has drifted since prepare phase). If state drifted, aborts immediately (`TOCTOU_DRIFT`).
14. `on_tool_execution_post`: Collects connector execution receipt with cryptographically signed outcome attestation.
15. `on_tool_error`: Captures connector faults and prevents error message injection loops.

### Phase IV: Delegation, Memory & Egress
16. `on_subagent_delegation`: Enforces monotonic attenuation: $\text{Scope}_{\text{child}} \subseteq \text{Scope}_{\text{parent}}$. Ensures no subagent can ever hold broader authority than its parent.
17. `on_memory_write`: Prevents ASI06 memory poisoning by signing memory nodes with source provenance tags.
18. `on_network_egress`: Intercepts socket/HTTP connections; ensures all external requests pass through Anchor proxy with capability verification.
19. `on_session_end`: Finalizes session Merkle checkpoint; publishes transparency log receipt (RFC 9943 SCITT).

---

## 3. Anchor's Hardening Architecture vs Reference Guardian

| Dimension | OWASP Reference Guardian | Anchor Hardened Guardian (`anchor_v1.acs_guardian`) |
|---|---|---|
| **Default Stance** | Fail-Open (`ALLOW` on unhandled error) | **Strict Fail-Closed** (`DENY` + panic receipt on any fault) |
| **Transport Security** | Plain HTTP / unauthenticated JSON-RPC | **Mutual TLS (mTLS)** with Ed25519 identity verification |
| **Decision Primitive** | Advisory boolean (`true`/`false`) | **Cryptographic Capability Token** (Ed25519 signed, holder-bound) |
| **State Drifting** | Ignored (Vulnerable to TOCTOU) | **EffectPreview Hash Binding** (Aborts if state changes pre-commit) |
| **Delegation** | Flat token forwarding | **Monotonic Attenuation Chain** (Proof of non-amplification) |
| **Audit Trail** | Ephemeral JSON text logs | **SCITT RFC 9943 Transparency Log** + Merkle Checkpoints |

---

## 4. Implementation Guidance for the Agent Ship

### For Implementer (`implementer`):
- Implement `ACSGuardianInterceptor` in `src/anchor_v1/acs_guardian.py`.
- Wrap every hook in a strict `try ... except Exception as exc` block that immediately executes `self.fail_closed(exc)` and emits a `RejectionReceipt`.

### For Coder (`coder`):
- Implement the canonical serialization bridge between ACS JSON-RPC events and Anchor's `ActionEnvelope`.
- Ensure CBOR/COSE encoding preserves exact type boundaries (integers, strings, byte arrays).

### For Security Auditor (`security-auditor`):
- Construct adversarial test cases simulating:
  1. Network partition during hook evaluation.
  2. Malformed JSON payload with nested prototype pollution.
  3. Replay of legitimate capability tokens across different hook contexts.
