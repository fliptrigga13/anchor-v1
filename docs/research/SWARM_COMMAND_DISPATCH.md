# Anchor v1: Swarm Command Dispatch Directive

**Command Authority**: Pair Programming Lead on behalf of Lauren Flipo  
**Swarm Platform**: Hermes Agent Framework (`C:\Users\fyou1\AppData\Local\hermes\profiles`)  
**Mission Objective**: Drive Anchor v1 (`C:\Users\fyou1\anchor-v1\repo`) through remaining release gates and Wave B/C milestones with zero regressions.  

---

## 1. Fleet Role Allocations & Ownership Lanes

Per Rule 6 ("One owner per artifact: Don't rewrite or clobber files another agent owns"), work lanes are strictly segregated:

```
                          ┌──────────────────────────┐
                          │         LEADER           │
                          │   (Fleet Coordinator)    │
                          └─────────────┬────────────┘
                                        │
           ┌────────────────────────────┼───────────────────────────┐
           ▼                            ▼                           ▼
┌────────────────────┐       ┌────────────────────┐      ┌────────────────────┐
│   PLAN-ARCHITECT   │       │     RESEARCHER     │      │  SECURITY-AUDITOR  │
│  TLA+ & Formal Spec│       │ Standards & ACS    │      │ Adversarial Matrix │
│  (tla/, docs/SPEC) │       │ (docs/research/)   │      │ (adversarial_*.py) │
└──────────┬─────────┘       └──────────┬─────────┘      └──────────┬─────────┘
           │                            │                           │
           └────────────────────────────┼───────────────────────────┘
                                        │
           ┌────────────────────────────┴───────────────────────────┐
           ▼                                                        ▼
┌────────────────────┐                                   ┌────────────────────┐
│       CODER        │                                   │    IMPLEMENTER     │
│ Core Protocols     │                                   │ PEP Gateways &     │
│ (cbor, cose, env)  │                                   │ Wire Integrations  │
└──────────┬─────────┘                                   └──────────┬─────────┘
           │                                                        │
           └────────────────────────────┬───────────────────────────┘
                                        │
           ┌────────────────────────────┴───────────────────────────┐
           ▼                                                        ▼
┌────────────────────┐                                   ┌────────────────────┐
│      REVIEWER      │                                   │    TEST-WRITER     │
│ Integrity Audits   │                                   │ Property-Based &   │
│ & Invariant Gates  │                                   │ Conformance Suites │
└────────────────────┘                                   └────────────────────┘
```

---

## 2. Agent Battle Orders & Deliverables

### 1. `leader` (Fleet Coordinator)
- **Role**: Command the ship, synthesize sub-deliverables, verify quality gates.
- **Mandate**:
  - Track overall release blocker burndown:
    - [x] Rust/WASM offline verifier integrated (PR #2 merged)
    - [x] Small TLA+ model checked (11.2M states, 0 violations)
    - [x] Wave A adversarial harness passing (100% pass)
    - [ ] Complete OWASP ACS Guardian hook matrix (19 hooks)
    - [ ] Native MCP 2026-07-28 proxy gateway
    - [ ] Full 3-id TLA+ model symmetry reduction
  - Maintain the release receipt manifest.

### 2. `plan-architect` (Formal Methods & Architecture)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\tla\`, `docs\SPEC.md`
- **Immediate Task**:
  - Implement symmetry reduction for the 3-identity TLA+ model (`tla/authority.tla` / `tla/authority.cfg`) to reduce state-space from 60M+ down to verifiable bounds.
  - Formally verify that Invariant `I4_NonAmplication` holds across arbitrary depth delegation.

### 3. `researcher` (Standards Intelligence)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\docs\research\`
- **Immediate Task**:
  - Ingest the 3 research dossiers (`RESEARCH_OWASP_ACS_GUARDIAN.md`, `RESEARCH_DELEGATION_AND_IETF_STANDARDS.md`, `RESEARCH_TOCTOU_STATE_BINDING.md`).
  - Monitor IETF WIMSE and OAuth Working Group mailing lists for updates to `draft-asor-wimse-agent-delegation-chain`.

### 4. `coder` (Core Authority Implementation)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\src\anchor_v1\envelope.py`, `cbor.py`, `cose.py`
- **Immediate Task**:
  - Ensure canonical CBOR sorting strictly adheres to RFC 8949 §4.2.1 (deterministic key ordering).
  - Ensure COSE signatures (`cose.py`) use strict protected headers without ambiguous unprotected payload tampering.

### 5. `implementer` (Gateways & Enforcement)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\src\anchor_v1\acs_guardian.py`, `mcp_gateway.py`, `pep.py`
- **Immediate Task**:
  - Ensure all 19 OWASP ACS lifecycle hooks fail-closed under any unhandled exception.
  - Implement stdio and SSE transport interception for the native MCP gateway.

### 6. `security-auditor` (Adversarial Adversary)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\adversarial_harness.py`
- **Immediate Task**:
  - Expand `adversarial_harness.py` to cover Wave B and C capabilities:
    - Attack ACS Guardian fail-open bypass attempts.
    - Attack TOCTOU state binding with microsecond racing threads.
    - Attack WebAuthn signature replay across different action digests.
  - Require ≥95% pass rate and 0 unadjudicated failures.

### 7. `reviewer` (Quality & Invariant Inspector)
- **Primary Lane**: Code reviews across all PRs.
- **Immediate Task**:
  - Verify every code commit preserves:
    - Zero network calls in verifier paths.
    - Constant-time cryptographic comparison (`hmac.compare_digest`).
    - Exact type assertions on all parsed inputs.

### 8. `test-writer` (Conformance & Quality Assurance)
- **Primary Lane**: `C:\Users\fyou1\anchor-v1\repo\tests\`
- **Immediate Task**:
  - Maintain 100% green test suite across all 1,050 tests.
  - Add Hypothesis fuzzing tests for `state_binding.py` and `attenuated_tokens.py`.

---

## 3. Execution Commands

To execute and dispatch tasks across the profiles:
```bash
# Run tests under active environment
cd C:\Users\fyou1\anchor-v1\repo
.venv\Scripts\python -m pytest

# Run adversarial verification
.venv\Scripts\python adversarial_harness.py

# Launch swarm coordination via Hermes Kanban
hermes kanban swarm "Complete Anchor v1 release blockers with hardened ACS Guardian and MCP PEP" \
  --worker implementer:harden-acs-hooks \
  --worker coder:canonical-cbor-invariants \
  --worker test-writer:expand-hypothesis-fuzzing \
  --verifier security-auditor \
  --synthesizer leader
```
