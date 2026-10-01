# Anchor Research Dossier: State-Bound Prepare/Commit & TOCTOU Elimination

**Target**: Anchor State Binding & Verification Engine (`anchor_v1.state_binding`, `anchor_v1.pep`)  
**Threat Focus**: Time-of-Check to Time-of-Use (TOCTOU) Race Conditions & World State Drifting  
**Classification**: P0 Security Engineering Specification  

---

## 1. The Threat: The Pre-Execution Drift Gap

In autonomous AI systems, an authorization decision is typically made at time $t_0$ based on an observation of the world state $S(t_0)$. Execution of the action occurs at time $t_1 = t_0 + \Delta t$.

In real-world environments, $\Delta t$ can range from milliseconds (network latency, model inference) to hours (human-in-the-loop approval, out-of-band quorum). During this window, an adversary or concurrent process can alter the underlying target state:
1. **Git Repository Branch Manipulation**: An agent requests approval to merge a PR targeting base commit `abc1234`. Between approval and merge, a malicious commit is pushed to the base branch. The approved diff now introduces a backdoor.
2. **HTTP State Mutation**: An agent receives a capability to update a customer profile where `ETag = "v1"`. A concurrent process updates the record to `ETag = "v2"`. The write clobbers confidential records.
3. **Database Race Condition**: An agent is granted permission to deduct \$50 from an account with balance \$60. Another thread deducts \$40 in parallel. The second deduction creates an overdraft.

---

## 2. Anchor's Solution: EffectPreview State Digests

Anchor eliminates TOCTOU by introducing **State-Bound Prepare/Commit**:
Every capability minted by Anchor does not merely bind to the target action arguments; **it binds cryptographically to the exact prerequisite world state**.

### 2.1 The Two-Phase Prepare/Commit Protocol

```
Agent Proposes Action
         │
         ▼
[Phase 1: Prepare]
Read prerequisite state keys: K_read
Compute State Digest: D_state = H(sort({ k: V(k) for k in K_read }))
Compute EffectPreview Digest: D_preview = H(ActionDigest || D_state || H(PlannedWrites))
Mint Capability: Cap = Sign_Issuer(D_preview || Exp || Nonce || HolderKey)
         │
         ▼ (Arbitrary time delay, human approval, queuing)
         │
[Phase 2: Commit / PEP Execution]
PEP re-reads keys K_read from target system
Verify Current State Digest: D_current == D_state
  ├── If MATCH: Atomically execute PlannedWrites and mark Cap CONSUMED
  └── If MISMATCH: ABORT IMMEDIATELY with TOCTOU_DRIFT rejection
```

### 2.2 Mathematical Invariants

1. **State Completeness**: The read set $K_{\text{read}}$ MUST be a superset of all keys affected by the planned writes:
   $$K_{\text{writes}} \subseteq K_{\text{read}}$$
2. **State Invariance**: If $S(t_1)[K_{\text{read}}] \ne S(t_0)[K_{\text{read}}]$, the capability token is cryptographically invalid for execution.
3. **Atomic Consumption**: State verification and capability consumption MUST execute within a single linearizable transaction.

---

## 3. Connector Implementations

### Git Connector:
- `K_read`: `["git:base_head_sha", "git:tree_hash"]`
- `EffectPreview`: Binds to the exact Git commit SHA and tree hash. If any push occurs on the target branch while approval is pending, the capability fails to execute.

### HTTP REST Connector:
- `K_read`: `["http:etag", "http:last_modified"]`
- `EffectPreview`: Binds to the HTTP `ETag` and content hash. The PEP injects `If-Match: <etag>` on the outgoing HTTP request.

### File System PEP:
- `K_read`: `["fs:path:mtime", "fs:path:size", "fs:path:sha256"]`
- PEP validates the file has not been touched by an external process before applying edits.

---

## 4. Implementation Guidance for the Agent Ship

### For Coder (`coder`):
- Audit `src/anchor_v1/state_binding.py` to ensure `read_state_digest` uses canonical JSON/CBOR sorting for all key-value mappings.
- Implement the `If-Match` header injection logic in the HTTP PEP adapter (`anchor_v1.pep`).

### For Security Auditor (`security-auditor`):
- Run attack scenario `TestTOCTOU::test_state_change_between_prepare_and_commit_denies`.
- Ensure tests verify that modifying an *unrelated* key inside the bound read-set still triggers fail-closed denial.
