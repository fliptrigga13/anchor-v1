# Anchor Research Dossier: IETF Delegation Standards & Monotonic Attenuation

**Target**: Anchor Delegation & Token Engine (`anchor_v1.attenuated_tokens`, `anchor_v1.delegation_chains`)  
**Standards Convergence**:
- `draft-asor-wimse-agent-delegation-chain` (WIMSE WG, 2026)
- `draft-niyikiza-oauth-attenuating-agent-tokens` (OAuth WG, 2026)
- `draft-embesozzi-intent-agent-native-authorization` (OAuth / RAR, 2026)
**Classification**: P0 Mathematical Invariants & Standards Mapping  

---

## 1. The Core Invariant: Why OAuth Token Exchange (RFC 8693) Fails

RFC 8693 (OAuth 2.0 Token Exchange) is widely deployed for microservice impersonation and delegation. However, in autonomous multi-agent systems, RFC 8693 exhibits a fatal architectural limitation:
> **RFC 8693 provides an audit history of delegation, NOT an unforgeable monotonic authority constraint.**

In RFC 8693, when Agent A exchanges a token to delegate to Agent B, the Authorization Server issues a new token based on server-side policy. If the Authorization Server is compromised, misconfigured, or offline, an intermediary agent can easily request or receive elevated privileges (amplification).

In contrast, Anchor implements the **WIMSE Monotonic Delegation Invariant**:
$$\forall k \ge 1, \quad \text{Authority}(R_k) \subseteq \text{Authority}(R_{k-1})$$
where $R_k$ is the delegation receipt at hop $k$, and the subset relation $\subseteq$ is strictly evaluated across all dimensions:
1. **Action Set**: $\text{Actions}(R_k) \subseteq \text{Actions}(R_{k-1})$. If parent has `['read', 'write']`, child cannot hold `['read', 'write', 'delete']`.
2. **Resource Prefix**: $\text{Prefix}(R_k) \sqsubseteq \text{Prefix}(R_{k-1})$ with boundary-aware canonical prefix matching (preventing `workspace://scope-evil` from matching `workspace://scope`).
3. **Spend Envelope**: $\text{SpendLimit}(R_k) \le \text{SpendLimit}(R_{k-1})$ in identical currency asset.
4. **Temporal Validity**: $[\text{NBF}_k, \text{EXP}_k] \subseteq [\text{NBF}_{k-1}, \text{EXP}_{k-1}]$.
5. **Caveat Inheritance**: $\text{Caveats}(R_{k-1}) \subseteq \text{Caveats}(R_k)$ (caveats can only be added, never dropped).

Every intermediate enforcement point or leaf verifier can evaluate this chain **completely offline** without making network calls to any central authority server.

---

## 2. Standards Cross-Walk Table

| Standard / Draft | Focus Area | Anchor Module | Key Guarantee Enforced |
|---|---|---|---|
| **draft-asor-wimse-agent-delegation-chain** | Hop-by-hop non-amplification proof | `anchor_v1.delegation_chains` | Chain position assertions ($k = \text{depth}$), custody-break rejection, cycle detection |
| **draft-niyikiza-oauth-attenuating-agent-tokens** | Proof-of-Possession capability tokens | `anchor_v1.attenuated_tokens` | Holder-of-key DPoP/Ed25519 signing, single-use nonce tracking, caveat filtering |
| **draft-embesozzi-intent-agent-native-authorization** | Rich Authorization Requests (RAR) | `anchor_v1.envelope` | Canonical ActionEnvelope digest binding to user-authorized intent |
| **RFC 9943 (SCITT)** | Supply chain & execution transparency | `anchor_v1.scitt`, `anchored_checkpoints` | Signed statement issuance, Merkle inclusion receipts, multi-witness consistency |

---

## 3. Delegation Chain Verification Algorithm

Anchor's offline verifier executes the following deterministic checks on chain $\mathcal{C} = [R_0, R_1, \dots, R_n]$:

```python
def verify_delegation_chain(chain: list[DelegationReceipt], trusted_roots: set[str], now: datetime):
    # 1. Root verification
    root = chain[0]
    if root.issuer not in trusted_roots:
        raise DelegationError("Root issuer is not in trusted authority set")
    if root.depth != 0 or root.parent_receipt_hash is not None:
        raise DelegationError("Malformed root receipt")
    
    seen_hashes = {root.content_hash()}
    
    # 2. Inductive step for each hop
    for i in range(1, len(chain)):
        parent = chain[i - 1]
        child = chain[i]
        
        # Custody Check: Child must be signed by the delegatee of parent
        if child.issuer != parent.delegatee:
            raise DelegationError(f"Custody break at hop {i}: signed by {child.issuer}, expected {parent.delegatee}")
        
        # Hash Linkage: Child parent_receipt_hash must match parent content hash
        if child.parent_receipt_hash != parent.content_hash():
            raise DelegationError(f"Broken hash link at hop {i}")
            
        # Cycle Check
        ch_hash = child.content_hash()
        if ch_hash in seen_hashes:
            raise DelegationError(f"Cycle detected at hop {i}")
        seen_hashes.add(ch_hash)
        
        # Depth Monotonicity
        if child.depth != i:
            raise DelegationError(f"Depth claim {child.depth} != position {i}")
            
        # Time Window Invariant
        if not (parent.not_before <= child.not_before and child.expires_at <= parent.expires_at):
            raise DelegationError(f"Temporal window widened at hop {i}")
            
        # Scope Monotonicity
        if not is_subset(child.scope, parent.scope):
            raise DelegationError(f"Authority widened beyond parent at hop {i}")
```

---

## 4. Implementation Guidance for the Agent Ship

### For Plan Architect (`plan-architect`):
- Ensure the TLA+ specification in `tla/authority.tla` formally includes `InvariableDelegationNarrowing` as a temporal property checked across all state steps.

### For Test Writer (`test-writer`):
- Implement property-based fuzz tests (Hypothesis) generating random DAGs of delegation receipts and asserting that any graph with cycles, out-of-order depths, or widened scopes immediately fails closed with `DelegationError`.
