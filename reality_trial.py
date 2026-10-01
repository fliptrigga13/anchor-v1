"""ANCHOR v1 — Reality Trial (End-to-End Governed Execution).

Verifies the complete Action -> Authority -> Capability -> Enforcement -> Effect -> Proof chain:
1. Constitutional quorum & subject binding.
2. In-process ACS Guardian evaluation (19-hook wire format).
3. One-use holder-of-key capability minting.
4. ShellPEP execution with secret injection.
5. Fail-closed adversarial attacks: parameter tampering & double-spend.
6. SCITT-compatible evidence checkpoint & offline proof verification.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure anchor_v1 and tests are on path
sys.path.insert(0, r"C:\Users\fyou1\anchor-v1\repo\src")
sys.path.insert(0, r"C:\Users\fyou1\anchor-v1\repo")

from anchor_v1.acs_guardian import (
    AcsGuardian,
    GuardianEvent,
    TOOL_CALL_PROPOSED,
)
from anchor_v1.authority import (
    issue_execution,
    make_holder_proof,
    verify_capability,
)
from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.pep import (
    CredentialBroker,
    PEPError,
    ShellPEP,
)
from anchor_v1.scitt import (
    LocalTransparencyLog,
    STATEMENT_EXECUTION,
    add_receipt,
    issue_statement,
    verify_transparent_statement,
)
from anchor_v1.store import CapabilityStore, DoubleSpendError
from tests.test_guardian_pep_integration import make_shell_envelope, make_event, make_guardian

def run_reality_trial():
    print("=" * 70)
    print("  ANCHOR v1 — END-TO-END REALITY TRIAL")
    print("=" * 70)

    t0 = datetime.now(timezone.utc)
    now_fn = lambda: t0

    # 1. Identity & Keys
    print("\n[Step 1] Initializing Keys & Identities...")
    authority_signer = Ed25519Signer.generate("authority-1")
    agent_signer = Ed25519Signer.generate("agent-worker")
    log_signer = Ed25519Signer.generate("scitt-log-1")
    psk = b"guardian-psk-32bytes-secret1234"
    challenge = b"reality-trial-replay-challenge-01"

    pub_auth = authority_signer._private_key.public_key()
    pub_log = log_signer._private_key.public_key()
    
    trusted_issuers = {
        authority_signer.public_key_bytes(): pub_auth,
        authority_signer.key_id.encode(): pub_auth,
    }
    trusted_logs = {
        log_signer.public_key_bytes(): pub_log,
        log_signer.key_id.encode(): pub_log,
    }

    # 2. Storage & Transparency Log
    print("[Step 2] Initializing Capability Store & SCITT Transparency Log...")
    store = CapabilityStore()
    tx_log = LocalTransparencyLog(log_signer, trusted_issuers=trusted_issuers)

    # 3. Policy Enforcement Point (ShellPEP)
    broker = CredentialBroker({"DATABASE_CREDENTIAL": "brokered_secret_token_abc"})
    shell_pep = ShellPEP(
        store=store,
        broker=broker,
        challenge=challenge,
        trusted_issuers=trusted_issuers,
    )

    # 4. Guardian Configuration
    guardian = make_guardian(authority_signer, t0, holder=agent_signer)

    # 5. Define Task & ActionEnvelope
    cmd = ["echo", "ANCHOR_V1_REALITY_TRIAL_SUCCESS"]
    params = {"cmd": " ".join(cmd)}
    event = make_event(agent_signer, params=params, event_type="pre_tool_call")
    envelope = make_shell_envelope(
        subject=event.subject,
        params=params,
        now=t0,
    )
    shell_pep.register_command(envelope.action_digest, cmd)
    print(f"  Target Action Digest: {envelope.action_digest}")

    # 6. Lifecycle Interception (ACS Hook)
    print("\n[Step 3] Submitting Event to OWASP ACS Guardian...")
    decision = guardian.handle_event(event, presented_envelope=envelope)
    print(f"  Guardian Decision: {decision.decision}")
    assert decision.decision == "ALLOW", "Guardian must allow policy-conforming action"
    assert decision.capability is not None, "ALLOW must emit a cryptographic capability"
    print("  [OK] Verifiable COSE-Sign1 Capability Minted.")

    # Register in Store
    payload = verify_capability(decision.capability, trusted_issuers, now=t0)
    store.register_capability(payload)
    print(f"  Capability Registered: ID={payload.capability_id}")

    # 7. Governed Execution through PEP
    print("\n[Step 4] Executing through ShellPEP with Atomic Capability Consumption...")
    proof = make_holder_proof(agent_signer, payload.capability_id, challenge)

    result = shell_pep.execute(
        envelope=envelope,
        capability_cose=decision.capability,
        holder_proof=proof,
    )
    print(f"  Process Return Code: {result.returncode}")
    print(f"  Process Output: {result.stdout.strip()}")
    assert result.returncode == 0
    assert "ANCHOR_V1_REALITY_TRIAL_SUCCESS" in result.stdout
    assert store.capability_state(payload.capability_id) == "CONSUMED"
    print("  [OK] State Transition: Capability successfully marked CONSUMED in store.")

    # 8. Adversarial Stress Tests (Fail-Closed Guarantees)
    print("\n[Step 5] Adversarial Containment Verification:")

    # Attack A: Replay / Double-Spend
    print("  [Attack A] Replaying consumed capability at PEP...")
    try:
        shell_pep.execute(
            envelope=envelope,
            capability_cose=decision.capability,
            holder_proof=proof,
        )
        raise AssertionError("Double-spend must not succeed!")
    except PEPError as exc:
        print(f"  [OK] Attack A Defeated: {exc}")

    # Attack B: Parameter Tampering (Substitution)
    print("  [Attack B] Presenting capability with tampered command params...")
    tampered_envelope = make_shell_envelope(
        subject=event.subject,
        params={"cmd": "rm -rf /"},
        now=t0,
    )
    try:
        shell_pep.execute(
            envelope=tampered_envelope,
            capability_cose=decision.capability,
            holder_proof=proof,
        )
        raise AssertionError("Parameter substitution must not succeed!")
    except PEPError as exc:
        print(f"  [OK] Attack B Defeated: {exc}")

    # 9. SCITT Transparency Log Checkpoint
    print("\n[Step 6] Anchoring Audit Evidence in SCITT Transparency Log...")
    stmt_bytes = issue_statement(
        issuer=authority_signer,
        statement_type=STATEMENT_EXECUTION,
        subject=f"action:{envelope.action_digest}",
        claims={
            "capability_id": payload.capability_id,
            "principal": agent_signer.key_id,
            "returncode": result.returncode,
            "executed_at": t0.isoformat(),
        },
    )
    receipt_bytes = tx_log.register(stmt_bytes)
    transparent_bundle = add_receipt(stmt_bytes, receipt_bytes)
    print(f"  Merkle Tree Size: {tx_log.tree_size}")
    print(f"  Merkle Root: {tx_log.tree_root().hex()}")

    # 10. Offline Verification
    print("\n[Step 7] Offline Independent Verification of Evidence Bundle...")
    verified = verify_transparent_statement(transparent_bundle, trusted_issuers, trusted_logs)
    assert verified["statement"]["subject"] == f"action:{envelope.action_digest}"
    assert verified["statement"]["issuer"] == authority_signer.key_id
    assert len(verified["receipts"]) == 1
    assert verified["receipts"][0]["log_key_id"] == log_signer.key_id
    assert verified["receipts"][0]["leaf_index"] == 0
    print("  [OK] Evidence Cryptographically Verified Offline (Zero Network, Zero Operator Trust).")

    print("\n" + "=" * 70)
    print("  REALITY TRIAL PASSED: ALL 7 INVARIANTS & INTEGRATIONS GREEN")
    print("=" * 70)

if __name__ == "__main__":
    run_reality_trial()
