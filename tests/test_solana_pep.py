"""Tests for ANCHOR v1 Solana Instruction PEP integration."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from anchor_v1 import authority
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.integrations.solana_pep import (
    COMPUTE_BUDGET_PROGRAM_ID,
    STANDARD_SOLANA_PROGRAM_IDS,
    SYSTEM_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    BudgetExceededError,
    InstructionValidationError,
    SolanaCredentialBroker,
    SolanaExecutionResult,
    SolanaInstruction,
    SolanaInstructionPEP,
    UnauthorizedProgramError,
    UnauthorizedRecipientError,
)
from anchor_v1.pep import BrokerAccessDenied, PEPError
from anchor_v1.store import CapabilityStore, DoubleSpendError

VALID_RECIPIENT_1 = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
VALID_RECIPIENT_2 = "GvDMxPzN1sCj7L26YDK2HnMRXEQmQ2aemov8YBtPS7vR"
ROGUE_RECIPIENT = "BadActorDrainAddress11111111111111111111111"
ROGUE_PROGRAM = "MaliciousDeFiContract11111111111111111111111"
CONSTITUTION_HASH = "solana-constitutional-governance-hash-v1"


@pytest.fixture
def keys():
    issuer = Ed25519Signer.generate("solana-issuer")
    holder = Ed25519Signer.generate("solana-holder")
    wallet = Ed25519PrivateKey.generate()
    return issuer, holder, wallet


@pytest.fixture
def setup_solana_pep(keys):
    issuer, holder, wallet = keys
    broker = SolanaCredentialBroker(
        wallet_private_key=wallet,
        rpc_url="https://api.mainnet-beta.solana.com",
    )
    store = CapabilityStore()
    now_ts = datetime.now(timezone.utc).timestamp()
    store.sync_revocations([], now=now_ts)
    challenge = secrets.token_bytes(32)
    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    pep = SolanaInstructionPEP(
        broker=broker,
        store=store,
        trusted_issuers=trusted,
        challenge=challenge,
        allowed_program_ids=set(STANDARD_SOLANA_PROGRAM_IDS),
        allowed_recipients={VALID_RECIPIENT_1, VALID_RECIPIENT_2},
        max_lamports_per_tx=1_000_000_000,  # 1.0 SOL max
    )
    return pep, store, issuer, holder, broker, challenge


def make_solana_envelope(holder, instructions, now, plane="solana_instruction"):
    inst_summary = [
        {"program_id": i.program_id, "recipient": i.recipient, "lamports": i.lamports}
        for i in instructions
    ]
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=holder.public_key_b64(),
        effect=Effect(
            plane=plane,
            verb="execute",
            target="Solana_Runtime_V1",
            args_digest=sha256_hex(inst_summary),
        ),
        policy_ref=CONSTITUTION_HASH,
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(seconds=300),
        nonce=secrets.token_hex(16),
    )


def test_credential_broker_isolation(keys):
    _, _, wallet = keys
    broker = SolanaCredentialBroker(wallet_private_key=wallet)

    with pytest.raises(BrokerAccessDenied):
        _ = broker.secrets

    with pytest.raises(BrokerAccessDenied):
        _ = broker.private_key

    assert len(broker.wallet_public_bytes) == 32
    assert len(broker.wallet_pubkey_base58) >= 32


def test_successful_solana_transfer_execution(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    instructions = [
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=VALID_RECIPIENT_1,
            lamports=500_000_000,  # 0.5 SOL
            instruction_type="transfer",
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    result = pep.execute_transaction(
        envelope=envelope,
        capability_cose=cap_cose,
        holder_proof=proof,
        instructions=instructions,
        spend_amount=500_000_000,
    )

    assert result.signature.startswith("sig_")
    assert result.total_lamports == 500_000_000
    assert result.instruction_count == 1
    assert result.program_ids == (SYSTEM_PROGRAM_ID,)
    assert result.action_digest == envelope.action_digest
    assert len(result.scitt_receipt_digest) == 64
    assert store.capability_state(payload.capability_id) == "CONSUMED"


def test_double_spend_replay_rejected(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    instructions = [
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=VALID_RECIPIENT_1,
            lamports=200_000_000,
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    # First execution succeeds
    pep.execute_transaction(
        envelope=envelope,
        capability_cose=cap_cose,
        holder_proof=proof,
        instructions=instructions,
    )

    # Replay attack fails closed
    with pytest.raises(PEPError) as exc:
        pep.execute_transaction(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            instructions=instructions,
        )
    assert "already consumed" in str(exc.value) or "authorization failed" in str(exc.value)


def test_unauthorized_program_id_rejected_before_consumption(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    # Rogue DeFi contract invocation
    instructions = [
        SolanaInstruction(
            program_id=ROGUE_PROGRAM,
            recipient=VALID_RECIPIENT_1,
            lamports=100_000,
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    with pytest.raises(UnauthorizedProgramError):
        pep.execute_transaction(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            instructions=instructions,
        )

    # Capability must remain unconsumed
    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_unauthorized_recipient_rejected_before_consumption(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    # Attacker tries to transfer to unauthorized drain address
    instructions = [
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=ROGUE_RECIPIENT,
            lamports=100_000,
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    with pytest.raises(UnauthorizedRecipientError):
        pep.execute_transaction(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            instructions=instructions,
        )

    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_budget_exceeded_rejected(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    # 1.5 SOL exceeds 1.0 SOL limit
    instructions = [
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=VALID_RECIPIENT_1,
            lamports=1_500_000_000,
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=2_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    with pytest.raises(BudgetExceededError):
        pep.execute_transaction(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            instructions=instructions,
        )

    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_multi_instruction_transaction_success(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    # Multi-instruction tx: Set Compute Budget limit + System Program Transfer
    instructions = [
        SolanaInstruction(
            program_id=COMPUTE_BUDGET_PROGRAM_ID,
            data=b"\x02\x00\x00\x00\x00\x00\x00\x00",
            instruction_type="compute_budget",
        ),
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=VALID_RECIPIENT_2,
            lamports=300_000_000,
            instruction_type="transfer",
        ),
    ]
    envelope = make_solana_envelope(holder, instructions, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    result = pep.execute_transaction(
        envelope=envelope,
        capability_cose=cap_cose,
        holder_proof=proof,
        instructions=instructions,
    )

    assert result.instruction_count == 2
    assert COMPUTE_BUDGET_PROGRAM_ID in result.program_ids
    assert SYSTEM_PROGRAM_ID in result.program_ids
    assert result.total_lamports == 300_000_000


def test_invalid_plane_rejected(setup_solana_pep):
    pep, store, issuer, holder, _, challenge = setup_solana_pep
    now = datetime.now(timezone.utc)

    instructions = [
        SolanaInstruction(
            program_id=SYSTEM_PROGRAM_ID,
            recipient=VALID_RECIPIENT_1,
            lamports=100_000,
        )
    ]
    envelope = make_solana_envelope(holder, instructions, now, plane="invalid_plane")

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=1_000_000_000,
        ttl=timedelta(seconds=300),
        now=now,
    )

    trusted = {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    payload = authority.verify_capability(cap_cose, trusted, now=now)
    store.register_capability(payload)
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)

    with pytest.raises(PEPError) as exc:
        pep.execute_transaction(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            instructions=instructions,
        )
    assert "refuses invalid plane" in str(exc.value)
