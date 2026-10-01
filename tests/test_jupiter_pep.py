"""Tests for ANCHOR v1 Jupiter Swap V2 PEP integration."""

from __future__ import annotations

import base64
import os
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
from anchor_v1.integrations.jupiter_pep import (
    BudgetExceededError,
    JupiterCredentialBroker,
    JupiterSwapPEP,
    PEPError,
    SlippageViolationError,
    UnauthorizedMintError,
)
from anchor_v1.pep import BrokerAccessDenied
from anchor_v1.store import CapabilityStore, DoubleSpendError

MINT_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
MINT_SOL = "So11111111111111111111111111111111111111112"
MINT_MALICIOUS = "BadTokenMint1111111111111111111111111111111"
CONSTITUTION_HASH = "test-jupiter-constitution-hash"


@pytest.fixture
def keys():
    issuer = Ed25519Signer.generate("jupiter-issuer")
    holder = Ed25519Signer.generate("jupiter-holder")
    wallet = Ed25519PrivateKey.generate()
    return issuer, holder, wallet


@pytest.fixture
def setup_pep(keys):
    issuer, holder, wallet = keys
    broker = JupiterCredentialBroker(
        jupiter_api_key="jup_test_key_xyz",
        wallet_private_key=wallet,
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
    pep = JupiterSwapPEP(
        broker=broker,
        store=store,
        trusted_issuers=trusted,
        challenge=challenge,
        allowed_input_mints={MINT_SOL, MINT_USDC},
        allowed_output_mints={MINT_SOL, MINT_USDC},
        max_slippage_bps=50,
        max_single_swap=10_000_000,
    )
    return pep, store, issuer, holder, broker, challenge


def make_jupiter_envelope(holder, params, now):
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=holder.public_key_b64(),
        effect=Effect(
            plane="jupiter_swap",
            verb="swap",
            target="Jupiter_Swap_V2",
            args_digest=sha256_hex(params),
        ),
        policy_ref=CONSTITUTION_HASH,
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(seconds=300),
        nonce=secrets.token_hex(16),
    )


def test_credential_broker_isolation(keys):
    _, _, wallet = keys
    broker = JupiterCredentialBroker(
        jupiter_api_key="jup_secret_key",
        wallet_private_key=wallet,
    )
    with pytest.raises(BrokerAccessDenied):
        _ = broker.secrets

    with pytest.raises(BrokerAccessDenied):
        _ = broker.private_key

    # Public wallet bytes are accessible
    assert len(broker.wallet_public_bytes) == 32


def test_successful_jupiter_swap_execution(setup_pep):
    pep, store, issuer, holder, _, challenge = setup_pep
    now = datetime.now(timezone.utc)

    order_params = {
        "inputMint": MINT_USDC,
        "outputMint": MINT_SOL,
        "amount": 1_000_000,
        "slippageBps": 30,
    }
    envelope = make_jupiter_envelope(holder, order_params, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=10_000_000,
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

    result = pep.execute_swap(
        envelope=envelope,
        capability_cose=cap_cose,
        holder_proof=proof,
        order_params=order_params,
        spend_amount=1_000_000,
    )

    assert result.signature.startswith("sig_")
    assert result.input_mint == MINT_USDC
    assert result.output_mint == MINT_SOL
    assert result.input_amount == 1_000_000
    assert result.action_digest == envelope.action_digest


def test_double_spend_replay_rejected(setup_pep):
    pep, store, issuer, holder, _, challenge = setup_pep
    now = datetime.now(timezone.utc)

    order_params = {
        "inputMint": MINT_USDC,
        "outputMint": MINT_SOL,
        "amount": 500_000,
        "slippageBps": 20,
    }
    envelope = make_jupiter_envelope(holder, order_params, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=10_000_000,
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
    pep.execute_swap(
        envelope=envelope,
        capability_cose=cap_cose,
        holder_proof=proof,
        order_params=order_params,
    )

    # Second execution must fail closed (DoubleSpendError)
    with pytest.raises(PEPError) as exc:
        pep.execute_swap(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            order_params=order_params,
        )
    assert "already consumed" in str(exc.value) or "authorization failed" in str(exc.value)


def test_unauthorized_mint_rejected_before_consumption(setup_pep):
    pep, store, issuer, holder, _, challenge = setup_pep
    now = datetime.now(timezone.utc)

    order_params = {
        "inputMint": MINT_MALICIOUS,
        "outputMint": MINT_SOL,
        "amount": 100_000,
        "slippageBps": 20,
    }
    envelope = make_jupiter_envelope(holder, order_params, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=10_000_000,
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

    with pytest.raises(UnauthorizedMintError):
        pep.execute_swap(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            order_params=order_params,
        )

    # Ensure capability was NOT consumed
    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_excessive_slippage_rejected(setup_pep):
    pep, store, issuer, holder, _, challenge = setup_pep
    now = datetime.now(timezone.utc)

    # Proposed slippage is 150 bps; max allowed is 50 bps
    order_params = {
        "inputMint": MINT_USDC,
        "outputMint": MINT_SOL,
        "amount": 100_000,
        "slippageBps": 150,
    }
    envelope = make_jupiter_envelope(holder, order_params, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=10_000_000,
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

    with pytest.raises(SlippageViolationError):
        pep.execute_swap(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            order_params=order_params,
        )

    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_budget_exceeded_rejected(setup_pep):
    pep, store, issuer, holder, _, challenge = setup_pep
    now = datetime.now(timezone.utc)

    # 50,000,000 exceeds max_single_swap of 10,000,000
    order_params = {
        "inputMint": MINT_USDC,
        "outputMint": MINT_SOL,
        "amount": 50_000_000,
        "slippageBps": 20,
    }
    envelope = make_jupiter_envelope(holder, order_params, now)

    cap_cose = authority.issue_execution(
        issuer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=10_000_000,
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
        pep.execute_swap(
            envelope=envelope,
            capability_cose=cap_cose,
            holder_proof=proof,
            order_params=order_params,
        )

    assert store.capability_state(payload.capability_id) == "ISSUED"
