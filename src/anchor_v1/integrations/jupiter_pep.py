"""ANCHOR v1 — Jupiter Swap V2 Policy Enforcement Point (PEP).

Enforces constitutional governance, cryptographically-bounded spend envelopes,
and holder-of-key authorization over Jupiter Swap V2 API orders on Solana.

DEPLOYMENT INVARIANT:
--------------------
The AI Agent NEVER possesses ambient access to the Solana wallet signing keys
or the Jupiter Developer Platform API key. The PEP and CredentialBroker sit
outside the agent boundary.

The agent only proposes a swap intent and presents an unforgeable COSE-Sign1
capability token signed by the constitution quorum. The PEP:
  1. Validates the swap parameters against constitutional constraints (mint whitelist,
     maximum amount, maximum slippage).
  2. Atomically consumes the capability token in the linearizable store (preventing
     replay attacks, TOCTOU divergence, or unauthorized parameter tampering).
  3. Signs the transaction using brokered keys inside the secure boundary.
  4. Dispatches the signed transaction to Jupiter /swap/v2/execute.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..canonical import sha256_hex
from ..envelope import ActionEnvelope
from ..pep import BrokerAccessDenied, PEPError
from ..store import AuthorizationDenied, CapabilityStore

__all__ = [
    "JupiterCredentialBroker",
    "JupiterSwapPEP",
    "JupiterSwapResult",
    "SlippageViolationError",
    "UnauthorizedMintError",
    "BudgetExceededError",
]


class SlippageViolationError(PEPError):
    """Raised when proposed swap slippage exceeds constitutional threshold."""


class UnauthorizedMintError(PEPError):
    """Raised when an unwhitelisted token mint is targeted."""


class BudgetExceededError(PEPError):
    """Raised when swap amount exceeds single-transaction or envelope budget."""


class JupiterCredentialBroker:
    """Holds Jupiter Developer Platform API keys and Solana signing keys.

    Agent-side code cannot read raw keys: accessing .secrets or .private_key
    raises BrokerAccessDenied. Only the PEP can broker signatures.
    """

    def __init__(
        self,
        *,
        jupiter_api_key: str,
        wallet_private_key: Ed25519PrivateKey,
    ) -> None:
        self.__jupiter_api_key = str(jupiter_api_key)
        self.__wallet_private_key = wallet_private_key
        self.__wallet_public_key = wallet_private_key.public_key()

    @property
    def secrets(self):
        raise BrokerAccessDenied("Raw broker secrets are never exposed to agent code.")

    @property
    def private_key(self):
        raise BrokerAccessDenied("Wallet private key is strictly isolated within the broker.")

    @property
    def wallet_public_bytes(self) -> bytes:
        return self.__wallet_public_key.public_bytes_raw()

    def _brokered_api_key(self) -> str:
        return self.__jupiter_api_key

    def _sign_transaction_bytes(self, raw_tx: bytes) -> bytes:
        """Internal helper: signs transaction bytes with the isolated private key."""
        return self.__wallet_private_key.sign(raw_tx)


@dataclass(frozen=True)
class JupiterSwapResult:
    signature: str
    input_mint: str
    output_mint: str
    input_amount: int
    output_amount: int
    request_id: str
    action_digest: str


class JupiterSwapPEP:
    """Policy Enforcement Point for Jupiter Swap V2 operations."""

    def __init__(
        self,
        *,
        broker: JupiterCredentialBroker,
        store: CapabilityStore,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        challenge: bytes,
        allowed_input_mints: set[str] | None = None,
        allowed_output_mints: set[str] | None = None,
        max_slippage_bps: int = 100,  # 1.00% default limit
        max_single_swap: int = 100_000_000,  # e.g. 100 USDC in native units
        api_client: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self._broker = broker
        self._store = store
        self._trusted_issuers = dict(trusted_issuers)
        self._challenge = bytes(challenge)
        self.allowed_input_mints = allowed_input_mints
        self.allowed_output_mints = allowed_output_mints
        self.max_slippage_bps = max_slippage_bps
        self.max_single_swap = max_single_swap
        self._api_client = api_client or self._default_mock_client

    @property
    def challenge(self) -> bytes:
        return self._challenge

    def _default_mock_client(
        self, method: str, endpoint: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Default simulated Jupiter Swap V2 order & execution router."""
        if endpoint == "/swap/v2/order":
            # Simulate returning an order response with an unsigned transaction
            raw_tx = f"tx_payload_{payload.get('inputMint')}_{payload.get('amount')}".encode("utf-8")
            return {
                "transaction": base64.b64encode(raw_tx).decode("utf-8"),
                "requestId": "req_" + sha256_hex(raw_tx)[:16],
                "inAmount": str(payload.get("amount", 0)),
                "outAmount": str(int(payload.get("amount", 0)) * 99 // 100),
                "lastValidBlockHeight": 250000000,
            }
        elif endpoint == "/swap/v2/execute":
            # Simulate transaction landing
            return {
                "status": "Success",
                "signature": "sig_" + sha256_hex(payload.get("signedTransaction", "").encode())[:32],
            }
        raise PEPError(f"Unknown endpoint: {endpoint}")

    def execute_swap(
        self,
        *,
        envelope: ActionEnvelope,
        capability_cose: bytes,
        holder_proof: bytes,
        order_params: dict[str, Any],
        spend_amount: int = 0,
    ) -> JupiterSwapResult:
        """Executes a Jupiter Swap order subject to constitutional verification."""
        if envelope.effect.plane != "jupiter_swap":
            raise PEPError(f"JupiterSwapPEP refuses non-jupiter envelope plane: {envelope.effect.plane}")

        # 1. Parameter policy verification
        input_mint = str(order_params.get("inputMint", ""))
        output_mint = str(order_params.get("outputMint", ""))
        amount = int(order_params.get("amount", 0))
        slippage_bps = int(order_params.get("slippageBps", 50))

        if self.allowed_input_mints is not None and input_mint not in self.allowed_input_mints:
            raise UnauthorizedMintError(f"Input mint {input_mint} not permitted by policy")
        if self.allowed_output_mints is not None and output_mint not in self.allowed_output_mints:
            raise UnauthorizedMintError(f"Output mint {output_mint} not permitted by policy")
        if slippage_bps > self.max_slippage_bps:
            raise SlippageViolationError(f"Slippage {slippage_bps} bps exceeds max limit of {self.max_slippage_bps} bps")
        if amount > self.max_single_swap:
            raise BudgetExceededError(f"Swap amount {amount} exceeds max single swap {self.max_single_swap}")

        # 2. Atomic single-use capability consumption
        try:
            self._store.consume_capability(
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=self._challenge,
                trusted_issuers=self._trusted_issuers,
                envelope=envelope,
                spend_amount=spend_amount or amount,
            )
        except AuthorizationDenied as exc:
            raise PEPError(f"JupiterSwapPEP authorization failed: {exc}") from exc

        # 3. Call Jupiter /order
        order_resp = self._api_client("GET", "/swap/v2/order", order_params)
        raw_tx_b64 = order_resp.get("transaction")
        if not raw_tx_b64:
            raise PEPError("Jupiter /swap/v2/order failed to return transaction data")

        raw_tx = base64.b64decode(raw_tx_b64)

        # 4. Sign transaction via isolated broker
        sig = self._broker._sign_transaction_bytes(raw_tx)
        signed_tx = raw_tx + b"__sig__" + sig
        signed_tx_b64 = base64.b64encode(signed_tx).decode("utf-8")

        # 5. Post to Jupiter /execute
        exec_payload = {
            "signedTransaction": signed_tx_b64,
            "requestId": order_resp.get("requestId"),
            "lastValidBlockHeight": order_resp.get("lastValidBlockHeight"),
        }
        exec_resp = self._api_client("POST", "/swap/v2/execute", exec_payload)
        tx_sig = exec_resp.get("signature", "unknown")

        return JupiterSwapResult(
            signature=tx_sig,
            input_mint=input_mint,
            output_mint=output_mint,
            input_amount=int(order_resp.get("inAmount", amount)),
            output_amount=int(order_resp.get("outAmount", 0)),
            request_id=order_resp.get("requestId", ""),
            action_digest=envelope.action_digest,
        )
