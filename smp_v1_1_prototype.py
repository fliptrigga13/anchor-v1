#!/usr/bin/env python3
"""ANCHOR v1.1 Seam Mapping Provider — reference prototype (R2-R11 conformant).

Builder's executable answer to the v1.1 SMP conformance target: the normative
draft (~/workspace/boardroom/hidden_files/v11r-normative-draft.md, binding
authority per R1) as amended by parent rulings R2-R11, consolidated in
~/workspace/boardroom/hidden_files/v1.1-smp-revised-spec.md.

REAL modules, zero mocks, zero edits to src/anchor_v1/ (lives outside the
kernel, in the deployment shim).

What it proves, by running code:
  R2  - anchor: URI grammar: lowercase-only, namespace [a-z][a-z0-9-]{0,31},
        1-32 chars; name segments [a-z0-9._-], 1-64 chars; total <= 256
        octets; namespaces {shell, acs} ONLY (no anchor:http in v1.1).
  R3  - injectivity: two entries mapping to the same (plane, presented_verb)
        -> registry load REFUSES, naming both colliding entries.
  R4  - signed registry: {payload, signature{key_id, alg=EdDSA, sig,
        payload_hash_sha256}}; Ed25519 over canonical JSON bytes; pin record
        {registry_version, payload_hash_sha256, owner_key_id}; any startup
        verification failure -> adapter refuses to start.
  R5  - runtime integrity: canonical payload bytes retained; SHA-256
        re-computed before EVERY translation; mismatch -> adapter latches
        dead, refuses ALL translations until restart, emits SCITT
        registry_compromise statement. v11e (S2): parsed entries are also
        re-derived from the retained canonical bytes and compared
        field-by-field against the live entry objects, so a privileged
        in-process mutation (object.__setattr__/ctypes) that leaves the
        bytes intact is still detected and latched before any translation.
  R6  - mint dedup in the Gateway: dedup_key = SHA-256(canonical CBOR of
        (acs_action, acs_resource, presented action_digest, principal,
        QUANTIZED validity window [bucket_start, bucket_start+ttl],
        registry_hash_pin)) — §6.2 amendment (v11d): the timestamp is rounded
        down to discrete window_quantum_sec buckets so concurrent live-clock
        requests in the same bucket compute identical hashes; per-dedup_key
        lock held across translate->mint->emit; hit -> RETURN stored result
        (no second handle_event, no raise); PENDING duplicate -> DENY
        "event pending approval".
  R7  - adapter CONSTRUCTS GuardianEvent(action=entry.acs_action,
        resource=entry.acs_resource) and the presented ActionEnvelope from the
        registry entry; normative entry schema (entry_id, plane,
        qualified_verb, target_shape, presented_verb, acs_action,
        acs_resource).
  R8  - audit via anchor_v1.scitt.issue_statement, type anchor.v1/decision,
        subject f"action:{action_digest}", claims per spec 7.3 (nonce,
        prev_statement_hash chain, capability_id, registry_digest, ...);
        pipeline issue -> LocalTransparencyLog.register (explicit
        trusted_issuers) -> add_receipt -> transparent bytes stored.
  R9  - translate() order: parse -> 2.4 consistency -> allowlist +
        target_shape -> construct -> mint wrapper; integrity re-check before
        every translation; identical translate() on handle_event and
        resolve_pending paths.
  R10 - target_shape kind "exact" (byte equality) or "prefix" (linear scan);
        no regex, no backtracking matchers.
  R11 - http-plane intents DENY as unmapped (no anchor:http namespace in v1.1).
  §5.2 - SCITT-outage terminal behavior: a statement-write failure never
        escapes as a non-refusal — the DENY stands, the failure is recorded
        in the Gateway's local durable decision log with a monotonic
        scitt_outage counter, and translation continues. Persistent failures
        reaching the deployment-configured scitt_outage_threshold latch
        refuse-all + operator alert. A post-mint emit failure does NOT roll
        back the mint; the §7.6 reconciler re-emits from the durable
        decided record (which already holds capability_id).
  §5.3 - a SINGLE registry_compromise statement is emitted at §3.9 latch
        time; refused translations while latched only bump a local
        monotonic counter surfaced to the operator (no statement storm).

NOTE (§4.4): intake rate-limiting of unmapped intents is a DEPLOYMENT
obligation ("Deployments MUST rate-limit unmapped-intent intake (token
bucket or equivalent)"). This reference prototype deliberately does NOT
implement it: every unmapped intent still gets its deny_unmapped SCITT
statement, because the audit behavior is what is under test here. A
production deployment MUST front this adapter with an intake token bucket
that drops excess intents before translation.

DEPLOYMENT NOTES (v11e) — WAL and workdir hardening, plus the documented
residuals carried verbatim from the v11d-critic adjudication:
  * WAL (decision.wal.jsonl) records are hash-chained (prev_hash/rec_hash);
    replay verifies the full chain and refuses to start on any break or
    forgery. The chain detects record forgery and mid-file truncation, but
    CANNOT distinguish a crash from pure tail-truncation (both leave a
    self-consistent prefix). Therefore production deployments MUST (a) keep
    the workdir/WAL owner-only (restrictive file permissions) and (b) back
    up the WAL — restore from backup on any integrity refusal.
  * A restart orphans any still-PENDING ASK (the pending binding is
    process-local); the intent is then allowed a fresh ASK instead of being
    DENY'd "event pending approval" forever.
  * Documented limitations (verbatim acceptance language):
    L1. Quantized dedup guarantees one mint per dedup_key bucket; intents
        straddling a bucket boundary may mint once per bucket (<=1 extra
        mint per straddle). No fail-open; each bucket converges.
    L2. §6.3 holds per gateway process. Multi-process/multi-replica
        deployments MUST run a single gateway or add shared exclusion;
        concurrent cross-process duplicates each mint.
    L3. §7.2 ordering holds within a process lifetime. Across restarts the
        chain forks from genesis and reconcile() may duplicate statements.
        Production MUST persist the chain tip and use a real SCITT service
        (§7.3).
    L4. §6.2 specifies a process-lifetime map. Production MUST add TTL
        eviction tied to validity window + quantum.
    L5. The shim does not authenticate the caller→principal binding; the
        kernel's holder-key registry is the boundary. Multi-tenant front-ends
        MUST authenticate before submit_intent.
    L6. Registry freeze + re-derived integrity check stop unprivileged and
        single-attribute in-memory tampering. Arbitrary code execution inside
        the shim process remains total compromise (direct kernel calls, WAL
        tamper); the process boundary and code review are the controls.
    L7. HTTP plane: unchanged from prior rounds — http intents DENY
        as unmapped until a namespace extension is specified (documented
        limitation, not a gap).
    L8. (v11g) Effective ASK→approval TTL is at most one validity-window
        quantum (300s). approve_intent re-presents the durable ASK-time
        envelope, and the kernel denies the mint when the approval moment
        falls outside that envelope's [bucket_start, bucket_start+ttl]
        window ("presented envelope outside validity window"). An approval
        arriving ~300s or more after the ASK is therefore DENIED —
        fail-closed, never fail-open; the pending record itself is not
        what expires. Fresh-envelope re-issue semantics at approve time
        are post-launch work.

Run with ./.venv/bin/python from ~/workspace/anchor-v1.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1 import scitt as scitt_mod
from anchor_v1.acs_guardian import AcsGuardian, GuardianDecision, GuardianEvent
from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.cbor import cbor_dumps
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.scitt import (
    STATEMENT_DECISION,
    LocalTransparencyLog,
    add_receipt,
    issue_statement,
    parse_statement,
    verify_transparent_statement,
)

# ---------------------------------------------------------------------------
# R2: anchor: URI grammar (new v1.1 surface, adapter-owned)
# ---------------------------------------------------------------------------

MAX_URI_OCTETS = 256
DEFINED_NAMESPACES = frozenset({"shell", "acs"})  # R2: no http namespace
_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")      # 1..32 chars
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")       # 1..64 chars
ENFORCEMENT_PLANES = frozenset({"shell", "http"})          # §1.3 (R2/R11)


class SMPRefusal(Exception):
    """Fail-closed refusal from the adapter/gateway. The intent is dropped;
    the Guardian is never called on deny paths."""


class SCITTOutageError(SMPRefusal):
    """A SCITT statement-write failure, converted to a fail-closed refusal.

    Subclasses SMPRefusal so the DENY stands and the failure can never
    escape the adapter as a non-refusal (§5.1/§5.2): the outage has already
    been recorded in the Gateway's local durable decision log with the
    monotonic scitt_outage counter, and per §5.2 the adapter MUST NOT
    attempt to emit a statement about the failed emit (no infinite
    regress) — so translate() re-raises it without a second emit."""


class SimulatedCrash(Exception):
    """Test-only crash injection between pipeline stages (crash-window probe)."""


def parse_anchor_uri(verb: str) -> tuple[str, tuple[str, ...]]:
    """Parse per §2.2/R2. Returns (namespace, name_segments).

    Raises SMPRefusal("malformed ...") on grammar violation. A grammatically
    valid URI in an undefined namespace is NOT malformed — it is unmapped
    (§4.5); callers check the namespace against DEFINED_NAMESPACES.
    """
    if not isinstance(verb, str):
        raise SMPRefusal(f"malformed anchor URI: not a string: {verb!r}")
    raw = verb.encode("utf-8")
    if len(raw) > MAX_URI_OCTETS:
        raise SMPRefusal(
            f"malformed anchor URI: {len(raw)} octets > {MAX_URI_OCTETS}")
    if not verb.startswith("anchor:"):
        raise SMPRefusal(f"malformed anchor URI (missing 'anchor:' scheme): {verb!r}")
    rest = verb[len("anchor:"):]
    parts = rest.split("/")
    if len(parts) < 2 or any(p == "" for p in parts):
        raise SMPRefusal(
            f"malformed anchor URI (empty segment/trailing slash): {verb!r}")
    namespace, names = parts[0], tuple(parts[1:])
    if not _NAMESPACE_RE.match(namespace):
        raise SMPRefusal(
            f"malformed anchor URI (bad namespace {namespace!r}): {verb!r}")
    for seg in names:
        if not _NAME_RE.match(seg):
            raise SMPRefusal(
                f"malformed anchor URI (bad name segment {seg!r}): {verb!r}")
    return namespace, names


# ---------------------------------------------------------------------------
# Registry: build (deploy-time), pin, load (R3/R4/R7/R10)
# ---------------------------------------------------------------------------

def build_registry_payload(*, version: str, owner_key_id: str,
                           spiffe_id: str, entries: list[dict],
                           issued_at: str) -> dict:
    return {
        "registry_version": version,
        "owner": {"keyid": owner_key_id, "spiffe_id": spiffe_id},
        "issued_at": issued_at,
        "entries": entries,
    }


def sign_registry(payload: dict, owner: Ed25519Signer) -> dict:
    """Deploy-time signing: {payload, signature} per §3.5/R4."""
    payload_bytes = canonical_bytes(payload)
    sig = owner.sign_bytes(payload_bytes)
    return {
        "payload": payload,
        "signature": {
            "key_id": owner.key_id,
            "alg": "EdDSA",
            "sig": sig.hex(),
            "payload_hash_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        },
    }


def make_pin(*, version: str, payload_hash_sha256: str,
             owner_key_id: str) -> dict:
    return {
        "registry_version": version,
        "payload_hash_sha256": payload_hash_sha256,
        "owner_key_id": owner_key_id,
    }


@dataclass(frozen=True)
class RegistryEntry:
    entry_id: str
    plane: str
    qualified_verb: str
    target_kind: str      # "exact" | "prefix" (R10)
    target_value: str
    presented_verb: str
    acs_action: str
    acs_resource: str

    def matches(self, plane: str, verb: str, target: str) -> bool:
        if self.plane != plane or self.qualified_verb != verb:
            return False
        if self.target_kind == "exact":
            return target == self.target_value          # byte equality
        if self.target_kind == "prefix":
            return target.startswith(self.target_value)  # linear scan
        return False  # unreachable: kind validated at load


class MappingRegistry:
    """Loaded, frozen, signed registry (R3/R4/R7/R10). Immutable at runtime."""

    def __init__(self, *, registry_doc: dict, pin: dict,
                 owner_pubkey: bytes):
        # --- §3.7(a): pin hash check -------------------------------------
        payload = registry_doc.get("payload")
        signature = registry_doc.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise SMPRefusal("refusing to start: registry file must carry "
                             "{payload, signature} (§3.5)")
        payload_bytes = canonical_bytes(payload)  # retained (R5)
        actual_hash = hashlib.sha256(payload_bytes).hexdigest()
        if actual_hash != pin.get("payload_hash_sha256"):
            raise SMPRefusal(
                f"refusing to start: registry payload hash {actual_hash[:16]}… "
                f"!= pin {str(pin.get('payload_hash_sha256'))[:16]}…")
        # --- §3.7(b): signature check ------------------------------------
        if signature.get("key_id") != pin.get("owner_key_id"):
            raise SMPRefusal(
                f"refusing to start: signature key_id "
                f"{signature.get('key_id')!r} != pin owner "
                f"{pin.get('owner_key_id')!r}")
        if signature.get("alg") != "EdDSA":
            raise SMPRefusal("refusing to start: signature alg must be EdDSA")
        try:
            sig_bytes = bytes.fromhex(signature["sig"])
        except (ValueError, KeyError, TypeError):
            raise SMPRefusal("refusing to start: signature.sig not hex")
        try:
            Ed25519PublicKey.from_public_bytes(owner_pubkey).verify(
                sig_bytes, payload_bytes)
        except InvalidSignature:
            raise SMPRefusal("refusing to start: registry signature "
                             "verification FAILED (forgery/tamper)")
        except Exception as exc:
            raise SMPRefusal(f"refusing to start: signature check error: {exc}")
        if signature.get("payload_hash_sha256") != actual_hash:
            raise SMPRefusal("refusing to start: signature.payload_hash_sha256 "
                             "does not match recomputed payload hash")
        # --- pin/version consistency --------------------------------------
        version = payload.get("registry_version")
        if version != pin.get("registry_version"):
            raise SMPRefusal(
                f"refusing to start: registry_version {version!r} != pin "
                f"{pin.get('registry_version')!r}")
        owner_meta = payload.get("owner") or {}
        if owner_meta.get("keyid") != pin.get("owner_key_id"):
            raise SMPRefusal("refusing to start: payload owner.keyid != pin "
                             "owner_key_id")
        self._payload_bytes = payload_bytes   # R5: retained for re-hash
        self._pinned_hash = actual_hash
        self._version = version
        self._owner_keyid = pin["owner_key_id"]
        # v11e (S2): entries are built by the pure _build_entries so
        # assert_live() can re-derive them from the retained canonical
        # payload bytes and detect in-memory tamper.
        self._entries: list[RegistryEntry] = self._build_entries(
            payload.get("entries"))
        self._dead = False

    # -- entry validation (§2 grammar, §2.4, §3.3 kinds, §3.4, §1.3) ---------
    @staticmethod
    def _build_entries(entries) -> list[RegistryEntry]:
        """Validate raw entry dicts and build the frozen entry list.

        Pure function of the payload entries (no self mutation) so the
        runtime integrity check can re-derive entries from the retained
        canonical payload bytes and compare against the live objects."""
        built: list[RegistryEntry] = []
        if not isinstance(entries, list) or not entries:
            raise SMPRefusal("refusing to start: registry has no entries")
        seen_presented: dict[tuple[str, str], str] = {}  # R3 injectivity
        seen_triple: dict[tuple[str, str, tuple[str, str]], str] = {}  # §3.4
        for raw in entries:
            eid = raw.get("entry_id", "<missing entry_id>")
            plane = raw.get("plane")
            if plane not in ENFORCEMENT_PLANES:
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} names fictitious "
                    f"target plane {plane!r} (§1.3: only 'shell'/'http' are "
                    f"enforcement planes)")
            qv, pv = raw.get("qualified_verb"), raw.get("presented_verb")
            try:
                parse_anchor_uri(qv)
                pns, _ = parse_anchor_uri(pv)
            except SMPRefusal as exc:
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} has malformed verb: "
                    f"{exc}") from exc
            if plane == "shell" and pns != "shell":
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} violates §2.4: "
                    f"shell-plane entry with presented verb {pv!r}")
            if pns == "acs":
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} violates §2.4(c): "
                    f"anchor:acs/ verb as executable effect verb")
            aa = raw.get("acs_action")
            try:
                ans, _ = parse_anchor_uri(aa)
            except SMPRefusal as exc:
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} has malformed "
                    f"acs_action: {exc}") from exc
            if ans != "acs":
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r}: acs_action must be in "
                    f"anchor:acs/ (evaluation domain), got {aa!r}")
            shape = raw.get("target_shape") or {}
            kind, value = shape.get("kind"), shape.get("value")
            if kind not in ("exact", "prefix") or not isinstance(value, str):
                raise SMPRefusal(
                    f"refusing to start: entry {eid!r} has bad target_shape "
                    f"(kind must be 'exact'/'prefix', value a string; "
                    f"regex/backtracking matchers forbidden, R10)")
            key = (plane, pv)  # R3: injectivity on (plane, presented_verb)
            if key in seen_presented:
                raise SMPRefusal(
                    f"refusing to start: N-to-1 privilege collapse (R3): "
                    f"entries {seen_presented[key]!r} and {eid!r} map to the "
                    f"same (plane, presented_verb)={key!r}")
            seen_presented[key] = eid
            # §3.4: duplicate registry key — identical (plane, qualified_verb,
            # target_shape) triple (target_shape compared by value, not
            # object identity) is dead registry text with order-dependent
            # lookup; only the signing-key holder can author one, so this
            # is a fail-fast authoring check at load.
            triple = (plane, qv, (kind, value))
            if triple in seen_triple:
                raise SMPRefusal(
                    f"refusing to start: duplicate registry key (§3.4): "
                    f"entries {seen_triple[triple]!r} and {eid!r} share the "
                    f"identical (plane, qualified_verb, target_shape)="
                    f"{triple!r} — dead registry text with "
                    f"order-dependent lookup")
            seen_triple[triple] = eid
            for f in ("acs_resource",):
                if not isinstance(raw.get(f), str) or not raw.get(f):
                    raise SMPRefusal(
                        f"refusing to start: entry {eid!r} missing {f}")
            built.append(RegistryEntry(
                entry_id=eid, plane=plane, qualified_verb=qv,
                target_kind=kind, target_value=value, presented_verb=pv,
                acs_action=aa, acs_resource=raw["acs_resource"]))
        return built

    # -- R5: runtime integrity ----------------------------------------------
    def assert_live(self) -> None:
        """Re-hash before every translation; latch dead on any mismatch.

        v11e (S2): the retained canonical payload bytes are ground truth.
        After the bytes re-hash, the parsed entries are re-derived from
        those bytes and compared field-by-field against the live entry
        objects. A privileged in-process mutation (object.__setattr__ /
        ctypes) that leaves the retained bytes intact is still detected
        here — before any translation — and latches the adapter dead."""
        if self._dead:
            raise SMPRefusal("adapter dead: registry integrity failure "
                             "(latched); restart with a valid registry")
        observed = hashlib.sha256(self._payload_bytes).hexdigest()
        if observed != self._pinned_hash:
            self._dead = True
            raise SMPRefusal(
                f"REGISTRY MUTATION DETECTED: observed {observed[:16]}… != "
                f"pinned {self._pinned_hash[:16]}…; adapter latched dead")
        try:
            rederived = self._build_entries(
                json.loads(self._payload_bytes)["entries"])
        except Exception as exc:
            self._dead = True
            raise SMPRefusal(
                f"REGISTRY ENTRY RE-DERIVATION FAILED ({exc}); adapter "
                f"latched dead") from exc
        if rederived != self._entries:
            self._dead = True
            raise SMPRefusal(
                "REGISTRY ENTRY MUTATION DETECTED: live parsed entries "
                "diverge from the entries re-derived from the retained "
                "canonical payload bytes (in-memory tamper); adapter "
                "latched dead")

    def lookup(self, plane: str, verb: str, target: str) -> RegistryEntry | None:
        for e in self._entries:          # linear scan; no regex (R10)
            if e.matches(plane, verb, target):
                return e
        return None

    @property
    def version(self): return self._version
    @property
    def digest(self): return self._pinned_hash      # registry_digest claim
    @property
    def owner_keyid(self): return self._owner_keyid

# ---------------------------------------------------------------------------
# Adapter: translate pipeline (R7/R9) + SCITT audit (R8)
# ---------------------------------------------------------------------------

@dataclass
class TranslatedIntent:
    event: GuardianEvent
    envelope: ActionEnvelope
    entry: RegistryEntry
    dedup_key: str


class ShimAdapter:
    """The v1.1 Seam Mapping Provider (deployment shim, pre-forward).

    Owns: registry integrity (R5), translate() (R9), SCITT statement chain
    (R8). Never calls the Guardian — the Gateway does that (§1.5).
    """

    def __init__(self, *, registry: MappingRegistry,
                 translation_signer: Ed25519Signer,
                 log_signer: Ed25519Signer,
                 constitution_hash: str, capability_ttl_s: float,
                 now_fn=None, scitt_outage_threshold: int = 3,
                 window_quantum_sec: float = 300.0):
        self.registry = registry
        self._tsigner = translation_signer
        self._constitution = constitution_hash
        self._ttl_s = float(capability_ttl_s)
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        # §6.2 amendment (v11d): mint-dedup clock quantization. The validity
        # window (and envelope issued_at) are quantized to discrete buckets
        # of this size so concurrent same-bucket requests build byte-identical
        # envelopes and dedup_keys under a live clock.
        self._window_quantum_sec = max(1.0, float(window_quantum_sec))
        # v11d F4: a quantum larger than the capability TTL would mint
        # envelopes whose validity window excludes the mint moment for part
        # of each bucket (the kernel fails closed with DENY, but the
        # misconfiguration must not deploy silently).
        if self._window_quantum_sec > self._ttl_s:
            raise ValueError(
                f"window_quantum_sec ({self._window_quantum_sec}) must not "
                f"exceed capability_ttl_s ({self._ttl_s})")
        self._prev_statement_hash = "0" * 64          # genesis (R8/§7.3)
        self._seq = 0
        # v11h (harden-F): high-water bucket watermark. The dedup_key is
        # bucket-scoped, so a backward wall-clock jump across a bucket
        # boundary would otherwise mint an identical intent twice (the
        # "re-opened" earlier bucket computes a different dedup_key).
        # Pin the translate-time bucket to the maximum bucket start ever
        # observed: a backward jump then recomputes the SAME dedup_key and
        # hits dedup (deny-as-duplicate) instead of double-minting.
        # New (non-duplicate) intents submitted while the wall clock trails
        # the watermark get an envelope whose issued_at is in the future
        # relative to the wall clock; the kernel's validity-window check
        # then denies them fail-closed until the clock catches up.
        self._bucket_lock = threading.Lock()
        self._max_bucket_seen: float | None = None  # epoch seconds
        self._statements: list[bytes] = []            # issued (pre-receipt)
        self._transparent: list[bytes] = []           # + receipts
        # §5.2: persistent-outage latch config + state. The durable
        # scitt_outage counter lives in the Gateway's decision log (wired by
        # the Gateway via attach_outage_log); the adapter mirrors it locally.
        self._scitt_outage_threshold = max(1, int(scitt_outage_threshold))
        self._scitt_outage_count = 0
        self._scitt_latched = False        # refuse-all latch (§5.2)
        self._scitt_latched_refused = 0   # translations refused while latched
        self._record_scitt_outage = None  # Gateway-wired durable recorder
        self._operator_alert = None       # Gateway-wired alert sink
        # §5.3: single compromise statement at latch; counter-only after.
        self._compromise_emitted = False
        self._latched_refused_count = 0
        trusted = {translation_signer.key_id.encode("utf-8"):
                   Ed25519PublicKey.from_public_bytes(
                       translation_signer.public_key_bytes())}
        # §7.9: explicit trusted_issuers — the permissive default MUST NOT
        # be used.
        self._log = LocalTransparencyLog(signer=log_signer,
                                         trusted_issuers=trusted)
        self._log_trusted = {log_signer.key_id.encode("utf-8"):
                             Ed25519PublicKey.from_public_bytes(
                                 log_signer.public_key_bytes())}
        self.trusted_issuers = trusted

    def attach_outage_log(self, *, record_fn, alert_fn) -> None:
        """Wire the Gateway's local durable decision log into the adapter.

        record_fn(why: str) -> int: durably records one SCITT write failure
        and returns the new monotonic scitt_outage count. alert_fn(msg: str):
        operator-alert sink. Called once by SmpGateway.__init__ (§5.2)."""
        self._record_scitt_outage = record_fn
        self._operator_alert = alert_fn

    def _on_scitt_write_failure(self, why: str) -> int:
        """§5.2: record a SCITT statement-write failure; latch refuse-all
        (plus operator alert) once failures reach the deployment threshold."""
        rec = self._record_scitt_outage
        if rec is not None:
            n = rec(why)  # durable monotonic counter in the Gateway's log
        else:             # standalone adapter (no Gateway): in-memory only
            self._scitt_outage_count += 1
            n = self._scitt_outage_count
        self._scitt_outage_count = n
        if n >= self._scitt_outage_threshold and not self._scitt_latched:
            self._scitt_latched = True
            alert = self._operator_alert
            if alert is not None:
                alert(f"SCITT OUTAGE: {n} statement-write failures reached "
                      f"the deployment threshold "
                      f"({self._scitt_outage_threshold}); adapter latched "
                      f"refuse-all per §5.2")
        return n

    # -- R8: SCITT decision statements --------------------------------------
    def _emit_statement(self, *, claims: dict, action_digest: str) -> bytes:
        """Single funnel for every SCITT statement write (R8/§7).

        §5.2 terminal behavior: a write failure is recorded (durable
        scitt_outage counter) and converted to SCITTOutageError — a
        fail-closed SMPRefusal, never a raw exception — so it can never
        escape translate()/submit_intent() as a non-refusal. Callers MUST
        NOT emit a statement about the failed emit (no infinite regress)."""
        try:
            return self._emit_statement_inner(claims=claims,
                                              action_digest=action_digest)
        except Exception as exc:
            self._on_scitt_write_failure(f"{type(exc).__name__}: {exc}")
            raise SCITTOutageError(
                f"SCITT statement write failed: {exc}") from exc

    def _emit_statement_inner(self, *, claims: dict,
                              action_digest: str) -> bytes:
        claims = dict(claims)
        claims["nonce"] = secrets.token_hex(16)          # 128-bit CSPRNG
        claims["prev_statement_hash"] = self._prev_statement_hash
        claims["registry_digest"] = self.registry.digest
        claims["registry_keyid"] = self.registry.owner_keyid
        claims["registry_version"] = self.registry.version
        stmt = issue_statement(
            statement_type=STATEMENT_DECISION,            # "anchor.v1/decision"
            subject=f"action:{action_digest}",            # R8 / §7.2
            claims=claims,
            issuer=self._tsigner,
        )
        receipt = self._log.register(stmt)               # §7.9 pipeline
        transparent = add_receipt(stmt, receipt)
        self._prev_statement_hash = hashlib.sha256(stmt).hexdigest()
        self._seq += 1
        self._statements.append(stmt)
        self._transparent.append(transparent)
        return stmt

    def emit_deny(self, *, status: str, reason: str, plane: str, verb: str,
                  target: str, principal: str, params: dict,
                  entry_id: str | None = None,
                  acs_action: str | None = None,
                  acs_resource: str | None = None,
                  dedup_key: str | None = None) -> bytes:
        # No translated envelope exists on deny paths: the subject binds the
        # intent digest instead (documented deviation point).
        intent_digest = hashlib.sha256(cbor_dumps(
            [plane, verb, target, principal, sha256_hex(params)])).hexdigest()
        return self._emit_statement(
            action_digest=intent_digest,
            claims={
                "translation_status": status,
                "orchestrator_id": principal,
                "original_verb": verb,
                "original_target": target,
                "translated_verb": None,
                "translated_target": None,
                "acs_action": acs_action,
                "acs_resource": acs_resource,
                "registry_entry_id": entry_id,
                "action_digest": intent_digest,
                "capability_id": None,
                "dedup_key": dedup_key,
                "deny_reason": reason,
            })

    def emit_allow(self, *, envelope: ActionEnvelope, entry: RegistryEntry,
                   principal: str, verb: str, target: str,
                   capability_id: str | None, dedup_key: str,
                   pending_note: str | None = None) -> bytes:
        return self._emit_statement(
            action_digest=envelope.action_digest,
            claims={
                "translation_status": "hit",
                "orchestrator_id": principal,
                "original_verb": verb,
                "original_target": target,
                "translated_verb": entry.presented_verb,
                "translated_target": target,
                "acs_action": entry.acs_action,
                "acs_resource": entry.acs_resource,
                "registry_entry_id": entry.entry_id,
                "action_digest": envelope.action_digest,
                "capability_id": capability_id,
                "dedup_key": dedup_key,
                "deny_reason": pending_note,
            })

    def emit_compromise(self, *, observed: str, pinned: str) -> bytes:
        return self._emit_statement(
            action_digest=observed,
            claims={
                "translation_status": "registry_compromise",
                "orchestrator_id": None,
                "original_verb": None,
                "original_target": None,
                "translated_verb": None,
                "translated_target": None,
                "acs_action": None,
                "acs_resource": None,
                "registry_entry_id": None,
                "action_digest": None,
                "capability_id": None,
                "dedup_key": None,
                "deny_reason": (f"registry mutation detected: observed "
                                f"{observed} != pinned {pinned}; adapter "
                                f"latched dead, refusing ALL translations"),
                "observed_digest": observed,
                "pinned_digest": pinned,
            })

    # -- R9: translate(intent), the identical function for both paths --------
    def translate(self, *, plane: str, verb: str, target: str,
                  principal: str, params: dict, event_id: str,
                  event_type: str = "pre_tool_call",
                  session_id: str = "sess-smp") -> TranslatedIntent:
        """§4.2 order: parse -> §2.4 consistency -> allowlist+target_shape ->
        construct -> (gateway mints). Integrity re-check before every
        translation (R5). Raises SMPRefusal on any failure (fail-closed, §5).
        """
        # §5.2: persistent SCITT-outage latch — refuse-all. No statement is
        # attempted while latched (SCITT is presumed down; attempts would
        # only inflate the outage counter).
        if self._scitt_latched:
            self._scitt_latched_refused += 1
            raise SMPRefusal(
                "refuse-all: persistent SCITT statement-write outage "
                "(latched, §5.2); the adapter cannot meet its §7 audit "
                "obligations until restart")
        # R5: integrity re-check before EVERY translation.
        try:
            self.registry.assert_live()
        except SMPRefusal:
            # §5.3: the SINGLE registry_compromise statement is emitted at
            # latch time; refused translations while latched only bump the
            # local monotonic counter surfaced to the operator.
            if not self._compromise_emitted:
                self._compromise_emitted = True
                observed = hashlib.sha256(
                    self.registry._payload_bytes).hexdigest()
                try:
                    self.emit_compromise(observed=observed,
                                         pinned=self.registry.digest)
                except Exception:
                    pass  # §5.2: outage already recorded by _emit_statement;
                          # the refusal stands regardless
            self._latched_refused_count += 1
            raise
        try:
            return self._translate_inner(
                plane=plane, verb=verb, target=target, principal=principal,
                params=params, event_id=event_id, event_type=event_type,
                session_id=session_id)
        except SMPRefusal:
            # Includes SCITTOutageError: the emit itself failed, the outage
            # is already recorded, and §5.2 forbids a statement about the
            # failed emit — re-raise without a second emit. The DENY stands.
            raise
        except Exception as exc:  # §5.1 catch-all: any failure -> DENY
            try:
                self.emit_deny(status="error",
                               reason=f"adapter exception: {exc}",
                               plane=plane, verb=verb, target=target,
                               principal=principal, params=params)
            except Exception:
                pass  # §5.2: the catch-all's own emit failure is recorded
                      # (outage counter) by _emit_statement; it must never
                      # escape as a non-SMPRefusal
            raise SMPRefusal(f"adapter error (fail-closed): {exc}") from exc

    def _translate_inner(self, *, plane: str, verb: str, target: str,
                         principal: str, params: dict, event_id: str,
                         event_type: str, session_id: str) -> TranslatedIntent:
        # 1. parse §2.2/R2; malformed -> §5 error (never forwarded).
        try:
            namespace, _ = parse_anchor_uri(verb)
        except SMPRefusal as exc:
            self.emit_deny(status="error", reason=str(exc), plane=plane,
                           verb=verb, target=target, principal=principal,
                           params=params)
            raise
        # 2. §2.4 namespace->plane consistency, BEFORE the allowlist lookup.
        if plane == "http":
            # R11: no anchor:http/ namespace in v1.1 -> DENY as unmapped.
            self.emit_deny(
                status="deny_unmapped", plane=plane, verb=verb, target=target,
                principal=principal, params=params,
                reason="R11: no anchor:http/ namespace defined in v1.1; "
                       "http-plane intents cannot be expressed and DENY as "
                       "unmapped")
            raise SMPRefusal("http-plane intent denied as unmapped (R11)")
        if plane == "shell" and namespace != "shell":
            self.emit_deny(status="deny_namespace_mismatch", plane=plane,
                           verb=verb, target=target, principal=principal,
                           params=params,
                           reason=f"§2.4(a): shell-plane envelope with verb "
                                  f"in anchor:{namespace}/")
            raise SMPRefusal(f"namespace/plane mismatch: {verb!r} on 'shell'")
        if namespace == "acs":
            self.emit_deny(status="deny_namespace_mismatch", plane=plane,
                           verb=verb, target=target, principal=principal,
                           params=params,
                           reason="§2.4(c): anchor:acs/ verb as executable "
                                  "effect verb")
            raise SMPRefusal("anchor:acs/ verb may never be an effect verb")
        if plane not in ("shell",):
            self.emit_deny(status="deny_namespace_mismatch", plane=plane,
                           verb=verb, target=target, principal=principal,
                           params=params,
                           reason=f"unknown plane {plane!r}: no namespace "
                                  f"defined")
            raise SMPRefusal(f"no namespace defined for plane {plane!r}")
        if namespace not in DEFINED_NAMESPACES:
            # grammatically valid, undefined namespace -> unmapped (§4.5)
            self.emit_deny(status="deny_unmapped", plane=plane, verb=verb,
                           target=target, principal=principal, params=params,
                           reason=f"undefined namespace anchor:{namespace}/: "
                                  f"unmapped")
            raise SMPRefusal(f"undefined namespace anchor:{namespace}/")
        # 3. allowlist + target_shape (R10).
        entry = self.registry.lookup(plane, verb, target)
        if entry is None:
            self.emit_deny(status="deny_unmapped", plane=plane, verb=verb,
                           target=target, principal=principal, params=params,
                           reason=f"UNMAPPED_ACTION: {(plane, verb, target)!r}")
            raise SMPRefusal(f"UNMAPPED_ACTION: {(plane, verb, target)!r}")
        # 4. construct (R7): GuardianEvent + presented ActionEnvelope.
        now = self._now()
        # §6.2 amendment (v11d): quantize the validity window to
        # window_quantum_sec buckets. The raw clock is microsecond-precise;
        # without quantization, concurrent translate() calls each computed a
        # distinct window (and, via issued_at/nonce/action_id, a distinct
        # action_digest), so dedup never fired under a live clock (v11c S1).
        # Quantized windows make same-bucket requests build byte-identical
        # envelopes and dedup_keys, so the per-key lock converges to exactly
        # one mint. Documented residual: requests straddling a bucket
        # boundary inside one microsecond burst compute different keys.
        _q = self._window_quantum_sec
        nb = datetime.fromtimestamp(
            math.floor(now.timestamp() / _q) * _q, tz=timezone.utc)
        # v11h (harden-F): pin to the high-water bucket watermark so a
        # backward wall-clock jump cannot re-open an earlier dedup bucket.
        with self._bucket_lock:
            nb_ts = nb.timestamp()
            if self._max_bucket_seen is None or nb_ts > self._max_bucket_seen:
                self._max_bucket_seen = nb_ts
            elif nb_ts < self._max_bucket_seen:
                nb = datetime.fromtimestamp(self._max_bucket_seen,
                                            tz=timezone.utc)
        na = nb + timedelta(seconds=self._ttl_s)
        args_digest = sha256_hex(params)
        # Deterministic envelope: the presented envelope is a pure function
        # of the decided event, so retries of the same decided event produce
        # the same digest and the §6.2 dedup_key is well-defined. (Random
        # nonces would make the normative dedup key unsatisfiable with
        # adapter-constructed envelopes.)
        det = cbor_dumps([plane, entry.presented_verb, target, principal,
                          args_digest, nb.isoformat(), na.isoformat(),
                          self.registry.digest])
        envelope = ActionEnvelope(
            action_id=uuid.UUID(bytes=hashlib.sha256(
                b"action-id" + det).digest()[:16]),
            principal=principal,
            effect=Effect(plane=plane, verb=entry.presented_verb,
                          target=target, args_digest=args_digest),
            policy_ref=self._constitution,
            # issued_at = quantized bucket start (NOT the raw clock): the
            # action_digest folds issued_at, so byte-identical envelopes
            # (and hence identical dedup_keys) require a quantized issued_at.
            issued_at=nb, not_before=nb, not_after=na,
            nonce=hashlib.sha256(b"nonce" + det).hexdigest()[:32],
        )
        event = GuardianEvent(
            event_id=event_id, event_type=event_type, session_id=session_id,
            subject=principal, action=entry.acs_action,
            resource=entry.acs_resource, params=dict(params), ts=now,
        )
        # R6/§6.2 dedup_key.
        dedup_key = hashlib.sha256(cbor_dumps(
            [entry.acs_action, entry.acs_resource, envelope.action_digest,
             principal, [nb.isoformat(), na.isoformat()],
             self.registry.digest])).hexdigest()
        return TranslatedIntent(event=event, envelope=envelope, entry=entry,
                                dedup_key=dedup_key)

# ---------------------------------------------------------------------------
# Gateway: sole Guardian caller, mint dedup (R6), resolve_pending (§9),
# durable decision log + reconciler (§7.5/§7.6)
# ---------------------------------------------------------------------------

@dataclass
class SmpResult:
    decision: GuardianDecision
    envelope: ActionEnvelope | None
    status: str            # hit_allow | hit_deny | ask_pending | deny_* | error
    dedup_key: str | None
    from_cache: bool = False


def _pid_alive(pid: int) -> bool:
    """True if the OS still has a live process with this pid.

    Used to orphan PENDING/intent records whose owner crashed. A reused
    pid reads as alive — documented residual (the record then waits for
    the next liveness re-check or a process restart).
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True   # exists, owned by another user
    except OSError:
        return True   # conservative
    return True


class DecisionLog:
    """Durable (fsync'd JSONL WAL) decided-events + intent record store.

    v11e (F2): every record is hash-chained to its predecessor
    (prev_hash/rec_hash). _replay() verifies the full chain and FAILS
    CLOSED — the gateway refuses to start — on any break, forgery, or
    truncation that leaves subsequent records. Deployment MUST: restrictive
    (owner-only) file permissions on the workdir, plus WAL backups. A hash
    chain cannot distinguish a crash from pure tail-truncation (both leave
    a self-consistent prefix); that residual is covered by the
    backup/permission controls, not by the chain.

    harden-A (crash-consistency): a torn tail — a trailing partial line, or
    a complete final line missing its newline, from a kill -9 / power loss
    mid-append — no longer bricks the node. _replay drops ONLY the trailing
    incomplete line (after the full prefix hash-verifies) via a crash-safe
    ftruncate, or restores the missing newline; a corrupt middle line still
    refuses loudly.
    """

    _CHAIN_GENESIS = "genesis"

    def __init__(self, path: Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a", encoding="utf-8")
        self.decided: dict[str, dict] = {}   # dedup_key -> record
        self.intents: dict[str, dict] = {}   # dedup_key -> intent record
        self.alerts: list[str] = []
        self.scitt_outage: int = 0           # §5.2 monotonic outage counter
        self._chain_tip = self._CHAIN_GENESIS
        # harden-B (cross-process double-mint): OS-level mutual exclusion
        # for the check-and-mint critical section. The lock file is a
        # sibling of the WAL; flock is released by the kernel when the
        # holder's fd closes, so a crashed process can NEVER leave a stale
        # lock (no bricking).
        #
        # FILESYSTEM REQUIREMENT (harden-B critic finding 2): the WAL
        # workdir MUST be a local POSIX filesystem. flock() on NFS (emulated
        # via NLM — flaky on partitions) or on FUSE/network filesystems
        # where it is a silent no-op provides NO exclusion: without a real
        # flock the cross-process guarantee vanishes silently and the
        # double-mint / WAL-fork bugs return. If the workdir may sit on
        # NFS/FUSE, do not rely on harden-B; keep a single gateway process.
        self._lock_path = self._path.parent / (self._path.name + ".xproc.lock")
        self._lock_fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR,
                                0o600)
        self._replay_offset = 0     # WAL byte offset of our last read
        self._replay_lines = 0      # WAL line count of our last read
        # Reentrancy/thread-safety for xproc_section: flock() does not
        # exclude threads of the SAME process (same open file description),
        # and a second LOCK_EX / first LOCK_UN on the same fd would
        # corrupt the hold count. So thread exclusion is a threading.RLock
        # held for the whole section (reentrant within a thread), while
        # flock() is acquired/released exactly on the outermost entry/
        # exit of each thread — providing the cross-process exclusion.
        self._xproc_rlock = threading.RLock()
        self._xproc_depths: dict[int, int] = {}  # thread ident -> depth
        # dedup_keys with a live PENDING or an undecided intent record,
        # re-checked for owner liveness on every refresh (usually tiny).
        self._pending_watch: set[str] = set()
        # pid -> last monotonic time it was confirmed alive (bounds kill()
        # syscalls; a pid confirmed alive is re-checked after 60 s).
        self._live_pids: dict[int, float] = {}
        # v11g (SERIOUS-1): serialize the read-modify-write of _chain_tip
        # in _append. Lock ordering is fixed: the gateway's per-key locks
        # are always taken BEFORE _append is entered (never acquired
        # inside it), so this inner lock cannot deadlock. Created before
        # _replay() because _replay -> mark_orphaned -> _append.
        self._append_lock = threading.Lock()
        self._replay()

    def _append(self, op: dict) -> None:
        with self._append_lock:
            op = dict(op)
            op["prev_hash"] = self._chain_tip
            body = json.dumps(op, sort_keys=True)
            op["rec_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
            line = json.dumps(op, sort_keys=True)
            raw = (line + "\n").encode("utf-8")
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._chain_tip = hashlib.sha256(
                line.encode("utf-8")).hexdigest()
            # harden-B: keep the read offset in step with our own writes,
            # so a later _refresh() does not re-read (and re-verify) them.
            self._replay_offset += len(raw)
            self._replay_lines += 1

    @staticmethod
    def _parse_line(raw: bytes, lineno: int) -> dict | None:
        """Parse one raw WAL line. Returns None for blank lines.

        harden-B critic finding 3: a torn UTF-8 sequence is a loud
        SMPRefusal, not a leaked raw UnicodeDecodeError.
        """
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise SMPRefusal(
                f"WAL INTEGRITY FAILURE: line {lineno} is not valid "
                f"UTF-8 (possible tamper); refusing to start — restore "
                f"the WAL from backup")
        if not line:
            return None
        try:
            return json.loads(line)
        except ValueError:
            raise SMPRefusal(
                f"WAL INTEGRITY FAILURE: line {lineno} is not valid "
                f"JSON (possible tamper); refusing to start — restore "
                f"the WAL from backup")

    def _apply_record(self, op: dict, lineno: int,
                      raw_line: bytes) -> None:
        """Verify one WAL record against the hash chain and merge it into
        the in-memory indexes. Shared by _replay() (startup) and
        _refresh() (cross-process mid-run merge) — harden-B."""
        if not isinstance(op, dict):
            raise SMPRefusal(
                f"WAL INTEGRITY FAILURE: line {lineno} is not a "
                f"record object (possible tamper); refusing to start "
                f"— restore the WAL from backup")
        # v11e (F2): verify the hash chain before trusting any record.
        rec_hash = op.get("rec_hash")
        prev_hash = op.get("prev_hash")
        body = {k: v for k, v in op.items() if k != "rec_hash"}
        expect = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
        if (not isinstance(rec_hash, str)
                or not isinstance(prev_hash, str)
                or prev_hash != self._chain_tip or rec_hash != expect):
            raise SMPRefusal(
                f"WAL INTEGRITY FAILURE: hash chain broken at line "
                f"{lineno} (forgery or truncation); refusing to start "
                f"— restore the WAL from backup")
        # The tip hashes the stripped raw line — exactly what _append
        # hashed when it wrote the record.
        self._chain_tip = hashlib.sha256(raw_line.strip()).hexdigest()
        k = op.get("dedup_key")
        if op.get("op") == "intent" and k:
            self.intents[k] = op
        elif op.get("op") == "decided" and k:
            self.decided[k] = op
        elif op.get("op") == "orphaned" and k:
            rec = self.decided.get(k, {})
            rec["orphaned"] = True
            self.decided[k] = rec
        elif op.get("op") == "scitt_outage":
            # §5.2: monotonic across restarts — resume from the max.
            try:
                self.scitt_outage = max(self.scitt_outage,
                                        int(op.get("count", 0)))
            except (TypeError, ValueError):
                pass

    def _replay(self) -> None:
        if not self._path.exists():
            return
        self._chain_tip = self._CHAIN_GENESIS
        # harden-A (crash-consistency): a kill -9 / power loss mid-append
        # can leave a TORN TAIL — a trailing partial line that is not valid
        # JSON, or a complete final line missing its trailing newline
        # (crash landed between the line bytes and the newline flush; the
        # next append would otherwise concatenate onto it and brick the
        # node on the following restart). v1.1.1 failed CLOSED on any such
        # tail and stayed bricked until a manual backup restore.
        #
        # Recovery rule: ONLY the trailing incomplete line may be dropped,
        # and ONLY after every preceding line has verified against the hash
        # chain (the loop below verifies in order and raises before it ever
        # reaches the tail otherwise). A corrupt MIDDLE line — any non-blank
        # content after the bad line — still refuses loudly.
        #
        # Crash-safety of the repair itself: both repairs are idempotent and
        # size-atomic. Dropping the tail is a single ftruncate() to the last
        # verified line boundary + fsync: a crash mid-truncate leaves either
        # the old size (tail re-detected and re-verified on next boot) or
        # the new size (repair complete). Repairing a missing newline is a
        # one-byte append + fsync with the same either/or property.
        #
        # harden-B: the per-record verify-and-merge now goes through
        # _apply_record (shared with the cross-process _refresh), and the
        # replay establishes the read offset/line count that _refresh
        # resumes from.
        data = self._path.read_bytes()
        chunks: list[tuple[int, bytes]] = []  # (start_offset, line_bytes)
        off = 0
        for chunk in data.split(b"\n"):
            chunks.append((off, chunk))
            off += len(chunk) + 1
        torn_dropped = False
        seen_valid = False
        verified_lines = 0
        idx = 0
        total = len(chunks)
        while idx < total:
            start, chunk = chunks[idx]
            lineno = idx + 1
            idx += 1
            if not chunk.strip():
                continue
            parsed = False
            try:
                op = self._parse_line(chunk, lineno)
                parsed = True
            except SMPRefusal:
                op = None
            if not parsed or op is None:
                # Not valid JSON: torn tail, or middle corruption?
                rest_nonblank = any(c.strip() for _, c in chunks[idx:])
                if rest_nonblank:
                    raise SMPRefusal(
                        f"WAL INTEGRITY FAILURE: line {lineno} is not "
                        f"valid JSON with intact records after it "
                        f"(possible tamper); refusing to start — restore "
                        f"the WAL from backup")
                # Torn tail: every preceding line verified (the loop raises
                # on the first bad one, so reaching here IS the proof).
                # Truncate to the last verified line boundary — only now,
                # after full verification of the prefix.
                with open(self._path, "r+b") as fh:
                    fh.truncate(start)
                    fh.flush()
                    os.fsync(fh.fileno())
                torn_dropped = True
                self.alerts.append(
                    f"WAL torn tail at line {lineno}: dropped "
                    f"{len(data) - start} trailing byte(s) from an "
                    f"interrupted append; hash chain verified through the "
                    f"preceding {lineno - 1} line(s)")
                break
            # harden-B: verify against the chain and merge via the shared
            # helper (raises SMPRefusal on a broken chain / non-dict).
            self._apply_record(op, lineno, chunk)
            verified_lines += 1
            seen_valid = True
        if (not torn_dropped and seen_valid and data and not data.endswith(b"\n")
                and chunks and chunks[-1][1].strip()):
            # Complete final record whose trailing newline never landed
            # (crash between the line bytes and the newline flush). The
            # record is fully present and hash-verified, so it is kept;
            # restore the newline BEFORE any append can concatenate onto it.
            with open(self._path, "ab") as fh:
                fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.alerts.append(
                "WAL tail: final record was missing its trailing newline "
                "(interrupted append); newline restored, no records lost")
        # harden-B: establish the read cursor AFTER any torn-tail repair,
        # so _refresh() resumes exactly at end-of-verified-data.
        self._replay_offset = os.path.getsize(self._path)
        self._replay_lines = verified_lines
        self._update_pending_watch()
        # v11e (F2c): a restart orphans any still-PENDING ASK. The
        # gateway-side pending binding (_pending_by_id) is process-local
        # and cannot survive a restart, so the intent must be allowed a
        # fresh ASK instead of being DENY'd "event pending approval"
        # forever (fail-closed, but a permanent availability DoS from an
        # ordinary restart). Already-orphaned records are skipped
        # (idempotent across repeated restarts).
        #
        # harden-B: the orphan sweep runs under the cross-process section
        # so two processes restarting against the same WAL cannot fork the
        # chain; the read cursor is resynced afterwards (a peer may have
        # appended while we swept).
        with self.xproc_section():
            orphaned = 0
            for dk, rec in list(self.decided.items()):
                if rec.get("state") == "PENDING" and not rec.get("orphaned"):
                    self.mark_orphaned(
                        dk, "PENDING at WAL replay: ASK orphaned by restart; "
                            "a fresh ASK is allowed")
                    orphaned += 1
            self._replay_offset = os.fstat(
                self._fh.fileno()).st_size
            # Every record is one "\n"-terminated line; the orphan sweep
            # appended exactly `orphaned` of them.
            self._replay_lines = verified_lines + orphaned

    def _refresh(self) -> None:
        """Merge records other processes appended since our last read.

        Must be called with the xproc lock held (xproc_section does
        this): the refresh-then-act sequence is the cross-process analogue
        of the in-process per-key lock, and the chain tip it advances is
        what our subsequent _append calls chain onto.
        """
        st_size = os.fstat(self._fh.fileno()).st_size
        # harden-B critic finding 4: if our read cursor is beyond the
        # current file size, the WAL was replaced or truncated under us —
        # seeking past it would silently MISS records (double-mint).
        # Fail loudly instead of guessing.
        if self._replay_offset > st_size:
            raise SMPRefusal(
                "WAL INTEGRITY FAILURE: read offset beyond WAL size "
                f"({self._replay_offset} > {st_size}) — WAL replaced or "
                "truncated mid-run; refusing — restore the WAL from backup")
        with open(self._path, "rb") as fh:
            fh.seek(self._replay_offset)
            rest = fh.read()
        if rest:
            # Torn-tail tolerance (harden-A rule, applied mid-run): we
            # hold the xproc lock, so no other process is writing; a
            # trailing partial line is a crashed peer's remnant — drop it
            # crash-safely exactly like _replay does, instead of bricking
            # every gateway on one peer's crash. A corrupt MIDDLE line
            # still refuses loudly.
            chunks: list[tuple[int, bytes]] = []
            off = self._replay_offset
            for chunk in rest.split(b"\n"):
                chunks.append((off, chunk))
                off += len(chunk) + 1
            ends_with_nl = rest.endswith(b"\n")
            lineno = self._replay_lines
            idx = 0
            total = len(chunks)
            repaired_tail = False
            while idx < total:
                start, chunk = chunks[idx]
                idx += 1
                if not chunk.strip():
                    continue
                lineno += 1
                try:
                    op = self._parse_line(chunk, lineno)
                except SMPRefusal:
                    if idx == total and not ends_with_nl:
                        # Final chunk, no trailing newline: torn tail from
                        # a crashed peer (lock is held — safe to repair).
                        with open(self._path, "r+b") as fh2:
                            fh2.truncate(start)
                            fh2.flush()
                            os.fsync(fh2.fileno())
                        self.alerts.append(
                            f"WAL torn tail at line {lineno}: dropped a "
                            f"crashed peer's partial append; hash chain "
                            f"verified through the preceding lines")
                        repaired_tail = True
                        break
                    raise
                if op is not None:
                    self._apply_record(op, lineno, chunk)
            if not repaired_tail and not ends_with_nl and chunks and chunks[-1][1].strip():
                # Complete final record whose trailing newline never
                # landed (peer crashed between line bytes and newline).
                # The record verified, so keep it and restore the newline
                # before any append concatenates onto it.
                with open(self._path, "ab") as fh2:
                    fh2.write(b"\n")
                    fh2.flush()
                    os.fsync(fh2.fileno())
                self.alerts.append(
                    "WAL tail: final record was missing its trailing "
                    "newline (peer's interrupted append); newline "
                    "restored, no records lost")
            # Resync the cursor to the true end (post-repair).
            self._replay_offset = os.path.getsize(self._path)
            self._replay_lines = lineno
            self._update_pending_watch()
        self._recheck_pending_watch()

    def _update_pending_watch(self) -> None:
        """(Re)build the set of dedup_keys whose records still need an
        owner: PENDING decided records and undecided intent records."""
        for dk, rec in self.decided.items():
            if (rec.get("state") == "PENDING" and not rec.get("orphaned")
                    and rec.get("owner_pid") is not None):
                self._pending_watch.add(dk)
        for dk in self.intents:
            if dk not in self.decided:
                self._pending_watch.add(dk)

    def _recheck_pending_watch(self) -> None:
        """Orphan watched records whose owner pid is dead.

        This is what makes the single-mint guarantee SURVIVE crashes: a
        PENDING record from a process that died mid-mint is detected on
        the next refresh (or restart) and orphaned, so a later submit of
        the same intent gets a fresh ASK instead of blocking forever on a
        dead owner's PENDING — or worse, a second mint racing the corpse.
        """
        now = time.monotonic()
        for dk in list(self._pending_watch):
            rec = (self.decided.get(dk)
                   if dk in self.decided else self.intents.get(dk))
            if rec is None:
                self._pending_watch.discard(dk)
                continue
            owner = rec.get("owner_pid")
            if owner is None:
                # Pre-harden-B record (no owner stamped): cannot tell;
                # leave it — the restart-orphan path still covers it.
                self._pending_watch.discard(dk)
                continue
            if owner == os.getpid():
                continue  # our own records are watched by us, alive
            last = self._live_pids.get(owner)
            if last is None or now - last > 60.0:
                alive = _pid_alive(owner)
                if alive:
                    self._live_pids[owner] = now
                    continue
                self._live_pids.pop(owner, None)
            else:
                continue
            # Owner is dead: orphan the record so the intent can proceed.
            self._pending_watch.discard(dk)
            self.mark_orphaned(
                dk, f"owner pid {owner} died mid-mint; record orphaned so "
                    "a later submit gets a fresh ASK (harden-B)")

    @contextlib.contextmanager
    def xproc_section(self):
        """Cross-process critical section.

        Ordering (per key, then OS lock) is FIXED: the gateway always
        takes its per-dedup_key lock first and enters xproc_section
        second; nothing inside ever takes a per-key lock, so the order
        cannot invert and deadlock is impossible by construction.
        Reentrant within a thread (threading.RLock); flock() is
        acquired/released on the outermost entry/exit of each thread.
        """
        tid = threading.get_ident()
        with self._xproc_rlock:
            depth = self._xproc_depths.get(tid, 0)
            if depth == 0:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
                try:
                    self._refresh()
                except BaseException:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    raise
            self._xproc_depths[tid] = depth + 1
        try:
            yield
        finally:
            with self._xproc_rlock:
                depth = self._xproc_depths.get(tid, 0)
                if depth <= 1:
                    self._xproc_depths.pop(tid, None)
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                else:
                    self._xproc_depths[tid] = depth - 1

    def write_intent(self, *, dedup_key: str, nonce: str,
                     original_verb: str, action_digest: str,
                     event_id: str, owner_pid: int | None = None) -> None:
        rec = {"op": "intent", "dedup_key": dedup_key, "nonce": nonce,
               "original_verb": original_verb,
               "translated_action_digest": action_digest,
               "event_id": event_id, "owner_pid": owner_pid}
        self._append(rec)
        self.intents[dedup_key] = rec

    def write_decided(self, *, dedup_key: str, state: str,
                      capability_id: str | None,
                      statement_hash: str | None = None,
                      pending_id: str | None = None,
                      ask_digest: str | None = None,
                      envelope_json: dict | None = None,
                      decision_json: dict | None = None,
                      pending_fingerprint: str | None = None,
                      fingerprint: str | None = None,
                      ts: float | None = None,
                      owner_pid: int | None = None) -> None:
        # harden-C: fingerprint = clock-independent intent identity (v11d),
        # stored on every decided record so the cross-bucket carry-over can
        # find the previous quantum's decision; ts = epoch seconds of the
        # quantum the decision belongs to — the submit path stamps
        # translate time (ti.event.ts), i.e. the dedup_key's own bucket by
        # construction, so a stall between translate and mint cannot shift
        # the record into the wrong bucket. Old WAL records lack both
        # fields and simply never carry (safe).
        # harden-B: owner_pid stamps the process that minted the record,
        # so a crashed owner's PENDING/intent can be orphaned by the next
        # refresh instead of blocking (or double-minting) forever.
        rec = {"op": "decided", "dedup_key": dedup_key, "state": state,
               "capability_id": capability_id,
               "statement_hash": statement_hash, "pending_id": pending_id,
               "ask_digest": ask_digest, "envelope": envelope_json,
               "decision": decision_json,
               "pending_fingerprint": pending_fingerprint,
               "fingerprint": fingerprint, "ts": ts,
               "owner_pid": owner_pid}
        self._append(rec)
        self.decided[dedup_key] = rec

    def pending_fingerprint_hit(self, fingerprint: str) -> str | None:
        """Clock-independent pending-duplicate check (v11d fix for the
        cross-bucket §6.4 bypass). The dedup_key is bucket-scoped, so a
        duplicate of a still-pending intent submitted after a bucket roll
        computes a different key and misses the PENDING record. The
        fingerprint identifies the logical intent without any clock input;
        return the dedup_key of a still-PENDING record with this
        fingerprint, else None. O(n) scan — only used on the dedup-key
        cache-miss path."""
        for key, rec in self.decided.items():
            # v11e (F2c): orphaned PENDING records (ASK lost to a restart)
            # no longer block resubmission.
            if (rec.get("state") == "PENDING"
                    and not rec.get("orphaned")
                    and rec.get("pending_fingerprint") == fingerprint):
                return key
        return None

    def decided_carry_hit(self, fingerprint: str, *, now_ts: float,
                          quantum: float) -> dict | None:
        """harden-C: cross-bucket dedup carry-over scan. The §6.2 dedup_key
        is bucket-scoped, so the identical intent resubmitted in the next
        quantum computes a different key and would mint a second
        capability. Return a decided record for the same logical intent
        (clock-independent fingerprint) from the immediately previous
        quantum ONLY — one extra quantum, never more. ALLOW/DENY both
        scan here; the caller additionally requires a carried ALLOW's
        capability to verify as live right now (see _carry_live) — a
        stale/expired capability is never returned as fresh. O(n) scan —
        only used on the dedup-key cache-miss path, after the §6.4
        pending-duplicate guard."""
        cur_bucket = math.floor(now_ts / quantum)
        for _key, rec in list(self.decided.items()):
            if rec.get("fingerprint") != fingerprint:
                continue
            if rec.get("state") not in ("ALLOW", "DENY"):
                continue
            ts = rec.get("ts")
            if not isinstance(ts, (int, float)):
                continue  # pre-carry record (WAL replay) -> no carry
            if math.floor(ts / quantum) != cur_bucket - 1:
                continue
            return rec
        return None

    def mark_orphaned(self, dedup_key: str, why: str) -> None:
        self._append({"op": "orphaned", "dedup_key": dedup_key, "why": why})
        rec = self.decided.get(dedup_key, {"dedup_key": dedup_key})
        rec["orphaned"] = True
        self.decided[dedup_key] = rec
        self.alerts.append(f"ORPHANED intent {dedup_key[:16]}…: {why}")

    def record_scitt_outage(self, why: str) -> int:
        """§5.2: durably record one SCITT statement-write failure and return
        the new monotonic scitt_outage count (fsync'd WAL; survives
        restarts via replay)."""
        # harden-B: the outage counter is shared state; the increment and
        # the append must be atomic across processes or two processes can
        # write the same count (monotonicity break). Reentrant-safe: the
        # callers that already hold the section (submit paths) nest.
        with self.xproc_section():
            self.scitt_outage += 1
            self._append({"op": "scitt_outage", "count": self.scitt_outage,
                          "why": why})
            return self.scitt_outage

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
        try:
            os.close(self._lock_fd)
        except Exception:
            pass


def _freeze_decision(d: GuardianDecision) -> dict:
    """JSON-safe GuardianDecision: bytes capability -> hex wrapper."""
    data = d.model_dump()
    cap = data.get("capability")
    if cap is not None:
        data["capability"] = {"__bytes_hex__": bytes(cap).hex()}
    return data


def _thaw_decision(d: dict) -> GuardianDecision:
    d = dict(d)
    cap = d.get("capability")
    if isinstance(cap, dict) and "__bytes_hex__" in cap:
        d["capability"] = bytes.fromhex(cap["__bytes_hex__"])
    return GuardianDecision.model_validate(d)


class SmpGateway:
    """Sole caller of guardian.handle_event / guardian.resolve_pending (§1.5).

    R6: per-dedup_key lock held across translate->mint->emit; decided hit ->
    cached result; PENDING duplicate -> DENY "event pending approval".

    harden-B: the check-and-mint and ASK-resolve critical sections are ALSO
    cross-process sections (DecisionLog.xproc_section: flock + WAL refresh),
    so N gateway processes against one WAL still mint exactly once per
    dedup_key. Lock order is fixed everywhere: per-key lock first,
    xproc_section second.
    """

    def __init__(self, *, guardian: AcsGuardian, adapter: ShimAdapter,
                 issuer_trusted: dict, wal_path: Path,
                 now_fn=None):
        self._guardian = guardian
        self._adapter = adapter
        self._issuer_trusted = dict(issuer_trusted)
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._dlog = DecisionLog(wal_path)
        self._meta_lock = threading.Lock()
        # Per-key locks: key -> [threading.Lock, last_touch_monotonic].
        # last_touch uses time.monotonic() (NOT self._now(): the injectable
        # clock may be frozen in tests and must never gate reclamation).
        self._inflight: dict[str, list] = {}
        self._key_locks: dict[str, list] = {}
        # -- TTL eviction of per-key locks (memory hardening) ----------------
        # Entries idle longer than _lock_ttl_s (2x the 300s dedup quantum)
        # are eligible for eviction. A single maintenance pass reclaims them
        # opportunistically (at most every _lock_sweep_interval_s on the hot
        # path) or on demand via evict_stale_locks().
        self._lock_ttl_s = 600.0
        self._lock_sweep_interval_s = 60.0
        self._last_lock_sweep = time.monotonic()
        self._pending_by_id: dict[str, dict] = {}  # gw pending_id -> record
        self._crash_after_mint = False    # test hooks (crash-window probe)
        self._crash_before_mint = False
        self._seq = 0
        # §5.2: the adapter's SCITT-outage reporting is wired into THIS
        # Gateway's local durable decision log (monotonic scitt_outage
        # counter + operator alerts).
        adapter.attach_outage_log(
            record_fn=self._dlog.record_scitt_outage,
            alert_fn=self._dlog.alerts.append)

    

# -- locking -------------------------------------------------------------
    def _lock_entry(self, store: dict, key: str) -> threading.Lock:
        """Get-or-create the per-key lock, refreshing its touch timestamp.

        Opportunistically runs one eviction sweep (at most every
        _lock_sweep_interval_s). Caller must hold NO locks.
        """
        now = time.monotonic()
        with self._meta_lock:
            ent = store.get(key)
            if ent is None:
                ent = [threading.Lock(), now]
                store[key] = ent
            else:
                ent[1] = now
            if now - self._last_lock_sweep >= self._lock_sweep_interval_s:
                self._last_lock_sweep = now
                self._evict_stale_locks_locked(now)
            return ent[0]

    def _inflight_lock(self, key: str) -> threading.Lock:
        return self._lock_entry(self._inflight, key)

    def _key_lock(self, key: str) -> threading.Lock:
        return self._lock_entry(self._key_locks, key)

    @contextlib.contextmanager
    def _held_lock(self, store: dict, key: str):
        """Acquire the per-key lock with post-acquire identity revalidation.

        INVARIANT: a lock object is authoritative for a key ONLY while it is
        the mapped entry in `store`. Eviction deletes an entry only when its
        lock is uncontended (non-blocking acquire while holding _meta_lock,
        so no lookup can interleave). A thread that fetched a lock object
        before an eviction may still acquire that STALE object — so after
        acquiring we re-check, under _meta_lock, that the store still maps
        key -> this exact lock; on mismatch we release the stale lock and
        retry on a fresh lookup. A stale lock therefore never guards a
        critical section: two threads can never hold different locks for
        the same key, so dedup mutual exclusion (no double mint) survives
        eviction. Deadlock-free: the evictor never blocks on a key lock
        (acquire(blocking=False)); key locks are always acquired before
        _meta_lock, never while holding it.
        """
        while True:
            lock = self._lock_entry(store, key)
            lock.acquire()
            with self._meta_lock:
                ent = store.get(key)
                if ent is not None and ent[0] is lock:
                    break
            # Evicted between lookup and acquire: release the stale lock
            # and retry against a fresh entry.
            lock.release()
        try:
            yield lock
        finally:
            with self._meta_lock:
                ent = store.get(key)
                if ent is not None and ent[0] is lock:
                    ent[1] = time.monotonic()
            lock.release()

    def _evict_stale_locks_locked(self, now: float) -> dict:
        """Single maintenance pass over both lock dicts.

        Caller holds _meta_lock. Reclaims entries idle longer than
        _lock_ttl_s whose lock is uncontended. Returns eviction counts.
        """
        ttl = self._lock_ttl_s
        evicted = {"inflight": 0, "key_locks": 0}
        for store, name in ((self._inflight, "inflight"),
                            (self._key_locks, "key_locks")):
            stale = [k for k, ent in store.items() if now - ent[1] >= ttl]
            for k in stale:
                ent = store.get(k)
                if ent is None or now - ent[1] < ttl:
                    continue
                # Evict ONLY if uncontended: a held lock fails the
                # non-blocking acquire and survives this pass.
                if ent[0].acquire(blocking=False):
                    try:
                        if store.get(k) is ent:
                            del store[k]
                            evicted[name] += 1
                    finally:
                        ent[0].release()
        return evicted

    def evict_stale_locks(self) -> dict:
        """Public maintenance pass: reclaim per-key locks idle longer than
        _lock_ttl_s. Safe to call any time, including concurrently with
        submissions; never evicts a held or contended lock."""
        with self._meta_lock:
            return self._evict_stale_locks_locked(time.monotonic())

    @staticmethod
    def _intent_fingerprint(*, principal: str, plane: str, verb: str,
                            target: str, params: dict,
                            registry_digest: str) -> str:
        """Clock-independent identity of a logical intent (v11d: §9.2 ASK-time
        binding and the §6.4 cross-bucket pending-duplicate guard). Two
        submissions name the same logical intent iff their fingerprints
        match — no clock input, so bucket rolls can neither split nor merge
        intent identity."""
        return hashlib.sha256(cbor_dumps(
            [principal, plane, verb, target, sha256_hex(params),
             registry_digest])).hexdigest()

    # -- helpers ---------------------------------------------------------------
    def _deny_result(self, event_id: str, reason: str, status: str,
                     dedup_key: str | None = None) -> SmpResult:
        return SmpResult(
            decision=GuardianDecision(event_id=event_id, decision="DENY",
                                      reason=reason),
            envelope=None, status=status, dedup_key=dedup_key)

    def _capability_id(self, decision: GuardianDecision) -> str | None:
        if decision.decision not in ("ALLOW", "MODIFY") or not decision.capability:
            return None
        payload = authority.verify_capability(
            decision.capability, self._issuer_trusted, now=self._now())
        return payload.capability_id

    def _store_result(self, ti: TranslatedIntent,
                      decision: GuardianDecision) -> SmpResult:
        cap_id = self._capability_id(decision)
        if decision.decision == "ASK":
            status = "ask_pending"
        elif decision.decision in ("ALLOW", "MODIFY"):
            status = "hit_allow"
        else:
            status = "hit_deny"
        return SmpResult(decision=decision, envelope=ti.envelope,
                         status=status, dedup_key=ti.dedup_key)

    # -- main path -------------------------------------------------------------
    def submit_intent(self, *, plane: str, verb: str, target: str,
                      principal: str, params: dict,
                      event_type: str = "pre_tool_call",
                      session_id: str = "sess-smp") -> SmpResult:
        """Full pipeline: translate -> dedup -> intent record -> mint ->
        statement. Returns cached result on dedup hit (R6)."""
        intake_id = hashlib.sha256(cbor_dumps(
            [principal, plane, verb, target, sha256_hex(params)])).hexdigest()
        event_id = f"smp-{secrets.token_hex(8)}"
        with self._held_lock(self._inflight, intake_id):
            try:
                ti = self._adapter.translate(
                    plane=plane, verb=verb, target=target, principal=principal,
                    params=params, event_id=event_id, event_type=event_type,
                    session_id=session_id)
            except SMPRefusal as exc:
                # Adapter already emitted the deny/error statement (§7) —
                # unless the emit itself failed (§5.2: outage recorded, the
                # DENY still stands, no statement attempted about the
                # failed emit).
                status = ("error" if "error" in str(exc).lower()
                          or "malformed" in str(exc).lower()
                          else "deny")
                return self._deny_result(event_id, str(exc), status)
            # v11d: clock-independent identity of this logical intent, for
            # the §6.4 cross-bucket pending-duplicate guard below and the
            # ASK record's §9.2 binding.
            intent_fingerprint = self._intent_fingerprint(
                principal=principal, plane=plane, verb=verb,
                target=target, params=params,
                registry_digest=self._adapter.registry.digest)
            # harden-C: no extra lock needed for cross-bucket
            # serialization — _held_lock(self._inflight, intake_id) already
            # wraps this whole section and intake_id is clock-independent,
            # so identical intents are fully ordered even across a bucket
            # roll; a post-roll submit always observes the pre-roll
            # submit's completed decided record.
            # harden-B: the check-and-mint critical section is ALSO a
            # cross-process section: the WAL is refreshed on xproc_section
            # entry (so the decided/intent reads below see other processes'
            # records) and our appends cannot fork the chain. Lock order is
            # fixed: per-key lock first, xproc_section second.
            with self._held_lock(self._key_locks, ti.dedup_key), \
                    self._dlog.xproc_section():
                return self._submit_under_key_lock(
                    ti=ti, event_id=event_id,
                    intent_fingerprint=intent_fingerprint,
                    plane=plane, verb=verb, target=target,
                    principal=principal, params=params,
                    event_type=event_type, session_id=session_id)

    def _submit_under_key_lock(self, *, ti, event_id,
                                   intent_fingerprint, plane, verb,
                                   target, principal, params,
                                   event_type, session_id) -> SmpResult:
        """Check-and-mint critical section.

        harden-B: called with the per-dedup_key lock AND the
        cross-process xproc_section held (so the WAL is
        freshly refreshed: the decided/intent reads below see other
        processes' records, and our appends cannot fork the chain).
        """
        rec = self._dlog.decided.get(ti.dedup_key)
        if rec is not None:
            state = rec.get("state")
            if state in ("ALLOW", "DENY"):
                # R6/§6.3: return the stored result — no second
                # handle_event, no raise.
                stored = self._rehydrate(rec, ti)
                stored.from_cache = True
                return stored
            if state == "PENDING" and not rec.get("orphaned"):
                # §6.4: duplicate while pending -> DENY.
                # v11e (F2c): an orphaned PENDING (ASK lost to a
                # restart) no longer blocks — it falls through to
                # a fresh ASK below.
                return self._deny_result(
                    event_id, "event pending approval",
                    "deny_pending_duplicate", ti.dedup_key)
        else:
            # v11d fix (critic finding d): the dedup_key is
            # bucket-scoped, so a duplicate of a still-pending intent
            # submitted after a bucket roll computes a different key
            # and misses the PENDING record above → second ASK for
            # one intent. The fingerprint is clock-independent: deny
            # duplicates of any still-pending intent regardless of
            # bucket. Only on the dedup-key cache-miss path.
            if self._dlog.pending_fingerprint_hit(
                    intent_fingerprint) is not None:
                return self._deny_result(
                    event_id, "event pending approval",
                    "deny_pending_duplicate", ti.dedup_key)
            # harden-C: cross-bucket dedup carry-over. The
            # dedup_key is bucket-scoped (§6.2), so the identical
            # intent resubmitted after a bucket roll misses the
            # decided record above and would mint a second
            # capability. Carry over a decided ALLOW/DENY from
            # the immediately previous quantum only (one extra
            # quantum) — no second mint. A carried ALLOW is
            # returned only while its capability verifies as
            # live right now; otherwise fall through to a fresh
            # kernel mint below.
            carry = self._dlog.decided_carry_hit(
                intent_fingerprint,
                now_ts=self._adapter._now().timestamp(),
                quantum=self._adapter._window_quantum_sec)
            if carry is not None and self._carry_live(carry):
                # harden-C: pin the carried ALLOW under the new
                # bucket's dedup_key so the carry chains across
                # consecutive buckets — each submit leaves a
                # one-quantum trail. The chain self-terminates:
                # _carry_live re-verifies the ORIGINAL capability
                # every hop, so it extends only while that
                # capability is live (bounded by its TTL; with the
                # default quantum == TTL this is at most one extra
                # hop). DENY is deliberately NOT pinned: a deny
                # carries exactly one extra quantum, then a resubmit
                # gets a fresh kernel evaluation (policy may have
                # flipped to ALLOW; an unbounded deny chain would
                # suppress that forever).
                if carry.get("state") == "ALLOW":
                    self._dlog.write_decided(
                        dedup_key=ti.dedup_key,
                        state=carry.get("state"),
                        capability_id=carry.get("capability_id"),
                        statement_hash=carry.get("statement_hash"),
                        pending_id=carry.get("pending_id"),
                        ask_digest=carry.get("ask_digest"),
                        envelope_json=carry.get("envelope"),
                        decision_json=carry.get("decision"),
                        pending_fingerprint=carry.get(
                            "pending_fingerprint"),
                        fingerprint=intent_fingerprint,
                        ts=self._now().timestamp())
                stored = self._rehydrate(carry, ti)
                stored.from_cache = True
                return stored
        # §7.5(2): write-ahead intent record BEFORE the mint.
        # harden-B: stamp the owner pid so a crashed owner's PENDING can
        # be orphaned by the next refresh instead of blocking forever.
        self._dlog.write_intent(
            dedup_key=ti.dedup_key, nonce=ti.envelope.nonce,
            original_verb=verb,
            action_digest=ti.envelope.action_digest, event_id=event_id,
            owner_pid=os.getpid())
        if self._crash_before_mint:
            raise SimulatedCrash("crash between intent record and mint")
        # §7.5(3): mint.
        decision = self._guardian.handle_event(
            ti.event, presented_envelope=ti.envelope)
        cap_id = self._capability_id(decision)
        # Durably record the decision BEFORE the statement emit, so
        # the §7.6 reconciler can re-emit after a crash (§7.5 order).
        if decision.decision == "ASK":
            gw_pid = f"gw-{secrets.token_hex(8)}"
            self._dlog.write_decided(
                dedup_key=ti.dedup_key, state="PENDING",
                capability_id=None, pending_id=decision.pending_id,
                ask_digest=ti.envelope.action_digest,
                envelope_json=ti.envelope.model_dump(mode="json"),
                decision_json=_freeze_decision(decision),
                pending_fingerprint=intent_fingerprint,
                fingerprint=intent_fingerprint,
                ts=ti.event.ts.timestamp(),
                owner_pid=os.getpid())
            self._pending_by_id[gw_pid] = {
                "dedup_key": ti.dedup_key,
                "kernel_pending_id": decision.pending_id,
                "ask_digest": ti.envelope.action_digest,
                "envelope": ti.envelope,
                "entry_id": ti.entry.entry_id,
                "intent": {"plane": plane, "verb": verb,
                           "target": target, "principal": principal,
                           "params": dict(params),
                           "event_type": event_type,
                           "session_id": session_id},
            }
            try:
                self._adapter.emit_allow(
                    envelope=ti.envelope, entry=ti.entry,
                    principal=principal, verb=verb, target=target,
                    capability_id=None, dedup_key=ti.dedup_key,
                    pending_note=f"ASK pending: {decision.reason}")
            except Exception:
                pass  # §5.2: outage recorded by the adapter; the
                      # PENDING record is durable and the approval
                      # flow continues (translation continues)
            result = self._store_result(ti, decision)
            result.status = "ask_pending"
            # surface the gateway pending id to the caller
            result.decision = GuardianDecision(
                event_id=decision.event_id, decision="ASK",
                reason=decision.reason, pending_id=gw_pid)
            return result
        state = "ALLOW" if decision.decision in ("ALLOW", "MODIFY") \
            else "DENY"
        self._dlog.write_decided(
            dedup_key=ti.dedup_key, state=state,
            capability_id=cap_id,
            envelope_json=ti.envelope.model_dump(mode="json"),
            decision_json=_freeze_decision(decision),
            fingerprint=intent_fingerprint,
            ts=ti.event.ts.timestamp())
        if self._crash_after_mint:
            raise SimulatedCrash("crash between mint and statement")
        # §7.5(4): SCITT statement with the real capability_id.
        # §5.2: a post-mint emit failure does NOT roll back the mint
        # (no kernel revocation exists, B1). The outage is recorded
        # by the adapter; the decided record (with capability_id)
        # is durable, so the §7.6 reconciler re-emits the statement.
        stmt_hash = None
        try:
            stmt = self._adapter.emit_allow(
                envelope=ti.envelope, entry=ti.entry,
                principal=principal, verb=verb, target=target,
                capability_id=cap_id or "", dedup_key=ti.dedup_key,
                pending_note=(None if state == "ALLOW"
                              else f"guardian denied: "
                                   f"{decision.reason}"))
            stmt_hash = hashlib.sha256(stmt).hexdigest()
        except Exception:
            pass
        self._dlog.write_decided(
            dedup_key=ti.dedup_key, state=state,
            capability_id=cap_id,
            statement_hash=stmt_hash,
            envelope_json=ti.envelope.model_dump(mode="json"),
            decision_json=_freeze_decision(decision),
            fingerprint=intent_fingerprint,
            ts=ti.event.ts.timestamp())
        return self._store_result(ti, decision)

    def _carry_live(self, rec: dict) -> bool:
        """harden-C: is a carried-over decided record still usable now?
        DENY carries unconditionally — the fail-closed direction matches
        in-bucket cached-deny semantics (a policy flip to ALLOW takes
        effect at most one quantum later, same staleness class as the
        existing per-bucket cache). ALLOW carries only while the minted
        capability verifies as live RIGHT NOW through the real authority
        verification path (signature + validity window): the envelope
        window is mint-time-only, the capability's expires_at is what
        gates execution, so a stale capability is never returned as
        fresh — on any verification failure the intent falls through to
        a fresh kernel mint."""
        if rec.get("state") != "ALLOW":
            return True
        dj = rec.get("decision") or {}
        cap_hex = (dj.get("capability") or {}).get("__bytes_hex__")
        if not cap_hex:
            return False
        try:
            authority.verify_capability(
                bytes.fromhex(cap_hex), self._issuer_trusted,
                now=self._now())
        except Exception:
            return False
        return True

    def _rehydrate(self, rec: dict, ti: TranslatedIntent) -> SmpResult:
        """Rebuild the cached SmpResult for a decided dedup_key (R6)."""
        dj = rec.get("decision") or {}
        ej = rec.get("envelope") or {}
        decision = _thaw_decision(dj) if dj else \
            GuardianDecision(event_id="cached", decision="DENY",
                             reason="cached deny")
        envelope = ActionEnvelope.model_validate(ej) if ej else ti.envelope
        status = ("hit_allow" if decision.decision in ("ALLOW", "MODIFY")
                  else "hit_deny")
        return SmpResult(decision=decision, envelope=envelope, status=status,
                         dedup_key=ti.dedup_key, from_cache=True)

    # -- resolve_pending path (§9) ---------------------------------------------
    def resolve_approval(self, gw_pending_id: str, approved: bool,
                         presented_envelope: ActionEnvelope | None = None
                         ) -> SmpResult:
        """ASK/DEFER approval through the identical Adapter validation (§9.1),
        plus the ASK-time digest re-check (§9.2)."""
        rec = self._pending_by_id.get(gw_pending_id)
        if rec is None:
            raise ValueError(f"unknown gateway pending_id {gw_pending_id!r}")
        dedup_key = rec["dedup_key"]
        intent = rec["intent"]
        event_id = f"smp-{secrets.token_hex(8)}"
        # §9.1: the identical translate() — duplicated logic is non-conformant.
        try:
            ti = self._adapter.translate(
                plane=intent["plane"], verb=intent["verb"],
                target=intent["target"], principal=intent["principal"],
                params=intent["params"], event_id=event_id,
                event_type=intent["event_type"],
                session_id=intent["session_id"])
        except SMPRefusal as exc:
            return self._deny_result(event_id,
                                     f"resolve validation failed: {exc}",
                                     "deny", dedup_key)
        # §9.2: ASK-time binding — the kernel doesn't provide this.
        if presented_envelope is not None:
            # Presented-envelope path: strict digest equality with the
            # ASK-time envelope (catches verb-swapped envelope smuggling).
            use_env = presented_envelope
            if use_env.action_digest != rec["ask_digest"]:
                try:
                    self._adapter.emit_deny(
                        status="error", reason="§9.2: presented envelope digest != "
                                               "ASK-time digest (verb-swapped envelope "
                                               "smuggling denied)",
                        plane=intent["plane"], verb=intent["verb"],
                        target=intent["target"], principal=intent["principal"],
                        params=intent["params"], dedup_key=dedup_key)
                except Exception:
                    pass  # §5.2: outage recorded; the DENY stands
                return self._deny_result(event_id, "ASK-time digest mismatch",
                                         "error", dedup_key)
        else:
            # Bare path (no presented envelope): the re-translated envelope
            # folds the CURRENT quantum bucket, so a strict digest comparison
            # would deny honest approvals after any bucket roll (v11d F1).
            # Bind on the clock-independent intent fingerprint instead: the
            # live re-translation must describe the same logical intent that
            # was ASKed (same principal/plane/verb/target/params/registry).
            # A verb/target swap since ASK (P26-style) changes the
            # fingerprint and is denied here; the mint then uses the durable
            # ASK-time envelope. The §9.1 re-translation above still
            # validates live registry state first.
            live_fingerprint = self._intent_fingerprint(
                principal=intent["principal"], plane=intent["plane"],
                verb=intent["verb"], target=intent["target"],
                params=intent["params"],
                registry_digest=self._adapter.registry.digest)
            ask_record = self._dlog.decided.get(dedup_key)
            if (ask_record is None or ask_record.get("state") != "PENDING"
                    or ask_record.get("pending_fingerprint")
                    != live_fingerprint):
                try:
                    self._adapter.emit_deny(
                        status="error",
                        reason="§9.2: live re-translation does not match the "
                               "ASK-time intent (verb/target/params changed "
                               "since ASK?)",
                        plane=intent["plane"], verb=intent["verb"],
                        target=intent["target"], principal=intent["principal"],
                        params=intent["params"], dedup_key=dedup_key)
                except Exception:
                    pass  # §5.2: outage recorded; the DENY stands
                return self._deny_result(event_id, "ASK-time intent mismatch",
                                         "error", dedup_key)
            use_env = rec["envelope"]  # durable ASK-time envelope
            if use_env.action_digest != rec["ask_digest"]:
                return self._deny_result(
                    event_id, "ASK-time envelope corrupted", "error",
                    dedup_key)
        # harden-B: the resolve critical section is ALSO a cross-process
        # section: refresh the WAL on xproc_section entry so the
        # ask_record read below sees other processes' PENDING records.
        # Lock order is fixed: per-key lock first, xproc_section second.
        with self._held_lock(self._key_locks, dedup_key), \
                self._dlog.xproc_section():
            return self._resolve_under_section(
                rec=rec, ti=ti, intent=intent, dedup_key=dedup_key,
                event_id=event_id, gw_pending_id=gw_pending_id,
                use_env=use_env, approved=approved)

    def _resolve_under_section(self, *, rec, ti, intent,
                                   dedup_key, event_id, gw_pending_id,
                                   use_env, approved) -> SmpResult:
        """ASK resolve critical section.

        harden-B: called with the per-dedup_key lock AND the
        cross-process xproc_section held (so the WAL is
        freshly refreshed: the ask_record read below sees other
        processes' PENDING records).
        """
        drec = self._dlog.decided.get(dedup_key)
        if not drec or drec.get("state") != "PENDING":
            return self._deny_result(event_id, "event already decided",
                                     "deny", dedup_key)
        if not approved:
            decision = self._guardian.resolve_pending(
                rec["kernel_pending_id"], False)
            self._dlog.write_decided(
                dedup_key=dedup_key, state="DENY", capability_id=None,
                envelope_json=use_env.model_dump(mode="json"),
                decision_json=_freeze_decision(decision),
                fingerprint=drec.get("fingerprint") if drec else None,
                ts=self._now().timestamp())
            self._pending_by_id.pop(gw_pending_id, None)
            try:
                self._adapter.emit_deny(
                    status="deny_unmapped", plane=intent["plane"],
                    verb=intent["verb"], target=intent["target"],
                    principal=intent["principal"], params=intent["params"],
                    reason=f"ASK rejected by approver: {decision.reason}",
                    dedup_key=dedup_key, entry_id=rec["entry_id"],
                    acs_action=ti.entry.acs_action,
                    acs_resource=ti.entry.acs_resource)
            except Exception:
                pass  # §5.2: outage recorded; the DENY stands
            return self._deny_result(event_id, decision.reason, "deny",
                                     dedup_key)
        decision = self._guardian.resolve_pending(
            rec["kernel_pending_id"], True,
            presented_envelope=use_env)
        cap_id = self._capability_id(decision)
        state = "ALLOW" if decision.decision in ("ALLOW", "MODIFY") \
            else "DENY"
        self._dlog.write_decided(
            dedup_key=dedup_key, state=state, capability_id=cap_id,
            envelope_json=use_env.model_dump(mode="json"),
            decision_json=_freeze_decision(decision))
        # §5.2: post-resolve emit failure does not roll back the resolve;
        # the decided record is durable and the §7.6 reconciler re-emits.
        stmt_hash = None
        try:
            stmt = self._adapter.emit_allow(
                envelope=use_env, entry=ti.entry,
                principal=intent["principal"],
                verb=intent["verb"], target=intent["target"],
                capability_id=cap_id or "", dedup_key=dedup_key)
            stmt_hash = hashlib.sha256(stmt).hexdigest()
        except Exception:
            pass
        self._dlog.write_decided(
            dedup_key=dedup_key, state=state, capability_id=cap_id,
            statement_hash=stmt_hash,
            envelope_json=use_env.model_dump(mode="json"),
            decision_json=_freeze_decision(decision),
            fingerprint=drec.get("fingerprint") if drec else None,
            ts=self._now().timestamp())
        self._pending_by_id.pop(gw_pending_id, None)
        return SmpResult(decision=decision, envelope=use_env,
                         status="hit_allow" if state == "ALLOW"
                         else "hit_deny",
                         dedup_key=dedup_key)

    # -- §7.6 reconciler ----------------------------------------------------------
    def reconcile(self) -> dict:
        """Detect intent records with no matching statement; re-emit or mark
        orphaned. Returns a summary dict."""
        # harden-B: cross-process lock + refresh so the intent/decided scan
        # sees every process's records and the re-emit/orphan appends cannot
        # fork the hash chain.
        with self._dlog.xproc_section():
            return self._reconcile_under_section()

    def _reconcile_under_section(self) -> dict:
        """reconcile() body; runs under xproc_section (see reconcile)."""
        summary = {"re_emitted": [], "orphaned": [], "tamper": []}
        stated_keys = set()
        for stmt in self._adapter._statements:
            try:
                view = parse_statement(stmt, self._adapter.trusted_issuers)
                dk = (view["claims"] or {}).get("dedup_key")
                if dk:
                    stated_keys.add(dk)
            except Exception:
                continue
        for dk, intent in self._dlog.intents.items():
            if dk in stated_keys:
                continue
            drec = self._dlog.decided.get(dk, {})
            cap_id = drec.get("capability_id")
            if drec.get("state") in ("ALLOW", "MODIFY") and cap_id:
                # §7.6(a): re-emit deterministically; fresh nonce, chained.
                env = ActionEnvelope.model_validate(drec["envelope"])
                stmt = self._adapter._emit_statement(
                    action_digest=env.action_digest,
                    claims={
                        "translation_status": "hit",
                        "orchestrator_id": "reconciler",
                        "original_verb": intent.get("original_verb"),
                        "original_target": None,
                        "translated_verb": None,
                        "translated_target": None,
                        "acs_action": None,
                        "acs_resource": None,
                        "registry_entry_id": None,
                        "action_digest": env.action_digest,
                        "capability_id": cap_id,
                        "dedup_key": dk,
                        "deny_reason": "re-emitted by §7.6 reconciler "
                                       "(crash between mint and emit)",
                    })
                self._dlog.write_decided(
                    dedup_key=dk, state=drec["state"], capability_id=cap_id,
                    statement_hash=hashlib.sha256(stmt).hexdigest(),
                    envelope_json=drec.get("envelope"),
                    decision_json=drec.get("decision"),
                    fingerprint=drec.get("fingerprint"),
                    ts=drec.get("ts"))
                summary["re_emitted"].append(dk)
            elif not drec or drec.get("state") not in ("ALLOW", "MODIFY",
                                                       "DENY", "PENDING"):
                # §7.6(b): mint never completed -> ORPHANED + alert.
                self._dlog.mark_orphaned(
                    dk, "intent record without decided entry: mint never "
                        "completed (§7.6b)")
                summary["orphaned"].append(dk)
        return summary

    def close(self) -> None:
        self._dlog.close()

# ---------------------------------------------------------------------------
# Deployment bootstrap helper (used by the probe suite)
# ---------------------------------------------------------------------------

@dataclass
class Deployment:
    owner: Ed25519Signer
    translation_signer: Ed25519Signer
    log_signer: Ed25519Signer
    guardian_issuer: Ed25519Signer
    holder: Ed25519Signer
    subject: str
    trusted: dict
    registry: MappingRegistry
    adapter: ShimAdapter
    guardian: AcsGuardian
    gateway: SmpGateway
    registry_doc: dict
    pin: dict
    registry_path: Path
    pin_path: Path


def default_entries() -> list[dict]:
    return [
        {"entry_id": "e001", "plane": "shell",
         "qualified_verb": "anchor:shell/exec",
         "target_shape": {"kind": "exact", "value": "/usr/bin/backup"},
         "presented_verb": "anchor:shell/exec",
         "acs_action": "anchor:acs/backup.run",
         "acs_resource": "backup:host-a"},
        {"entry_id": "e002", "plane": "shell",
         "qualified_verb": "anchor:shell/backup-ask",
         "target_shape": {"kind": "exact", "value": "/usr/bin/backup-ask"},
         "presented_verb": "anchor:shell/backup-ask",
         "acs_action": "anchor:acs/backup.ask",
         "acs_resource": "backup:host-a"},
        {"entry_id": "e003", "plane": "shell",
         "qualified_verb": "anchor:shell/read",
         "target_shape": {"kind": "prefix", "value": "/var/log/"},
         "presented_verb": "anchor:shell/read",
         "acs_action": "anchor:acs/log.read",
         "acs_resource": "logs:host-a"},
    ]


def build_deployment(*, workdir: Path, entries: list[dict] | None = None,
                     version: str = "2026-09-23-r1",
                     decision_fn=None,
                     now_fn=None,
                     scitt_outage_threshold: int = 3,
                     window_quantum_sec: float = 300.0) -> Deployment:
    """Stand up a full deployment: keys, signed registry + pin, adapter,
    guardian, gateway. All real modules.

    scitt_outage_threshold: §5.2 deployment config — accumulated SCITT
    statement-write failures at or beyond this count latch the adapter
    refuse-all + raise an operator alert."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    owner = Ed25519Signer.generate("deploy/registry-owner-01")
    translation_signer = Ed25519Signer.generate(
        "smp-translation-log/test/2026")
    log_signer = Ed25519Signer.generate("test-transparency-log/2026")
    guardian_issuer = Ed25519Signer.generate("guardian-smp")
    holder = Ed25519Signer.generate("agent-holder")
    subject = holder.public_key_b64()
    trusted = {guardian_issuer.key_id.encode("utf-8"):
               Ed25519PublicKey.from_public_bytes(
                   guardian_issuer.public_key_bytes())}

    entries = default_entries() if entries is None else entries
    payload = build_registry_payload(
        version=version, owner_key_id=owner.key_id,
        spiffe_id="spiffe://deploy/registry-owner",
        entries=entries, issued_at=now_fn().isoformat())
    registry_doc = sign_registry(payload, owner)
    pin = make_pin(version=version,
                   payload_hash_sha256=hashlib.sha256(
                       canonical_bytes(payload)).hexdigest(),
                   owner_key_id=owner.key_id)
    registry_path = workdir / "smp-registry-v1.json"
    pin_path = workdir / "smp-registry-v1.pin"
    registry_path.write_text(json.dumps(registry_doc, indent=2) + "\n")
    pin_path.write_text(json.dumps(pin, indent=2) + "\n")

    registry = MappingRegistry(
        registry_doc=json.loads(registry_path.read_text()),
        pin=json.loads(pin_path.read_text()),
        owner_pubkey=owner.public_key_bytes())

    def _decide(event):
        if decision_fn is not None:
            return decision_fn(event)
        return "ALLOW"

    guardian = AcsGuardian(
        psk=b"smp-proto-psk-16bytes-long!!", issuer=guardian_issuer,
        constitution_hash="smp-proto-constitution-hash",
        decision_fn=_decide, now_fn=now_fn, capability_ttl_s=300.0,
        holder_keys={subject: holder.public_key_bytes()})
    adapter = ShimAdapter(
        registry=registry, translation_signer=translation_signer,
        log_signer=log_signer,
        constitution_hash="smp-proto-constitution-hash",
        capability_ttl_s=300.0, now_fn=now_fn,
        scitt_outage_threshold=scitt_outage_threshold,
        window_quantum_sec=window_quantum_sec)
    gateway = SmpGateway(
        guardian=guardian, adapter=adapter, issuer_trusted=trusted,
        wal_path=workdir / "decision.wal.jsonl", now_fn=now_fn)
    return Deployment(
        owner=owner, translation_signer=translation_signer,
        log_signer=log_signer, guardian_issuer=guardian_issuer,
        holder=holder, subject=subject, trusted=trusted, registry=registry,
        adapter=adapter, guardian=guardian, gateway=gateway,
        registry_doc=registry_doc, pin=pin, registry_path=registry_path,
        pin_path=pin_path)


def main() -> None:
    """Smoke demo: one mapped translation end-to-end (real Guardian + PEP)."""
    import tempfile
    from anchor_v1.pep import CredentialBroker, ShellPEP
    from anchor_v1.store import CapabilityStore

    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="smp-demo-")))
    res = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params={"cmd": "echo smp", "timeout_s": 30})
    print(f"decision={res.decision.decision} "
          f"capability={'yes' if res.decision.capability else 'no'}")
    assert res.decision.decision == "ALLOW" and res.decision.capability
    payload = authority.verify_capability(
        res.decision.capability, dep.trusted,
        now=datetime.now(timezone.utc))
    assert payload.action_digest == res.envelope.action_digest
    store = CapabilityStore()
    store.sync_revocations([], now=datetime.now(timezone.utc).timestamp())
    store.register_capability(payload)
    shell = ShellPEP(CredentialBroker({"T": "v"}), store, dep.trusted,
                     secrets.token_bytes(32))
    shell.register_command(res.envelope.action_digest, ["echo", "smp"])
    proof = authority.make_holder_proof(
        dep.holder, payload.capability_id, shell.challenge)
    out = shell.execute(envelope=res.envelope,
                        capability_cose=res.decision.capability,
                        holder_proof=proof)
    print(f"PEP exit={out.returncode}; statements="
          f"{len(dep.adapter._statements)}")
    assert out.returncode == 0
    dep.gateway.close()
    print("SMOKE OK: R2-R11 prototype green on the happy path.")


if __name__ == "__main__":
    main()
