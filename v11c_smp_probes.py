#!/usr/bin/env python3
"""v1.1 SMP battle-test ROUND 3 (v11c): adversarial probes NOT covered by the
171-check v11r suite, all against REAL anchor_v1 modules, zero mocks, keys
generated in-process per run. Real finding > green suite: a failed check is
evidence for the verdict, never papered over.

Run with ./.venv/bin/python from ~/workspace/anchor-v1.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import secrets
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")
sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.cbor import cbor_dumps
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.pep import CredentialBroker, EgressProxy, PEPError, ShellPEP
from anchor_v1.scitt import parse_statement, verify_transparent_statement
from anchor_v1.store import CapabilityStore

from smp_v1_1_prototype import (
    SMPRefusal,
    MappingRegistry,
    build_deployment,
    build_registry_payload,
    default_entries,
    make_pin,
    sign_registry,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
NOW_FN = lambda: NOW  # noqa: E731
PARAMS = {"cmd": "echo smp", "timeout_s": 30}

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        raise AssertionError(f"PROBE FAILED: {name} — {detail}")


class CallCounter:
    """Counts real Guardian invocations (proves pre-forward DENY)."""

    def __init__(self, guardian):
        self.handle_event_calls: list = []
        self.resolve_pending_calls: list = []
        orig_he, orig_rp = guardian.handle_event, guardian.resolve_pending

        def he(event, **kw):
            eid = event.event_id if hasattr(event, "event_id") else event.get("event_id")
            self.handle_event_calls.append(eid)
            return orig_he(event, **kw)

        def rp(pending_id, approved, **kw):
            self.resolve_pending_calls.append((pending_id, approved))
            return orig_rp(pending_id, approved, **kw)

        guardian.handle_event = he
        guardian.resolve_pending = rp


def fresh(tmp_prefix: str, *, entries=None, decision_fn=None, now_fn=None):
    workdir = Path(tempfile.mkdtemp(prefix=tmp_prefix))
    dep = build_deployment(workdir=workdir, entries=entries,
                           decision_fn=decision_fn, now_fn=now_fn or NOW_FN)
    counter = CallCounter(dep.guardian)
    return dep, counter


def minted_ids(dep) -> set[str]:
    ids = set()
    for rec in dep.gateway._dlog.decided.values():
        if rec.get("capability_id"):
            ids.add(rec["capability_id"])
    return ids


# ------------------------------------------------- P20: parsed-entry memory tamper
def p20_parsed_entry_memory_tamper():
    print("P20 parsed-entries memory tamper: mutate parsed e001 target_shape in "
          "memory, retained payload bytes untouched")
    dep, counter = fresh("p20-")
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P20 baseline ALLOW before tamper", r0.decision.decision == "ALLOW")
    n0 = len(counter.handle_event_calls)

    # ATTACK: mutate the PARSED RegistryEntry for e001 in memory. The R5
    # integrity check re-hashes only the retained canonical payload bytes,
    # so this must not trip assert_live — the question is whether the
    # tampered parsed entry is then trusted for translation.
    pinned_before = dep.registry.digest
    e001 = next(e for e in dep.registry._entries if e.entry_id == "e001")
    e001.target_value = "/usr/bin/attacker-tool"
    check("P20 retained payload bytes untouched (pin unchanged)",
          dep.registry.digest == pinned_before and
          hashlib.sha256(dep.registry._payload_bytes).hexdigest() == pinned_before,
          "R5 re-hash cannot see the parsed-entry mutation")

    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/attacker-tool",
        principal=dep.subject, params=dict(PARAMS))
    new_mints = len(counter.handle_event_calls) - n0
    minted = minted_ids(dep)
    # Evidence: what did the adapter emit for this translation?
    last_claims = parse_statement(
        dep.adapter._statements[-1], dep.adapter.trusted_issuers)["claims"]
    evidence = (f"observed decision={r.decision.decision}, "
                f"new handle_event calls={new_mints}, "
                f"statement translated_target={last_claims.get('translated_target')!r}, "
                f"registry_entry_id={last_claims.get('registry_entry_id')!r}")
    # The task's assertions: DENY + zero handle_event. If the implementation
    # ALLOWs/mints instead, that is a REAL FINDING — recorded, not hidden.
    check("P20 tampered-parsed-entry intent DENIED",
          r.decision.decision == "DENY", evidence)
    check("P20 zero handle_event calls after tamper",
          new_mints == 0, evidence)
    dep.gateway.close()


# ------------------------------------------------- P21: cross-process double-mint race
def _p21_child(workdir_parent: str, wal_path: str, ledger_path: str,
               barrier, now_iso: str, result_path: str) -> None:
    """Child: own gateway+guardian (same keys/config), shared WAL + mint ledger."""
    sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")
    sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1")
    from datetime import datetime as _dt
    from smp_v1_1_prototype import build_deployment as _bd
    now = _dt.fromisoformat(now_iso)
    workdir = Path(tempfile.mkdtemp(prefix="p21-child-", dir=workdir_parent))
    dep = _bd(workdir=workdir, now_fn=lambda: now)
    # Shared "kernel mint ledger": every real kernel mint appends one line.
    orig_he = dep.guardian.handle_event

    def he(event, **kw):
        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write("mint\n")
        return orig_he(event, **kw)

    dep.guardian.handle_event = he
    # Move the gateway onto the SHARED durable decision log (the one shared
    # kernel-store artifact): both processes front the same WAL.
    dep.gateway.close()
    from smp_v1_1_prototype import SmpGateway
    dep.gateway = SmpGateway(guardian=dep.guardian, adapter=dep.adapter,
                             issuer_trusted=dep.trusted,
                             wal_path=Path(wal_path), now_fn=lambda: now)
    barrier.wait(timeout=60)
    decisions, cached = [], 0
    for _ in range(25):
        r = dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
            principal=dep.subject, params={"cmd": "echo smp", "timeout_s": 30})
        decisions.append(r.decision.decision)
        cached += 1 if r.from_cache else 0
    dep.gateway.close()
    Path(result_path).write_text(json.dumps(
        {"decisions": decisions, "cached": cached}))


def p21_cross_process_double_mint_race():
    print("P21 cross-process double-mint race: 2 processes x 25 identical "
          "intents, shared WAL + shared mint ledger")
    ctx = mp.get_context("fork")
    parent_dir = Path(tempfile.mkdtemp(prefix="p21-"))
    wal_path = str(parent_dir / "shared-decision.wal.jsonl")
    ledger_path = str(parent_dir / "mint-ledger.txt")
    Path(ledger_path).write_text("")
    barrier = ctx.Barrier(2)
    res_paths = [str(parent_dir / f"child{i}.json") for i in (0, 1)]
    procs = [ctx.Process(target=_p21_child,
                         args=(str(parent_dir), wal_path, ledger_path,
                               barrier, NOW.isoformat(), rp))
             for rp in res_paths]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)
    check("P21 both children exited cleanly",
          all(p.exitcode == 0 for p in procs),
          f"exitcodes={[p.exitcode for p in procs]}")
    total_mints = sum(1 for _ in Path(ledger_path).read_text().splitlines()
                      if _.strip())
    child_stats = [json.loads(Path(rp).read_text()) for rp in res_paths]
    all_allow = all(d == "ALLOW" for s in child_stats for d in s["decisions"])
    check("P21 all 50 submissions returned ALLOW", all_allow)
    # R6's per-dedup_key lock is a threading.Lock: process-local by
    # construction. If cross-process dedup held, exactly one mint. Otherwise
    # the observed count is the measured residual — recorded honestly.
    check("P21 cross-process dedup holds: exactly ONE kernel mint",
          total_mints == 1,
          f"total_mints={total_mints} (R6 lock is process-local; each "
          f"process minted independently — child cache hits: "
          f"{[s['cached'] for s in child_stats]})")


# ------------------------------------------------- P22: F7 clock skew
def p22_clock_skew_ask_resolve():
    print("P22 F7 clock skew: ASK at T0, advance fake clock past the validity "
          "window, then honest approve")
    clock = [NOW]
    dep, counter = fresh(
        "p22-",
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask" else "ALLOW",
        now_fn=lambda: clock[0])
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    check("P22 ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    ask_envelope = dep.gateway._pending_by_id[gw_pid]["envelope"]
    # Honest operator is slow: the clock rolls past the ASK-time validity
    # window (ttl 300s) before the approval is submitted.
    clock[0] = clock[0] + timedelta(seconds=400)
    n_rp = len(counter.resolve_pending_calls)
    ra = dep.gateway.resolve_approval(gw_pid, approved=True,
                                      presented_envelope=ask_envelope)
    # The §9.2 digest check passes (original envelope presented); the kernel
    # then validates the validity window at the mint moment.
    check("P22 resolve_pending reached the kernel",
          len(counter.resolve_pending_calls) == n_rp + 1)
    reason = (ra.decision.reason or "")
    detail = (f"decision={ra.decision.decision}, reason={reason!r}")
    check("P22 honest approval after window roll DENIED (self-DoS residual)",
          ra.decision.decision == "DENY" and "validity window" in reason,
          detail)
    check("P22 nothing minted for the stale approval",
          len(minted_ids(dep)) == 0, detail)
    dep.gateway.close()


# ------------------------------------------------- P23: prefix path traversal
def p23_prefix_path_traversal():
    print("P23 prefix path traversal: target_shape prefix /var/log/ with "
          "target /var/log/../etc/passwd")
    dep, counter = fresh("p23-")
    traversal = "/var/log/../etc/passwd"
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/read", target=traversal,
        principal=dep.subject, params=dict(PARAMS))
    matched = r.decision.decision == "ALLOW"
    detail = f"decision={r.decision.decision}"
    check("P23 linear startswith matcher ALLOWs the traversal target (no "
          "path normalization in the adapter)", matched, detail)
    if matched:
        env_target = r.envelope.effect.target
        check("P23 matched target lands VERBATIM (orchestrator-supplied, not "
              "entry-fixed) in the minted envelope",
              env_target == traversal, f"envelope.target={env_target!r}")
        last_claims = parse_statement(
            dep.adapter._statements[-1], dep.adapter.trusted_issuers)["claims"]
        check("P23 SCITT statement records the raw traversal target",
              last_claims.get("translated_target") == traversal)
        # Exploitability at the PEP: the reference ShellPEP keys commands by
        # action_digest and never interprets the target as a path.
        store = CapabilityStore()
        store.sync_revocations([], now=NOW.timestamp())
        payload = authority.verify_capability(
            r.decision.capability, dep.trusted, now=NOW)
        store.register_capability(payload)
        shell = ShellPEP(CredentialBroker({"T": "v"}), store, dep.trusted,
                         secrets.token_bytes(32))
        proof = authority.make_holder_proof(
            dep.holder, payload.capability_id, shell.challenge)
        try:
            shell.execute(envelope=r.envelope,
                          capability_cose=r.decision.capability,
                          holder_proof=proof)
            pep_ran = True
        except PEPError as exc:
            pep_ran = False
            pep_why = str(exc)
        check("P23 PEP refuses the traversal envelope (no command registered "
              "for its digest) — fail-closed, nothing executed",
              not pep_ran, f"PEPError: {pep_why}" if not pep_ran else "EXECUTED")
        check("P23 residual documented: the minted envelope AUTHORIZES the "
              "un-normalized target string; any downstream consumer that "
              "normalizes target as a filesystem path would resolve "
              "/etc/passwd — normalization is a deployment/PEP obligation, "
              "absent from the adapter",
              True, "envelope + capability both commit to the raw string")
    dep.gateway.close()

# ------------------------------------------------- P24: signature forgery variants
def _p24_base():
    owner = Ed25519Signer.generate("p24/registry-owner")
    payload = build_registry_payload(
        version="2026-09-23-r1", owner_key_id=owner.key_id,
        spiffe_id="spiffe://p24/owner", entries=default_entries(),
        issued_at=NOW.isoformat())
    return owner, payload


def _p24_try_load(doc: dict, pin: dict, owner_pubkey: bytes):
    try:
        MappingRegistry(registry_doc=doc, pin=pin, owner_pubkey=owner_pubkey)
        return True, "STARTED (not refused)"
    except SMPRefusal as exc:
        return False, str(exc)


def p24a_forged_key_id_rewrite():
    print("P24a forgery: valid attacker signature, signature.key_id rewritten "
          "to the owner's key_id")
    owner, payload = _p24_base()
    attacker = Ed25519Signer.generate("p24/attacker")
    payload_bytes = canonical_bytes(payload)
    doc = {
        "payload": payload,
        "signature": {
            "key_id": owner.key_id,          # rewritten: claims to be owner
            "alg": "EdDSA",
            "sig": attacker.sign_bytes(payload_bytes).hex(),  # attacker's sig
            "payload_hash_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        },
    }
    pin = make_pin(version="2026-09-23-r1",
                   payload_hash_sha256=hashlib.sha256(payload_bytes).hexdigest(),
                   owner_key_id=owner.key_id)
    started, detail = _p24_try_load(doc, pin, owner.public_key_bytes())
    check("P24a key_id-rewritten forgery refused at startup",
          not started, detail)


def p24b_garbage_signature():
    print("P24b forgery: signature block claims alg EdDSA but sig is garbage")
    owner, payload = _p24_base()
    payload_bytes = canonical_bytes(payload)
    garbage_sig = secrets.token_bytes(64).hex()  # valid hex, 64 bytes, wrong
    doc = {
        "payload": payload,
        "signature": {
            "key_id": owner.key_id,
            "alg": "EdDSA",
            "sig": garbage_sig,
            "payload_hash_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        },
    }
    pin = make_pin(version="2026-09-23-r1",
                   payload_hash_sha256=hashlib.sha256(payload_bytes).hexdigest(),
                   owner_key_id=owner.key_id)
    started, detail = _p24_try_load(doc, pin, owner.public_key_bytes())
    check("P24b garbage-signature forgery refused at startup",
          not started, detail)
    # Non-hex garbage must also refuse (not crash with a raw exception).
    doc2 = json.loads(json.dumps(doc))
    doc2["signature"]["sig"] = "zz-not-hex-zz"
    started2, detail2 = _p24_try_load(doc2, pin, owner.public_key_bytes())
    check("P24b non-hex signature refused (fail-closed, SMPRefusal)",
          not started2, detail2)


def p24c_noncanonical_signing_bytes():
    print("P24c forgery: registry signed over pretty-printed (non-canonical) "
          "JSON bytes")
    owner, payload = _p24_base()
    pretty = json.dumps(payload, indent=2).encode("utf-8")  # non-canonical
    assert pretty != canonical_bytes(payload), "harness: bytes must differ"
    doc = {
        "payload": payload,
        "signature": {
            "key_id": owner.key_id,
            "alg": "EdDSA",
            "sig": owner.sign_bytes(pretty).hex(),   # genuine owner sig...
            "payload_hash_sha256": hashlib.sha256(pretty).hexdigest(),
        },
    }
    # Variant 1: attacker-influenced pin matching the non-canonical hash.
    pin_evil = make_pin(version="2026-09-23-r1",
                        payload_hash_sha256=hashlib.sha256(pretty).hexdigest(),
                        owner_key_id=owner.key_id)
    started, detail = _p24_try_load(doc, pin_evil, owner.public_key_bytes())
    check("P24c non-canonical signing refused (attacker pin)",
          not started, detail)
    # Variant 2: honest operator pin (canonical hash) — pin check fires first.
    pin_honest = make_pin(
        version="2026-09-23-r1",
        payload_hash_sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        owner_key_id=owner.key_id)
    started2, detail2 = _p24_try_load(doc, pin_honest, owner.public_key_bytes())
    check("P24c non-canonical signing refused (honest pin)",
          not started2, detail2)


# ------------------------------------------------- P25: SCITT chain-gap detection
def _p25_healthy_run(tmp_prefix: str):
    dep, counter = fresh(tmp_prefix)
    dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/nope", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/read", target="/var/log/syslog",
        principal=dep.subject, params=dict(PARAMS))
    return dep


def _p25_verify_chain(statements: list[bytes], trusted) -> tuple[bool, str]:
    """The v11r P15 chain-verification path: link prev_statement_hash."""
    prev = "0" * 64
    for i, s in enumerate(statements):
        try:
            view = parse_statement(s, trusted)
        except Exception as exc:
            return False, f"statement[{i}] unparseable: {type(exc).__name__}"
        got = (view["claims"] or {}).get("prev_statement_hash")
        if got != prev:
            return False, (f"chain link broken at statement[{i}]: "
                            f"prev={got[:12]}… expected {prev[:12]}…")
        prev = hashlib.sha256(s).hexdigest()
    return True, f"{len(statements)} links verified"


def p25a_chain_gap_detection():
    print("P25a SCITT chain-gap: delete a middle statement, run the "
          "chain-verification path")
    dep = _p25_healthy_run("p25a-")
    check("P25a three statements issued", len(dep.adapter._statements) == 3,
          f"got {len(dep.adapter._statements)}")
    ok_before, _ = _p25_verify_chain(dep.adapter._statements,
                                     dep.adapter.trusted_issuers)
    check("P25a chain verifies before tamper", ok_before)
    # ATTACK: delete the middle statement from the transparency log storage.
    stmts = list(dep.adapter._statements)
    del stmts[1]
    ok_after, why = _p25_verify_chain(stmts, dep.adapter.trusted_issuers)
    check("P25a chain-gap DETECTED by the verification path",
          not ok_after, f"detection: {why}")
    dep.gateway.close()


def p25b_statement_byte_tamper_detection():
    print("P25b SCITT tamper: flip bytes of a stored statement, verify")
    dep = _p25_healthy_run("p25b-")
    raw = bytearray(dep.adapter._statements[1])
    raw[50] ^= 0xFF
    tampered = bytes(raw)
    detected = False
    why = ""
    try:
        parse_statement(tampered, dep.adapter.trusted_issuers)
        why = "tampered statement parsed cleanly (NOT detected)"
    except Exception as exc:
        detected = True
        why = f"parse_statement raised {type(exc).__name__}"
    check("P25b statement byte-tamper DETECTED", detected, why)
    # Same for the transparent (receipt-carrying) bytes.
    traw = bytearray(dep.adapter._transparent[1])
    traw[60] ^= 0xFF
    detected2, why2 = False, ""
    try:
        verify_transparent_statement(
            bytes(traw), dep.adapter.trusted_issuers,
            {dep.log_signer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
                dep.log_signer.public_key_bytes())})
        why2 = "tampered transparent statement verified cleanly (NOT detected)"
    except Exception as exc:
        detected2 = True
        why2 = f"verify_transparent_statement raised {type(exc).__name__}"
    check("P25b transparent-statement tamper DETECTED", detected2, why2)
    dep.gateway.close()


# ------------------------------------------------- P26: continuity binding at resolve
def p26_resolve_with_different_valid_verb():
    print("P26 continuity binding: ASK anchor:shell/backup-ask, resolve with "
          "a DIFFERENT valid allowlisted verb (anchor:shell/exec)")
    dep, counter = fresh(
        "p26-",
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask" else "ALLOW")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    check("P26 ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    n_rp = len(counter.resolve_pending_calls)
    # Attacker swaps the pending intent to a different VALID allowlisted verb.
    dep.gateway._pending_by_id[gw_pid]["intent"]["verb"] = "anchor:shell/exec"
    dep.gateway._pending_by_id[gw_pid]["intent"]["target"] = "/usr/bin/backup"
    ra = dep.gateway.resolve_approval(gw_pid, approved=True)
    check("P26 resolve with swapped valid verb DENIED",
          ra.decision.decision == "DENY", f"reason={ra.decision.reason!r}")
    check("P26 guardian.resolve_pending never called",
          len(counter.resolve_pending_calls) == n_rp)
    check("P26 nothing minted by the swapped resolve",
          len(minted_ids(dep)) == 0)
    # The honest ASK is still pending and still approvable — the attack did
    # not destroy the legitimate approval.
    dep.gateway._pending_by_id[gw_pid]["intent"]["verb"] = "anchor:shell/backup-ask"
    dep.gateway._pending_by_id[gw_pid]["intent"]["target"] = "/usr/bin/backup-ask"
    ra2 = dep.gateway.resolve_approval(gw_pid, approved=True)
    check("P26 honest approval still resolves ALLOW after the attack",
          ra2.decision.decision == "ALLOW" and ra2.decision.capability is not None,
          f"decision={ra2.decision.decision}")
    dep.gateway.close()


# ------------------------------------------------- P27: panic-latch restart
def p27_panic_latch_restart():
    print("P27 panic-latch restart: tampered registry file persists on disk; "
          "a restarted process must refuse to start")
    dep, counter = fresh("p27-")
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P27 baseline ALLOW before tamper", r0.decision.decision == "ALLOW")
    # PANIC: tamper the ON-DISK registry file (not just memory). Flip one
    # ASCII byte inside a target value so the file stays valid UTF-8/JSON
    # (a raw bit-flip can break UTF-8 decoding — the realistic attacker
    # edits the file, not the encoding).
    raw = bytearray(Path(dep.registry_path).read_bytes())
    idx = bytes(raw).find(b"/usr/bin/backup")
    assert idx > 0, "harness: expected target value in registry file"
    raw[idx + len(b"/usr/bin/backu")] = ord("c")  # backup -> backuc
    Path(dep.registry_path).write_bytes(bytes(raw))
    check("P27 tampered registry file is on disk",
          b"/usr/bin/backuc" in Path(dep.registry_path).read_bytes())
    # Simulate process restart: fresh load from the tampered file + the
    # ORIGINAL pin, exactly as build_deployment does at startup.
    refused, detail = _p24_try_load(
        json.loads(Path(dep.registry_path).read_text()),
        json.loads(Path(dep.pin_path).read_text()),
        dep.owner.public_key_bytes())
    check("P27 restarted deployment REFUSES to start (no silent recovery)",
          not refused, detail)
    check("P27 refusal names the pin/hash mismatch",
          "pin" in detail.lower() or "hash" in detail.lower(), detail)
    dep.gateway.close()


# ------------------------------------------------- P28: http-plane end-to-end
def p28_http_plane_end_to_end():
    print("P28 http-plane end-to-end: http intents DENY pre-forward, "
          "EgressProxy.authorize_http never reached")
    dep, counter = fresh("p28-")
    egress = EgressProxy(CredentialBroker({"T": "v"}), CapabilityStore(),
                         dep.trusted, secrets.token_bytes(32))
    reached = []
    orig_auth = egress.authorize_http

    def spy(**kw):
        reached.append(kw.get("envelope"))
        return orig_auth(**kw)

    egress.authorize_http = spy
    n0 = len(counter.handle_event_calls)
    r1 = dep.gateway.submit_intent(
        plane="http", verb="anchor:http/fetch", target="https://example.com/x",
        principal=dep.subject, params=dict(PARAMS))
    check("P28 (plane=http, anchor:http/fetch) DENIED pre-forward",
          r1.decision.decision == "DENY", f"reason={r1.decision.reason!r}")
    r2 = dep.gateway.submit_intent(
        plane="http", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P28 (plane=http, anchor:shell/exec) DENIED pre-forward",
          r2.decision.decision == "DENY", f"reason={r2.decision.reason!r}")
    check("P28 zero handle_event calls across both http intents",
          len(counter.handle_event_calls) == n0)
    check("P28 EgressProxy.authorize_http never reached",
          len(reached) == 0, f"calls={len(reached)}")
    check("P28 nothing minted on the http plane",
          len(minted_ids(dep)) == 0)
    dep.gateway.close()


# ------------------------------------------------- P29: verb-swap smuggling pre-PEP
def p29_verb_swap_smuggling_pre_pep():
    print("P29 verb-swap smuggling pre-PEP: minted capability for digest-A, "
          "presented with verb-swapped envelope (digest-B)")
    dep, counter = fresh("p29-")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P29 baseline ALLOW minted", r.decision.decision == "ALLOW"
          and r.decision.capability is not None)
    env_a = r.envelope
    digest_a = env_a.action_digest
    # Verb-swapped envelope: same principal/target/args, different verb ->
    # different action_digest (digest-B). The kernel deliberately does NOT
    # validate verb/target on presented envelopes (documented residual), so
    # the PEP's digest binding is the last line of defense.
    evil = env_a.model_copy(deep=True)
    evil.effect = evil.effect.model_copy(update={"verb": "anchor:shell/evil"})
    digest_b = evil.action_digest
    check("P29 swapped envelope has a different digest",
          digest_b != digest_a, f"A={digest_a[:12]}… B={digest_b[:12]}…")
    store = CapabilityStore()
    store.sync_revocations([], now=NOW.timestamp())
    payload = authority.verify_capability(
        r.decision.capability, dep.trusted, now=NOW)
    store.register_capability(payload)
    shell = ShellPEP(CredentialBroker({"T": "v"}), store, dep.trusted,
                     secrets.token_bytes(32))
    shell.register_command(digest_a, ["echo", "legit"])
    marker = Path(tempfile.mkdtemp(prefix="p29-")) / "smuggled.marker"
    shell.register_command(digest_b, ["touch", str(marker)])
    proof = authority.make_holder_proof(
        dep.holder, payload.capability_id, shell.challenge)
    refused, why = False, ""
    try:
        shell.execute(envelope=evil, capability_cose=r.decision.capability,
                      holder_proof=proof)
    except PEPError as exc:
        refused, why = True, str(exc)
    check("P29 verb-swapped envelope refused at the PEP (fail-closed)",
          refused, f"PEPError: {why}" if refused else "EXECUTED")
    check("P29 refusal is the digest-mismatch binding",
          "digest" in why.lower() or "mismatch" in why.lower()
          or "binding" in why.lower(), why)
    check("P29 smuggled command never ran (no subprocess side effect)",
          not marker.exists())
    # The failed smuggle consumed nothing: the legit envelope still executes.
    out = shell.execute(envelope=env_a, capability_cose=r.decision.capability,
                        holder_proof=authority.make_holder_proof(
                            dep.holder, payload.capability_id, shell.challenge))
    check("P29 legit envelope still executes (failed smuggle consumed nothing)",
          out.returncode == 0)
    dep.gateway.close()


def main() -> None:
    probes = [p20_parsed_entry_memory_tamper,
              p21_cross_process_double_mint_race,
              p22_clock_skew_ask_resolve,
              p23_prefix_path_traversal,
              p24a_forged_key_id_rewrite,
              p24b_garbage_signature,
              p24c_noncanonical_signing_bytes,
              p25a_chain_gap_detection,
              p25b_statement_byte_tamper_detection,
              p26_resolve_with_different_valid_verb,
              p27_panic_latch_restart,
              p28_http_plane_end_to_end,
              p29_verb_swap_smuggling_pre_pep]
    failed = []
    for p in probes:
        print("=" * 70)
        try:
            p()
        except AssertionError as exc:
            failed.append((p.__name__, str(exc)))
            print(f"  [FAIL] {exc}")
        except Exception as exc:  # noqa: BLE001 — harness error, report it
            failed.append((p.__name__, f"HARNESS ERROR: {type(exc).__name__}: {exc}"))
            print(f"  [HARNESS ERROR] {type(exc).__name__}: {exc}")
    print("=" * 70)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"CHECKS: {passed}/{total} passed")
    if failed:
        print(f"PROBES FAILED: {len(failed)}")
        for name, why in failed:
            print(f"  - {name}: {why}")
        sys.exit(1)
    print("RESULT: all third-round adversarial probes green.")


if __name__ == "__main__":
    main()
