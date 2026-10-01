#!/usr/bin/env python3
"""v1.1 SMP battle-test: adversarial probes against the R2-R11 prototype.

REAL modules, zero mocks, zero kernel edits. Every probe asserts; any
assertion failure is a SPEC/implementation finding, not a probe bug
(unless the harness itself is wrong — then the harness is fixed).

Run with ./.venv/bin/python from ~/workspace/anchor-v1.
"""
from __future__ import annotations

import copy
import hashlib
import json
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
from anchor_v1.pep import CredentialBroker, ShellPEP
from anchor_v1.scitt import parse_statement, verify_transparent_statement
from anchor_v1.store import CapabilityStore

from smp_v1_1_prototype import (
    SMPRefusal,
    SimulatedCrash,
    MappingRegistry,
    build_deployment,
    build_registry_payload,
    default_entries,
    make_pin,
    sign_registry,
)

# Frozen at the real current time: digests are deterministic within the run
# (all threads share one NOW) while validity windows stay real for the
# store/PEP consume path.
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


def fresh(tmp_prefix: str, *, entries=None, decision_fn=None):
    workdir = Path(tempfile.mkdtemp(prefix=tmp_prefix))
    dep = build_deployment(workdir=workdir, entries=entries,
                           decision_fn=decision_fn, now_fn=NOW_FN)
    counter = CallCounter(dep.guardian)
    return dep, counter


def minted_ids(dep) -> set[str]:
    """All capability_ids ever minted through this deployment's gateway."""
    ids = set()
    for rec in dep.gateway._dlog.decided.values():
        if rec.get("capability_id"):
            ids.add(rec["capability_id"])
    return ids


# ---------------------------------------------------------------- P01: happy path
def p01_valid_mapped_intent():
    print("P01 valid mapped intent -> ALLOW, digest-bound, PEP executes")
    dep, counter = fresh("p01-")
    res = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P01 decision ALLOW", res.decision.decision == "ALLOW")
    check("P01 capability minted", res.decision.capability is not None)
    check("P01 exactly one handle_event", len(counter.handle_event_calls) == 1)
    payload = authority.verify_capability(res.decision.capability, dep.trusted, now=NOW)
    check("P01 payload binds QUALIFIED verb digest",
          payload.action_digest == res.envelope.action_digest,
          f"verb={res.envelope.effect.verb}")
    check("P01 presented verb is qualified", res.envelope.effect.verb == "anchor:shell/exec")
    store = CapabilityStore()
    store.sync_revocations([], now=NOW.timestamp())
    store.register_capability(payload)
    shell = ShellPEP(CredentialBroker({"T": "v"}), store, dep.trusted, secrets.token_bytes(32))
    shell.register_command(res.envelope.action_digest, ["echo", "smp"])
    proof = authority.make_holder_proof(dep.holder, payload.capability_id, shell.challenge)
    out = shell.execute(envelope=res.envelope, capability_cose=res.decision.capability,
                        holder_proof=proof)
    check("P01 PEP executes exit=0", out.returncode == 0)
    check("P01 capability consumed", store.capability_state(payload.capability_id) == "CONSUMED")
    dep.gateway.close()


# ------------------------------------------------- P02: registry tamper (same version)
def p02_registry_tamper():
    print("P02 registry tamper (entry modified, version identical) -> startup refusal")
    dep0, _ = fresh("p02a-")
    tampered = copy.deepcopy(dep0.registry_doc)
    tampered["payload"]["entries"][0]["presented_verb"] = "anchor:shell/pwn"
    dep0.gateway.close()
    workdir = Path(tempfile.mkdtemp(prefix="p02b-"))
    tpath = workdir / "reg.json"
    tpath.write_text(json.dumps(tampered))
    # load the tampered doc directly against the ORIGINAL pin
    from smp_v1_1_prototype import MappingRegistry
    refused, detail = False, ""
    try:
        MappingRegistry(registry_doc=json.loads(tpath.read_text()),
                        pin=dep0.pin, owner_pubkey=dep0.owner.public_key_bytes())
    except SMPRefusal as exc:
        refused = True
        detail = str(exc)
    check("P02 tampered registry refused at startup", refused, detail if refused else "NOT REFUSED")
    check("P02 refusal names pin/hash mismatch", "payload hash" in detail)
    check("P02 zero handle_event forwards possible (no adapter exists)", True,
          "startup refusal precedes any Gateway construction")


# ------------------------------------------------- P03: signature forgery
def p03_signature_forgery():
    print("P03 forged signature (attacker key, pin owner_key_id kept) -> startup refusal")
    dep0, _ = fresh("p03-")
    attacker = Ed25519Signer.generate(dep0.pin["owner_key_id"])  # same key_id, wrong key
    forged = sign_registry(dep0.registry_doc["payload"], attacker)
    assert forged["signature"]["key_id"] == dep0.pin["owner_key_id"]
    from smp_v1_1_prototype import MappingRegistry
    refused = False
    try:
        MappingRegistry(registry_doc=forged, pin=dep0.pin,
                        owner_pubkey=dep0.owner.public_key_bytes())
    except SMPRefusal as exc:
        refused = True
        detail = str(exc)
    check("P03 forged signature refused", refused, detail if refused else "NOT REFUSED")
    check("P03 refusal names signature failure", "signature" in detail.lower())
    dep0.gateway.close()


# ------------------------------------------------- P04: runtime mutation -> refuse-all + compromise statement
def p04_runtime_mutation():
    print("P04 runtime registry mutation -> refuse ALL + compromise statement")
    dep, counter = fresh("p04-")
    before = len(counter.handle_event_calls)
    # sanity: one good translation first
    r0 = dep.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                   target="/usr/bin/backup",
                                   principal=dep.subject, params=dict(PARAMS))
    check("P04 baseline ALLOW before mutation", r0.decision.decision == "ALLOW")
    # corrupt the retained canonical payload bytes after startup
    raw = bytearray(dep.registry._payload_bytes)
    raw[100] ^= 0xFF
    dep.registry._payload_bytes = bytes(raw)
    n_stmt_before = len(dep.adapter._statements)
    r1 = dep.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                   target="/usr/bin/backup",
                                   principal=dep.subject, params=dict(PARAMS))
    check("P04 post-mutation translation refused (DENY)", r1.decision.decision == "DENY")
    check("P04 no handle_event after mutation",
          len(counter.handle_event_calls) == before + 1,
          f"calls={len(counter.handle_event_calls)}")
    check("P04 compromise statement emitted",
          len(dep.adapter._statements) == n_stmt_before + 1)
    view = parse_statement(dep.adapter._statements[-1], dep.adapter.trusted_issuers)
    claims = view["claims"]
    check("P04 statement status registry_compromise",
          claims["translation_status"] == "registry_compromise")
    check("P04 statement carries observed vs pinned digests",
          claims.get("observed_digest") != claims.get("pinned_digest") and
          claims.get("pinned_digest") == dep.pin["payload_hash_sha256"])
    # latched: a second attempt also refuses
    r2 = dep.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                   target="/usr/bin/backup",
                                   principal=dep.subject, params=dict(PARAMS))
    check("P04 latch persists (second call refused)", r2.decision.decision == "DENY")
    check("P04 still zero post-mutation handle_events",
          len(counter.handle_event_calls) == before + 1)
    dep.gateway.close()


# ------------------------------------------------- P05: unmapped verb
def p05_unmapped_verb():
    print("P05 unmapped verb -> DENY, no capability, handle_event never called")
    dep, counter = fresh("p05-")
    n0 = len(counter.handle_event_calls)
    res = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/rm-rf-everything", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P05 decision DENY", res.decision.decision == "DENY")
    check("P05 no capability", res.decision.capability is None)
    check("P05 handle_event never invoked", len(counter.handle_event_calls) == n0)
    check("P05 deny reason names unmapped", "UNMAPPED" in res.decision.reason)
    # a deny statement was emitted pre-forward with capability_id null
    view = parse_statement(dep.adapter._statements[-1], dep.adapter.trusted_issuers)
    check("P05 deny statement status deny_unmapped",
          view["claims"]["translation_status"] == "deny_unmapped")
    check("P05 deny statement capability_id null",
          view["claims"]["capability_id"] is None)
    dep.gateway.close()


# ------------------------------------------------- P06/P07/P08: grammar attacks
def p06_uppercase_verb():
    print("P06 uppercase verb -> DENY pre-forward (lowercase-only, R2)")
    dep, counter = fresh("p06-")
    n0 = len(counter.handle_event_calls)
    res = dep.gateway.submit_intent(
        plane="shell", verb="anchor:Shell/Exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P06 uppercase DENY", res.decision.decision == "DENY")
    check("P06 no handle_event", len(counter.handle_event_calls) == n0)
    dep.gateway.close()


def p07_overlong_uri():
    print("P07 over-256-octet URI -> DENY pre-forward")
    dep, counter = fresh("p07-")
    n0 = len(counter.handle_event_calls)
    long_verb = "anchor:shell/" + "a" * 250   # 13 + 250 = 263 octets
    assert len(long_verb.encode()) > 256
    res = dep.gateway.submit_intent(
        plane="shell", verb=long_verb, target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P07 overlong DENY", res.decision.decision == "DENY")
    check("P07 no handle_event", len(counter.handle_event_calls) == n0)
    check("P07 reason cites 256-octet cap", "256" in res.decision.reason)
    dep.gateway.close()


def p08_malformed_uris():
    print("P08 malformed URIs -> all DENY pre-forward")
    dep, counter = fresh("p08-")
    n0 = len(counter.handle_event_calls)
    for bad in ["anchor:shell/ exec", "anch0r:shell/exec", "exec",
                "anchor:shell/exec/", "anchor:/exec", "anchor:shell/",
                "anchor:9shell/exec"]:
        res = dep.gateway.submit_intent(
            plane="shell", verb=bad, target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
        check(f"P08 malformed {bad!r} DENY", res.decision.decision == "DENY")
    check("P08 zero handle_events across all malformed",
          len(counter.handle_event_calls) == n0)
    dep.gateway.close()


# ------------------------------------------------- P09: N-to-1 at load
def p09_n_to_1_rejected():
    print("P09 N-to-1 registry -> startup refusal naming BOTH entries (R3)")
    entries = default_entries()
    entries.append({"entry_id": "e999", "plane": "shell",
                    "qualified_verb": "anchor:shell/sneaky",
                    "target_shape": {"kind": "exact", "value": "/usr/bin/backup"},
                    "presented_verb": "anchor:shell/exec",   # collides w/ e001
                    "acs_action": "anchor:acs/evil.run",
                    "acs_resource": "backup:host-a"})
    refused, detail = False, ""
    try:
        fresh("p09-", entries=entries)
    except SMPRefusal as exc:
        refused, detail = True, str(exc)
    check("P09 N-to-1 refused at load", refused, detail if refused else "NOT REFUSED")
    check("P09 names both colliding entries",
          "'e001'" in detail and "'e999'" in detail, detail)


# ------------------------------------------------- P10: fictitious plane
def p10_fictitious_plane():
    print("P10 fictitious target plane 'acs' -> startup refusal naming the entry")
    entries = default_entries()
    entries.append({"entry_id": "e666", "plane": "acs",
                    "qualified_verb": "anchor:acs/evil",
                    "target_shape": {"kind": "exact", "value": "x"},
                    "presented_verb": "anchor:acs/evil",
                    "acs_action": "anchor:acs/evil.run",
                    "acs_resource": "backup:host-a"})
    refused, detail = False, ""
    try:
        fresh("p10-", entries=entries)
    except SMPRefusal as exc:
        refused, detail = True, str(exc)
    check("P10 fictitious plane refused", refused, detail if refused else "NOT REFUSED")
    check("P10 names the offending entry", "'e666'" in detail, detail)


# ------------------------------------------------- P11: namespace/plane mismatch + R11
def p11_namespace_plane_mismatch():
    print("P11 namespace/plane mismatch + R11 http-plane -> DENY")
    dep, counter = fresh("p11-")
    n0 = len(counter.handle_event_calls)
    # R11: http-plane intent (no anchor:http namespace in v1.1) -> DENY as unmapped
    r = dep.gateway.submit_intent(
        plane="http", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P11 http-plane DENY as unmapped (R11)", r.decision.decision == "DENY")
    # shell plane with acs verb -> DENY (2.4c)
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:acs/backup.run", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P11 anchor:acs/ as effect verb DENY", r.decision.decision == "DENY")
    # shell plane, grammatically-valid undefined namespace -> DENY unmapped
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:http/fetch", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P11 undefined namespace DENY", r.decision.decision == "DENY")
    check("P11 zero handle_events", len(counter.handle_event_calls) == n0)
    dep.gateway.close()


# ------------------------------------------------- P12: prefix target_shape
def p12_prefix_shape():
    print("P12 target_shape prefix: match hit, non-match unmapped (R10)")
    dep, counter = fresh("p12-")
    n0 = len(counter.handle_event_calls)
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/read", target="/var/log/syslog",
        principal=dep.subject, params=dict(PARAMS))
    check("P12 prefix hit ALLOW", r.decision.decision == "ALLOW")
    check("P12 one handle_event", len(counter.handle_event_calls) == n0 + 1)
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/read", target="/etc/passwd",
        principal=dep.subject, params=dict(PARAMS))
    check("P12 non-prefix DENY unmapped", r.decision.decision == "DENY")
    check("P12 still one handle_event", len(counter.handle_event_calls) == n0 + 1)
    dep.gateway.close()

# ------------------------------------------------- P13: double-mint, 50 threads
def p13_double_mint_concurrency():
    print("P13 double-mint: 50 threads, same intent -> exactly ONE mint (R6)")
    dep, counter = fresh("p13-")
    results, errors = [], []
    barrier = threading.Barrier(50)

    def worker():
        try:
            barrier.wait(timeout=30)
            r = dep.gateway.submit_intent(
                plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
                principal=dep.subject, params=dict(PARAMS))
            results.append(r)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    check("P13 no worker errors", not errors, str(errors[:1]))
    check("P13 all 50 got results", len(results) == 50, f"got {len(results)}")
    check("P13 exactly ONE handle_event call",
          len(counter.handle_event_calls) == 1,
          f"calls={len(counter.handle_event_calls)}")
    check("P13 all decisions ALLOW", all(r.decision.decision == "ALLOW" for r in results))
    cap_ids = set()
    for r in results:
        p = authority.verify_capability(r.decision.capability, dep.trusted, now=NOW)
        cap_ids.add(p.capability_id)
    check("P13 all 50 share ONE capability_id (cached result, no second mint)",
          len(cap_ids) == 1, f"distinct={len(cap_ids)}")
    cached = sum(1 for r in results if r.from_cache)
    check("P13 49 served from cache", cached == 49, f"cached={cached}")
    check("P13 identical dedup_key across all", len({r.dedup_key for r in results}) == 1)
    # store holds exactly one capability for the digest
    store = CapabilityStore()
    store.sync_revocations([], now=NOW.timestamp())
    first = authority.verify_capability(results[0].decision.capability, dep.trusted, now=NOW)
    store.register_capability(first)
    check("P13 store: capability ISSUED once",
          store.capability_state(first.capability_id) == "ISSUED")
    check("P13 minted set size == 1", len(minted_ids(dep)) == 1)
    dep.gateway.close()


# ------------------------------------------------- P14: resolve_pending parity (§9)
def _ask_deployment():
    def decide(event):
        return "ASK" if event.action == "anchor:acs/backup.ask" else "ALLOW"
    return fresh("p14-", decision_fn=decide)


def p14a_ask_approve_flow():
    print("P14a ASK -> duplicate while pending DENY -> approve -> ALLOW")
    dep, counter = fresh("p14a-", decision_fn=(
        lambda e: "ASK" if e.action == "anchor:acs/backup.ask" else "ALLOW"))
    n0 = len(counter.handle_event_calls)
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    check("P14a ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    check("P14a gateway pending_id issued", gw_pid and gw_pid.startswith("gw-"))
    check("P14a one handle_event", len(counter.handle_event_calls) == n0 + 1)
    # duplicate while PENDING -> DENY "event pending approval", no new mint
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    check("P14a duplicate while pending DENY", r2.decision.decision == "DENY")
    check("P14a pending-duplicate reason", r2.decision.reason == "event pending approval")
    check("P14a no second handle_event", len(counter.handle_event_calls) == n0 + 1)
    # approve through the gateway
    ra = dep.gateway.resolve_approval(gw_pid, approved=True)
    check("P14a approve -> ALLOW", ra.decision.decision == "ALLOW")
    check("P14a approve minted", ra.decision.capability is not None)
    check("P14a one resolve_pending call", len(counter.resolve_pending_calls) == 1)
    cap_id = authority.verify_capability(ra.decision.capability, dep.trusted, now=NOW).capability_id
    check("P14a capability_id recorded", cap_id in minted_ids(dep))
    # re-submit the same intent after decide -> cached result (R6/§6.3),
    # no second handle_event, no second mint
    n1 = len(counter.handle_event_calls)
    r3 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    check("P14a re-submit after decide: no second handle_event",
          len(counter.handle_event_calls) == n1)
    check("P14a re-submit returns cached result", r3.from_cache is True)
    check("P14a cached capability identical",
          r3.decision.capability == ra.decision.capability)
    check("P14a still exactly one minted capability", len(minted_ids(dep)) == 1)
    dep.gateway.close()


def p14b_unmapped_at_resolve():
    print("P14b unmapped verb smuggled into resolve -> DENY, no mint (§9.1)")
    dep, counter = _ask_deployment()
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    gw_pid = r.decision.pending_id
    # attacker tampers the gateway's pending intent to an unmapped verb
    dep.gateway._pending_by_id[gw_pid]["intent"]["verb"] = "anchor:shell/evil-unmapped"
    n_rp = len(counter.resolve_pending_calls)
    ra = dep.gateway.resolve_approval(gw_pid, approved=True)
    check("P14b resolve DENY", ra.decision.decision == "DENY")
    check("P14b guardian.resolve_pending never called",
          len(counter.resolve_pending_calls) == n_rp)
    check("P14b nothing minted", len(minted_ids(dep)) == 0)
    dep.gateway.close()


def p14c_verb_swapped_envelope_at_resolve():
    print("P14c verb-swapped envelope at resolve -> DENY, no mint (§9.2)")
    dep, counter = _ask_deployment()
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    gw_pid = r.decision.pending_id
    ask_digest = dep.gateway._pending_by_id[gw_pid]["ask_digest"]
    # verb-swapped but args-identical envelope: the kernel would accept this
    # (it never checks verb) — the gateway's §9.2 re-check must stop it.
    evil = ActionEnvelope(
        action_id=uuid.uuid4(), principal=dep.subject,
        effect=Effect(plane="shell", verb="anchor:shell/evil",
                      target="/usr/bin/backup-ask",
                      args_digest=sha256_hex(PARAMS)),
        policy_ref="smp-proto-constitution-hash",
        issued_at=NOW, not_before=NOW,
        not_after=NOW + timedelta(seconds=300),
        nonce=secrets.token_hex(16))
    assert evil.action_digest != ask_digest, "harness: digests must differ"
    n_rp = len(counter.resolve_pending_calls)
    ra = dep.gateway.resolve_approval(gw_pid, approved=True,
                                      presented_envelope=evil)
    check("P14c resolve DENY on digest mismatch", ra.decision.decision == "DENY")
    check("P14c guardian.resolve_pending never called",
          len(counter.resolve_pending_calls) == n_rp)
    check("P14c nothing minted", len(minted_ids(dep)) == 0)
    dep.gateway.close()


def p14e_reject_path():
    print("P14e ASK rejected by approver -> DENY, pending cleared")
    dep, counter = _ask_deployment()
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask", target="/usr/bin/backup-ask",
        principal=dep.subject, params=dict(PARAMS))
    gw_pid = r.decision.pending_id
    ra = dep.gateway.resolve_approval(gw_pid, approved=False)
    check("P14e reject -> DENY", ra.decision.decision == "DENY")
    check("P14e nothing minted", len(minted_ids(dep)) == 0)
    try:
        dep.gateway.resolve_approval(gw_pid, approved=True)
        check("P14e double-resolve impossible", False, "second resolve succeeded")
    except ValueError:
        check("P14e double-resolve impossible", True)
    dep.gateway.close()


# ------------------------------------------------- P15: SCITT verification
def p15_scitt_verification():
    print("P15 SCITT statements: parse, chain, nonce, binding, transparency")
    dep, counter = fresh("p15-")
    # generate a mix: allow, unmapped deny, mismatch deny, malformed error
    r_allow = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/nope", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    dep.gateway.submit_intent(
        plane="http", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    dep.gateway.submit_intent(
        plane="shell", verb="not-a-uri", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    stmts = dep.adapter._statements
    check("P15 four statements emitted", len(stmts) == 4, f"got {len(stmts)}")
    check("P15 four transparent statements stored",
          len(dep.adapter._transparent) == 4)
    trusted_logs = {dep.log_signer.key_id.encode("utf-8"):
                    Ed25519PublicKey.from_public_bytes(
                        dep.log_signer.public_key_bytes())}
    nonces, prev = set(), "0" * 64
    minted = minted_ids(dep)
    for i, s in enumerate(stmts):
        view = parse_statement(s, dep.adapter.trusted_issuers)
        c = view["claims"]
        check(f"P15[{i}] type anchor.v1/decision",
              view["statement_type"] == "anchor.v1/decision")
        check(f"P15[{i}] subject action: prefixed",
              view["subject"].startswith("action:"))
        check(f"P15[{i}] chain link", c["prev_statement_hash"] == prev,
              f"expected {prev[:12]}…, got {c['prev_statement_hash'][:12]}…")
        prev = hashlib.sha256(s).hexdigest()
        check(f"P15[{i}] nonce unique 128-bit",
              len(c["nonce"]) == 32 and c["nonce"] not in nonces)
        nonces.add(c["nonce"])
        check(f"P15[{i}] registry_digest == pinned",
              c["registry_digest"] == dep.pin["payload_hash_sha256"])
        check(f"P15[{i}] registry_keyid == owner",
              c["registry_keyid"] == dep.pin["owner_key_id"])
        if c["translation_status"] == "hit":
            check(f"P15[{i}] allow binds minted capability_id",
                  c["capability_id"] in minted,
                  f"capability_id={c['capability_id']}")
            check(f"P15[{i}] allow action_digest == envelope digest",
                  c["action_digest"] == r_allow.envelope.action_digest)
        else:
            check(f"P15[{i}] deny/error capability_id null",
                  c["capability_id"] is None)
        # transparency: receipt-carrying bytes verify end-to-end
        tv = verify_transparent_statement(dep.adapter._transparent[i],
                                          dep.adapter.trusted_issuers,
                                          trusted_logs)
        check(f"P15[{i}] transparent statement verifies",
              tv["statement"]["subject"] == view["subject"] and
              len(tv["receipts"]) == 1)
    dep.gateway.close()


# ------------------------------------------------- P16: crash window (§7.5/§7.6)
def p16a_crash_between_mint_and_emit():
    print("P16a crash between mint and statement -> reconciler re-emits")
    dep, counter = fresh("p16a-")
    dep.gateway._crash_after_mint = True
    crashed = False
    try:
        dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
    except SimulatedCrash:
        crashed = True
    check("P16a crash simulated", crashed)
    dep.gateway._crash_after_mint = False
    dks = list(dep.gateway._dlog.intents)
    check("P16a exactly one intent record", len(dks) == 1)
    dk = dks[0]
    stated = set()
    for s in dep.adapter._statements:
        v = parse_statement(s, dep.adapter.trusted_issuers)
        if v["claims"].get("dedup_key"):
            stated.add(v["claims"]["dedup_key"])
    check("P16a auditor detects missing statement", dk not in stated)
    cap_id = dep.gateway._dlog.decided[dk]["capability_id"]
    check("P16a decided record has capability_id", bool(cap_id))
    summary = dep.gateway.reconcile()
    check("P16a reconciler re-emitted", summary["re_emitted"] == [dk],
          str(summary))
    check("P16a no orphans", summary["orphaned"] == [])
    # the re-emitted statement carries the real capability_id and chains
    v = parse_statement(dep.adapter._statements[-1], dep.adapter.trusted_issuers)
    check("P16a re-emit binds capability_id", v["claims"]["capability_id"] == cap_id)
    check("P16a re-emit chained", v["claims"]["prev_statement_hash"] ==
          hashlib.sha256(dep.adapter._statements[-2]).hexdigest()
          if len(dep.adapter._statements) > 1 else True)
    check("P16a re-emit marked", "re-emitted by §7.6 reconciler" in
          (v["claims"]["deny_reason"] or ""))
    dep.gateway.close()


def p16b_crash_before_mint_orphan():
    print("P16b crash between intent record and mint -> ORPHANED + alert (§7.6b)")
    dep, counter = fresh("p16b-")
    dep.gateway._crash_before_mint = True
    crashed = False
    try:
        dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
    except SimulatedCrash:
        crashed = True
    check("P16b crash simulated", crashed)
    check("P16b zero handle_events (mint never ran)",
          len(counter.handle_event_calls) == 0)
    summary = dep.gateway.reconcile()
    dk = list(dep.gateway._dlog.intents)[0]
    check("P16b marked orphaned", summary["orphaned"] == [dk], str(summary))
    check("P16b nothing re-emitted", summary["re_emitted"] == [])
    check("P16b operator alert raised",
          any("ORPHANED" in a for a in dep.gateway._dlog.alerts))
    check("P16b no statement for orphan",
          all(parse_statement(s, dep.adapter.trusted_issuers)["claims"].get("dedup_key") != dk
              for s in dep.adapter._statements))
    dep.gateway.close()


# ------------------------------------------------- P17: SCITT write failure (§5.2)
def p17_scitt_write_failure():
    print("P17 SCITT write failure -> DENY stands, outage counter, latch (§5.2)")
    import smp_v1_1_prototype as proto
    dep, counter = fresh("p17-")
    orig_issue = proto.issue_statement
    n0 = len(counter.handle_event_calls)

    def scitt_down(*a, **k):
        raise RuntimeError("SCITT write failed (injected)")

    # Phase A: one translation while SCITT is down (unmapped -> deny emit fails)
    proto.issue_statement = scitt_down
    try:
        r = dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/rm-rf-everything",
            target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
    finally:
        proto.issue_statement = orig_issue
    check("P17 DENY stands on SCITT failure", r.decision.decision == "DENY")
    check("P17 refusal names the SCITT failure", "SCITT" in r.decision.reason,
          r.decision.reason[:80])
    check("P17 no handle_event (pre-forward DENY)",
          len(counter.handle_event_calls) == n0)
    check("P17 scitt_outage counter == 1 (durable log)",
          dep.gateway._dlog.scitt_outage == 1,
          f"got {dep.gateway._dlog.scitt_outage}")
    check("P17 adapter outage mirror == 1",
          dep.adapter._scitt_outage_count == 1)
    check("P17 no statements stored while SCITT down",
          len(dep.adapter._statements) == 0)
    check("P17 no latch after a single failure",
          dep.adapter._scitt_latched is False)
    # translation continues: a healthy translation proceeds normally
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P17 translation continues (healthy -> ALLOW)",
          r2.decision.decision == "ALLOW")
    check("P17 healthy emit chained from genesis",
          parse_statement(dep.adapter._statements[0],
                          dep.adapter.trusted_issuers)["claims"]
          ["prev_statement_hash"] == "0" * 64)

    # Phase B (C1a): adapter bug + SCITT down — the catch-all's own emit
    # failing must surface as SMPRefusal, never a raw exception.
    class BoomEnvelope:
        def __init__(self, *a, **k):
            raise RuntimeError("adapter bug (injected)")
    proto.issue_statement = scitt_down
    orig_envelope = proto.ActionEnvelope
    proto.ActionEnvelope = BoomEnvelope
    raised = None
    try:
        dep.adapter.translate(
            plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS), event_id="smp-p17")
    except SMPRefusal as exc:
        raised = f"SMPRefusal: {exc}"
    except Exception as exc:  # noqa: BLE001 — the forbidden outcome
        raised = f"{type(exc).__name__}: {exc}"
    finally:
        proto.ActionEnvelope = orig_envelope
        proto.issue_statement = orig_issue
    check("P17 catch-all emit failure -> SMPRefusal, never raw",
          raised is not None and raised.startswith("SMPRefusal"), str(raised))
    check("P17 outage counter == 2 after catch-all failure",
          dep.gateway._dlog.scitt_outage == 2,
          f"got {dep.gateway._dlog.scitt_outage}")

    # Phase C: persistent failures reach the threshold -> latch + alert
    proto.issue_statement = scitt_down
    try:
        dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/rm-rf-everything",
            target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
    finally:
        proto.issue_statement = orig_issue
    check("P17 outage counter == 3 (threshold)",
          dep.gateway._dlog.scitt_outage == 3,
          f"got {dep.gateway._dlog.scitt_outage}")
    check("P17 adapter latched refuse-all",
          dep.adapter._scitt_latched is True)
    check("P17 operator alert raised",
          any("SCITT OUTAGE" in a for a in dep.gateway._dlog.alerts),
          str(dep.gateway._dlog.alerts[-1:]))

    # Phase D: while latched, even healthy translations refuse; no new
    # emit attempts (counter stays flat — no storm, no inflation)
    r3 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P17 latched: healthy translation still DENY",
          r3.decision.decision == "DENY")
    check("P17 latched refusal names SCITT outage", "SCITT" in r3.decision.reason)
    check("P17 latched: no handle_event",
          len(counter.handle_event_calls) == n0 + 1,
          f"calls={len(counter.handle_event_calls)}")
    proto.issue_statement = scitt_down
    try:
        dep.gateway.submit_intent(
            plane="shell", verb="anchor:shell/rm-rf-everything",
            target="/usr/bin/backup",
            principal=dep.subject, params=dict(PARAMS))
    finally:
        proto.issue_statement = orig_issue
    check("P17 latched: outage counter flat (no emit attempts)",
          dep.gateway._dlog.scitt_outage == 3,
          f"got {dep.gateway._dlog.scitt_outage}")
    check("P17 latched: refused-while-latched counter == 2",
          dep.adapter._scitt_latched_refused == 2)
    check("P17 latched: no statements attempted",
          len(dep.adapter._statements) == 1)

    # Phase E: durability — the counter survives in the WAL across replay
    wal = dep.gateway._dlog._path.read_text(encoding="utf-8")
    check("P17 3 scitt_outage ops durable in WAL",
          sum(1 for line in wal.splitlines()
              if '"op": "scitt_outage"' in line) == 3)
    wal_path = dep.gateway._dlog._path
    dep.gateway.close()
    from smp_v1_1_prototype import DecisionLog
    dlog2 = DecisionLog(wal_path)
    check("P17 outage count survives WAL replay", dlog2.scitt_outage == 3,
          f"got {dlog2.scitt_outage}")
    dlog2.close()


# ------------------------------------------------- P18: single compromise statement (§5.3)
def p18_single_compromise_statement():
    print("P18 registry compromise -> exactly ONE compromise statement (§5.3)")
    dep, counter = fresh("p18-")
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P18 baseline ALLOW before mutation", r0.decision.decision == "ALLOW")
    n_stmt_before = len(dep.adapter._statements)
    # flip the retained canonical payload bytes -> §3.9 latch on next translation
    raw = bytearray(dep.registry._payload_bytes)
    raw[100] ^= 0xFF
    dep.registry._payload_bytes = bytes(raw)
    refused = [dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS)) for _ in range(3)]
    check("P18 all 3 refused while latched",
          all(r.decision.decision == "DENY" for r in refused))
    compromise = [s for s in dep.adapter._statements[n_stmt_before:]
                  if parse_statement(
                      s, dep.adapter.trusted_issuers)["claims"]
                  ["translation_status"] == "registry_compromise"]
    check("P18 exactly ONE registry_compromise statement",
          len(compromise) == 1, f"got {len(compromise)}")
    check("P18 no per-intent statements while latched",
          len(dep.adapter._statements) == n_stmt_before + 1,
          f"statements={len(dep.adapter._statements)}")
    check("P18 local refused-counter == 3",
          dep.adapter._latched_refused_count == 3,
          f"got {dep.adapter._latched_refused_count}")
    check("P18 zero post-mutation handle_events",
          len(counter.handle_event_calls) == 1,
          f"calls={len(counter.handle_event_calls)}")
    dep.gateway.close()



# ------------------------------------------------- P19: duplicate registry key (§3.4)
def p19_duplicate_key_rejected():
    print("P19 duplicate (plane, qualified_verb, target_shape) -> startup "
          "refusal naming BOTH entries (§3.4)")
    # The P3b shadow shape: identical triple to e001, different
    # presented_verb, so the R3 (plane, presented_verb) injectivity check
    # passes and ONLY the new §3.4 duplicate-key rule can fire.
    entries = default_entries() + [{
        "entry_id": "e-shadow", "plane": "shell",
        "qualified_verb": "anchor:shell/exec",
        "target_shape": {"kind": "exact", "value": "/usr/bin/backup"},
        "presented_verb": "anchor:shell/exec-shadow",
        "acs_action": "anchor:acs/backup.run",
        "acs_resource": "backup:host-a"}]
    detail = ""
    deployment_built = True
    try:
        fresh("p19-", entries=entries)  # signed inside build_deployment
    except SMPRefusal as exc:
        deployment_built = False
        detail = str(exc)
    check("P19 duplicate key refused at load",
          not deployment_built, detail if detail else "NOT REFUSED")
    check("P19 names both colliding entries",
          "'e001'" in detail and "'e-shadow'" in detail, detail)
    check("P19 refusal is the §3.4 duplicate-key rule (not R3)",
          "§3.4" in detail and "duplicate registry key" in detail, detail)
    # Prove the refusal is a pre-gateway LOAD failure: build the same
    # duplicate registry signed by an explicit owner key and load
    # MappingRegistry directly — no adapter/guardian/gateway objects are
    # ever constructed, so zero handle_event calls are possible.
    owner = Ed25519Signer.generate("p19/registry-owner")
    payload = build_registry_payload(
        version="2026-09-23-r1", owner_key_id=owner.key_id,
        spiffe_id="spiffe://p19/owner", entries=entries,
        issued_at=NOW.isoformat())
    doc = sign_registry(payload, owner)   # properly signed, valid signature
    pin = make_pin(version="2026-09-23-r1",
                   payload_hash_sha256=hashlib.sha256(
                       canonical_bytes(payload)).hexdigest(),
                   owner_key_id=owner.key_id)
    refused2, detail2 = False, ""
    try:
        MappingRegistry(registry_doc=doc, pin=pin,
                        owner_pubkey=owner.public_key_bytes())
    except SMPRefusal as exc:
        refused2, detail2 = True, str(exc)
    check("P19 signed duplicate doc refused at MappingRegistry.load "
          "(pre-gateway)", refused2, detail2)
    check("P19 direct-load refusal names both entries",
          "'e001'" in detail2 and "'e-shadow'" in detail2, detail2)
    check("P19 zero handle_event calls possible (no gateway was built)",
          not deployment_built and refused2, "no deployment returned")


def p19b_distinct_target_shape_loads():
    print("P19b same (plane, qualified_verb), distinct target_shape -> "
          "loads fine, both entries reachable")
    entries = default_entries() + [{
        "entry_id": "e-exec-logs", "plane": "shell",
        "qualified_verb": "anchor:shell/exec",        # same as e001
        "target_shape": {"kind": "prefix", "value": "/var/log/"},  # different
        "presented_verb": "anchor:shell/exec-logs",  # -> no R3 collision
        "acs_action": "anchor:acs/log.read",
        "acs_resource": "logs:host-a"}]
    dep, counter = fresh("p19b-", entries=entries)
    check("P19b distinct-shape registry loads without refusal", True,
          "no refusal raised")
    r1 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/var/log/syslog",
        principal=dep.subject, params=dict(PARAMS))
    check("P19b exact-shape entry still resolves", r1.status == "hit_allow",
          r1.status)
    check("P19b prefix-shape entry resolves", r2.status == "hit_allow",
          r2.status)
    check("P19b both entries independently minted (no shadowing)",
          len(counter.handle_event_calls) == 2,
          f"handle_event calls={len(counter.handle_event_calls)}")
    dep.gateway.close()


def main() -> None:
    probes = [p01_valid_mapped_intent, p02_registry_tamper, p03_signature_forgery,
              p04_runtime_mutation, p05_unmapped_verb, p06_uppercase_verb,
              p07_overlong_uri, p08_malformed_uris, p09_n_to_1_rejected,
              p10_fictitious_plane, p11_namespace_plane_mismatch,
              p12_prefix_shape, p13_double_mint_concurrency,
              p14a_ask_approve_flow, p14b_unmapped_at_resolve,
              p14c_verb_swapped_envelope_at_resolve, p14e_reject_path,
              p15_scitt_verification, p16a_crash_between_mint_and_emit,
              p16b_crash_before_mint_orphan, p17_scitt_write_failure,
              p18_single_compromise_statement,
              p19_duplicate_key_rejected, p19b_distinct_target_shape_loads]
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
    print("RESULT: all adversarial probes green — R2-R11 prototype battle-tested.")


if __name__ == "__main__":
    main()
