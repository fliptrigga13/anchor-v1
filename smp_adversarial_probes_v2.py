#!/usr/bin/env python3
"""ADVERSARIAL PROBES — builder-v2, second battle-test of Gemini's revised
v1.1 SMP spec (~/workspace/goals/agent-boardroom/hidden_files/
gemini-thread-2026-09-23-1928.md, message #6).

Device under test: the CURRENT round-1 reference prototype
(~/workspace/anchor-v1/smp_v1_1_prototype.py — the hardened 1196-line
revision with MappingRegistry/SmpGateway, NOT the earlier draft). It is
FRIENDLY code reused as the executable embodiment of the revised spec's
claims. The job here is to BREAK it: every probe attacks a claim in the
revised spec / the reference implementation, using REAL v1.0.1 modules
only (zero mocks).

Probes:
  P1  shim-layer interception ordering + the spec's contradictory reading
      (sec.1: "It never routes to the Guardian natively; it mutates the
      envelope for the appropriate PEP" vs sec.7: "calls handle_event ->
      receives the newly minted capability_id")
  P2  registry-mutation fail-closed: (a) disk-file change post-load,
      (b1) in-memory _payload_bytes tamper, (b2) in-memory _entries tamper
  P3  N-to-1 rejection (spec: "categorically rejected"): (a) same
      presented_verb from two source verbs, (b) duplicate source verb
      (1-to-N shadow), (c) exact/prefix overlap order-dependence
  P4  SCITT receipt binding via the REAL scitt module: verify the full
      statement+receipt chain and all bound fields; then registry-swap
      and field-tamper attacks
  P5  double-mint: (a) gateway dedup under fixed clock, (b) gateway dedup
      under advancing clock, (c) kernel handle_event twice, same event_id
  P6  resolve_pending + allowlist: (a) gateway path under fixed clock,
      (b) gateway path under advancing clock (self-DoS), (c) direct
      guardian.resolve_pending bypass with an unmapped verb,
      (d) direct handle_event with an unmapped presented envelope

Each probe prints PASS/FAIL with the observed output. NOTE on polarity:
PASS = attack repelled / claim held; FAIL = spec claim BROKE under attack.

Run: ./.venv/bin/python smp_adversarial_probes_v2.py from ~/workspace/anchor-v1.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sys
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")
sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import smp_v1_1_prototype as proto
from anchor_v1 import authority
from anchor_v1.acs_guardian import GuardianEvent
from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.pep import CredentialBroker, PEPError, ShellPEP
from anchor_v1.scitt import SCITTError, verify_transparent_statement
from anchor_v1.store import CapabilityStore

SCRATCH = Path("/tmp/smp-probe-v2")
import shutil as _shutil
if SCRATCH.exists():
    _shutil.rmtree(SCRATCH)  # DecisionLog WALs replay across runs; start clean
SCRATCH.mkdir(parents=True, exist_ok=True)
T0 = datetime.now(timezone.utc)
CONSTITUTION = "smp-proto-constitution-hash"
PARAMS = {"cmd": "echo smp", "timeout_s": 30}

results: list[tuple[str, str, str]] = []


def verdict(name: str, ok: bool, detail: str):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}\n        {detail}")
    results.append((name, tag, detail))


def dep(tag: str, entries=None, decision_fn=None, clock=None):
    """Fresh full deployment. clock: dict(t=datetime) for a mutable clock."""
    workdir = SCRATCH / tag
    now_fn = (lambda: clock["t"]) if clock is not None else (lambda: T0)
    return proto.build_deployment(workdir=workdir, entries=entries,
                                  decision_fn=decision_fn, now_fn=now_fn)


def entry(eid, qv, pv, kind, value, acs_action="anchor:acs/backup.run",
          acs_resource="backup:host-a", plane="shell"):
    return {"entry_id": eid, "plane": plane, "qualified_verb": qv,
            "target_shape": {"kind": kind, "value": value},
            "presented_verb": pv, "acs_action": acs_action,
            "acs_resource": acs_resource}


def spy_on(d, attr="handle_event"):
    calls = []
    orig = getattr(d.guardian, attr)
    def wrapper(*a, **kw):
        calls.append((a, kw))
        return orig(*a, **kw)
    setattr(d.guardian, attr, wrapper)
    return calls


print("=" * 78)
print("P1 — SHIM-LAYER INTERCEPTION ORDERING + CONTRADICTORY READING")
print("=" * 78)

d = dep("p1")
calls = spy_on(d)
res = d.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                              target="/usr/bin/backup", principal=d.subject,
                              params=dict(PARAMS))
presented = calls[0][1].get("presented_envelope")
payload = authority.verify_capability(res.decision.capability, d.trusted,
                                      now=T0)
p1a = (res.decision.decision == "ALLOW"
       and presented is res.envelope
       and presented.action_digest == res.envelope.action_digest
       and payload.action_digest == res.envelope.action_digest)
verdict("P1a translate strictly pre-forward; mint binds translated digest",
        p1a,
        f"handle_event received the ADAPTER-BUILT envelope (identity match "
        f"{presented is res.envelope}); digest "
        f"{res.envelope.action_digest[:12]}... == payload binding; "
        f"orchestrator verb 'anchor:shell/exec' never appears in kernel "
        f"state — only the digest does")

# P1b: the spec's contradictory reading (sec.1 literal): hand the translated
# envelope to ShellPEP directly, bypassing handle_event entirely.
store = CapabilityStore()
store.sync_revocations([], now=T0.timestamp())
store.register_capability(payload)
shell = ShellPEP(CredentialBroker({"T": "v"}), store, d.trusted,
                 secrets.token_bytes(32))
shell.register_command(res.envelope.action_digest, ["echo", "smp"])
try:
    shell.execute(envelope=res.envelope, capability_cose=b"bogus-cose-bytes",
                  holder_proof=b"\x00" * 64)
    verdict("P1b PEP-without-kernel (sec.1 literal reading)", False,
            "executed with NO kernel decision — catastrophic")
except PEPError as exc:
    verdict("P1b PEP-without-kernel (sec.1 literal reading)", True,
            f"rejected as required — PEPError: {exc}")

# P1c: capability minted for digest A, executed against envelope digest B.
evil_env = ActionEnvelope(
    action_id=res.envelope.action_id, principal=d.subject,
    effect=Effect(plane="shell", verb="anchor:shell/exec",
                  target="/usr/bin/EVIL",
                  args_digest=sha256_hex(dict(PARAMS))),
    policy_ref=CONSTITUTION, issued_at=T0, not_before=T0,
    not_after=T0 + timedelta(seconds=300), nonce=secrets.token_hex(16))
shell.register_command(evil_env.action_digest, ["echo", "evil"])
proof = authority.make_holder_proof(d.holder, payload.capability_id,
                                    shell.challenge)
try:
    shell.execute(envelope=evil_env, capability_cose=res.decision.capability,
                  holder_proof=proof)
    verdict("P1c capability/envelope digest mismatch", False,
            "executed with wrong envelope — binding broken")
except PEPError as exc:
    verdict("P1c capability/envelope digest mismatch", True,
            f"rejected — PEPError: {exc}")
d.gateway.close()

print()
print("=" * 78)
print("P2 — REGISTRY-MUTATION FAIL-CLOSED")
print("     Spec: 'If the underlying disk file hash changes at runtime, or if")
print("     the memory state is tampered with, the SMP enters a fail-closed")
print("     panic state, refusing all subsequent translations.'")
print("=" * 78)

d = dep("p2")
# P2a: mutate the registry FILE on disk after startup (attacker appends an
# entry; cannot re-sign without the owner key, so the file no longer matches
# the pin — but the adapter never re-reads the file).
doc = json.loads(d.registry_path.read_text())
doc["payload"]["entries"].append(
    entry("evil", "anchor:shell/pwn", "anchor:shell/pwn", "exact",
          "/usr/bin/pwn"))
d.registry_path.write_text(json.dumps(doc, indent=2) + "\n")
try:
    r = d.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                target="/usr/bin/backup",
                                principal=d.subject, params=dict(PARAMS))
    ok = r.decision.decision == "ALLOW"
    verdict("P2a disk-file mutation at runtime", not ok,
            f"disk registry TAMPERED post-startup; translation still "
            f"{r.decision.decision} — assert_live() re-hashes only the "
            f"IN-MEMORY payload bytes, the disk file is NEVER re-read, so "
            f"the spec's 'disk file hash changes at runtime -> panic' is "
            f"UNIMPLEMENTED in the reference")
except proto.SMPRefusal as exc:
    verdict("P2a disk-file mutation at runtime", True, f"refused: {exc}")

# P2b1: flip a byte in the retained in-memory payload bytes.
# NOTE: SmpGateway.submit_intent converts adapter SMPRefusal into a DENY
# result (it does not propagate), so detection is observed via the decision.
d2 = dep("p2b1")
raw = bytearray(d2.registry._payload_bytes)
raw[100] ^= 0xFF
d2.registry._payload_bytes = bytes(raw)
r = d2.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                             target="/usr/bin/backup", principal=d2.subject,
                             params=dict(PARAMS))
detected = (r.decision.decision == "DENY" and d2.registry._dead)
verdict("P2b1 in-memory payload-bytes tamper", detected,
        f"decision={r.decision.decision}, latched_dead={d2.registry._dead} "
        f"— byte-level tamper of the retained payload IS detected and latches "
        f"the adapter dead (this half of the claim holds)")

# P2b2: tamper the PARSED in-memory entries (the actual allowlist the
# lookup() consults) — redirect e001's target to an attacker path.
# v11d: RegistryEntry is a frozen dataclass, so the UNPRIVILEGED path
# (plain assignment) is repelled at the assignment itself
# (FrozenInstanceError). The PRIVILEGED path (object.__setattr__) is
# covered by the v11e V-C1 probe (re-derived integrity check -> DENY +
# latch). Either way, no mint for the attacker target may occur.
d3 = dep("p2b2")
tamper_repelled_at_assignment = False
for e in d3.registry._entries:
    if e.entry_id == "e001":
        try:
            e.target_value = "/usr/bin/attacker-tool"   # in-memory redirect
        except FrozenInstanceError:
            tamper_repelled_at_assignment = True
r = d3.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                             target="/usr/bin/attacker-tool",
                             principal=d3.subject, params=dict(PARAMS))
redirect_minted = (r.decision.decision == "ALLOW")
verdict("P2b2 in-memory _entries tamper (allowlist redirect)",
        not redirect_minted,
        f"decision={r.decision.decision} for attacker target "
        f"/usr/bin/attacker-tool — unprivileged tamper repelled at "
        f"assignment (FrozenInstanceError: {tamper_repelled_at_assignment}); "
        f"v11e re-derivation additionally latches on privileged "
        f"object.__setattr__ tamper (see V-C1)")
d.gateway.close(); d2.gateway.close(); d3.gateway.close()

print()
print("=" * 78)
print("P3 — N-TO-1 REJECTION ('categorically rejected')")
print("=" * 78)

# P3a: two distinct source verbs -> the SAME presented verb (=> same kernel
# digest for identical target/principal/params).
n2o = [entry("n1", "anchor:shell/run", "anchor:shell/exec", "exact",
             "/usr/bin/backup"),
       entry("n2", "anchor:shell/run_admin", "anchor:shell/exec", "exact",
             "/usr/bin/backup")]
try:
    d = dep("p3a", entries=n2o)
    verdict("P3a N-to-1 load-time rejection", False,
            "registry with two source verbs -> one presented verb ACCEPTED")
    d.gateway.close()
except proto.SMPRefusal as exc:
    verdict("P3a N-to-1 load-time rejection", True,
            f"categorically rejected at load — SMPRefusal: {str(exc)[:110]}...")

# P3b (adversarial edge): the REVERSE — one source verb, two presented verbs
# (1-to-N shadow). The §3.4 load-time check refuses registries where two
# entries share the identical (plane, qualified_verb, target_shape) triple,
# so the "dead registry text / first-match-wins" hazard this probe used to
# document can no longer load: it is refused at startup, fail-closed.
one2n = [entry("s1", "anchor:shell/run", "anchor:shell/exec", "exact",
              "/usr/bin/backup"),
         entry("s2", "anchor:shell/run", "anchor:shell/exec2", "exact",
              "/usr/bin/backup")]
try:
    d = dep("p3b", entries=one2n)
    verdict("P3b duplicate source verb (1-to-N shadow)", False,
            "registry with duplicate (plane, qualified_verb, target_shape) "
            "ACCEPTED at load — §3.4 check bypassed")
    d.gateway.close()
except proto.SMPRefusal as exc:
    verdict("P3b duplicate source verb (1-to-N shadow)", True,
            f"refused at load per §3.4 (no dead registry text possible) — "
            f"SMPRefusal: {str(exc)[:110]}...")

# P3c: order-dependence — closed by the same §3.4 load-time refusal: a
# registry whose entries would exhibit order-dependent lookup never loads.
try:
    d = dep("p3c-rev", entries=list(reversed(one2n)))
    verdict("P3c duplicate-source order-dependence", False,
            "order-dependent registry ACCEPTED at load — §3.4 check bypassed")
    d.gateway.close()
except proto.SMPRefusal as exc:
    verdict("P3c duplicate-source order-dependence", True,
            f"refused at load per §3.4 (order-dependence impossible) — "
            f"SMPRefusal: {str(exc)[:110]}...")

print()
print("=" * 78)
print("P4 — SCITT RECEIPT BINDING (real scitt module)")
print("=" * 78)

d = dep("p4")
res = d.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                              target="/usr/bin/backup", principal=d.subject,
                              params=dict(PARAMS))
payload = authority.verify_capability(res.decision.capability, d.trusted,
                                      now=T0)
transparent = d.adapter._transparent[-1]
view = verify_transparent_statement(transparent, d.adapter.trusted_issuers,
                                    d.adapter._log_trusted)
claims = view["statement"]["claims"]
have = {k: claims.get(k) for k in
        ["nonce", "prev_statement_hash", "registry_digest", "registry_keyid",
         "registry_version", "original_verb", "original_target",
         "translated_verb", "action_digest", "capability_id", "dedup_key"]}
complete = all(v is not None for v in have.values())
verdict("P4a full statement+receipt verify; bindings present",
        complete and claims["capability_id"] == payload.capability_id
        and claims["action_digest"] == res.envelope.action_digest
        and claims["registry_digest"] == d.registry.digest,
        f"verify_transparent_statement OK (issuer sig + log receipt sig); "
        f"nonce={claims['nonce'][:8]}... registry_digest="
        f"{claims['registry_digest'][:12]}... original_verb="
        f"{claims['original_verb']} action_digest="
        f"{claims['action_digest'][:12]}... capability_id="
        f"{claims['capability_id'][:8]}...")
print("        DEVIATION vs spec: the bound 'nonce' is SMP-GENERATED in "
      "_emit_statement, NOT 'the orchestrator's inbound request nonce' — "
      "submit_intent mints its own event_id and the orchestrator supplies "
      "no nonce at all. The five-binding claim overstates provenance.")

# P4b ATTACK: registry swap — build a second deployment with a different
# registry (different digest), then re-verify the OLD receipt.
d_swap = dep("p4swap", entries=[
    entry("w1", "anchor:shell/run", "anchor:shell/exec", "exact",
          "/usr/bin/other")])
try:
    v2 = verify_transparent_statement(transparent,
                                      d.adapter.trusted_issuers,
                                      d.adapter._log_trusted)
    same_pin = (v2["statement"]["claims"]["registry_digest"]
                == d_swap.registry.digest)
    verdict("P4b registry-swap detection from the receipt ALONE", False,
            f"OLD receipt still verifies cleanly after the registry was "
            f"swapped (receipt pin={d.registry.digest[:12]}... vs current "
            f"pin={d_swap.registry.digest[:12]}..., equal={same_pin}). "
            f"Cryptography says 'valid' — the swap is detectable ONLY by "
            f"comparing the receipt's registry_digest claim against an "
            f"EXTERNALLY held expected pin. The receipt alone cannot raise "
            f"the alarm.")
except Exception as exc:
    verdict("P4b registry-swap detection", True,
            f"re-verify failed: {type(exc).__name__}: {exc}")

# P4c ATTACK: tamper one claim byte inside the transparent statement.
raw = bytearray(transparent)
anchor = raw.find(b"capability_id")
assert anchor != -1
raw[anchor + 20] ^= 0xFF
try:
    verify_transparent_statement(bytes(raw), d.adapter.trusted_issuers,
                                 d.adapter._log_trusted)
    verdict("P4c claim-field tamper", False,
            "TAMPERED receipt VERIFIED — signature binding broken")
except Exception as exc:
    verdict("P4c claim-field tamper", True,
            f"re-verify fails closed — {type(exc).__name__}: {str(exc)[:120]}")
d.gateway.close(); d_swap.gateway.close()

print()
print("=" * 78)
print("P5 — DOUBLE-MINT")
print("=" * 78)

# P5a: fixed clock — same intent twice through the gateway.
d = dep("p5a")
calls = spy_on(d)
r1 = d.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                             target="/usr/bin/backup", principal=d.subject,
                             params=dict(PARAMS))
r2 = d.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                             target="/usr/bin/backup", principal=d.subject,
                             params=dict(PARAMS))
p1 = authority.verify_capability(r1.decision.capability, d.trusted, now=T0)
p2 = authority.verify_capability(r2.decision.capability, d.trusted, now=T0)
verdict("P5a gateway dedup, fixed clock",
        len(calls) == 1 and r2.from_cache
        and p1.capability_id == p2.capability_id,
        f"one handle_event call, second submit from_cache={r2.from_cache}, "
        f"same capability_id {p1.capability_id[:8]}... — dedup holds")
d.gateway.close()

# P5b: ADVERSARIAL — advancing clock. dedup_key embeds the validity window
# [nb, na], so the same logical event 10s later gets a NEW dedup_key.
clock = {"t": T0}
d = dep("p5b", clock=clock)
calls = spy_on(d)
kw = dict(plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
          principal=d.subject, params=dict(PARAMS))
ra = d.gateway.submit_intent(**kw)
clock["t"] = T0 + timedelta(seconds=10)
rb = d.gateway.submit_intent(**kw)
pa = authority.verify_capability(ra.decision.capability, d.trusted, now=T0)
pb = authority.verify_capability(rb.decision.capability, d.trusted, now=T0)
double = (len(calls) == 2 and ra.decision.decision == "ALLOW"
          and rb.decision.decision == "ALLOW"
          and pa.capability_id != pb.capability_id)
verdict("P5b gateway dedup, clock +10s (retry semantics)", not double,
        f"TWO handle_event calls, TWO mints: {pa.capability_id[:8]}... vs "
        f"{pb.capability_id[:8]}... — dedup_key embeds [nb,na], so a retry "
        f"of the SAME logical event after the clock moves is a 'new' event. "
        f"'One capability per decided event' holds only within a frozen "
        f"time window; the gateway cannot distinguish retry from new event")
d.gateway.close()

# P5c: kernel reality — same event_id twice, straight to the Guardian.
d = dep("p5c")
gk = d.guardian
env = ActionEnvelope(
    action_id=res.envelope.action_id, principal=d.subject,
    effect=Effect(plane="shell", verb="anchor:shell/exec",
                  target="/usr/bin/backup",
                  args_digest=sha256_hex(dict(PARAMS))),
    policy_ref=CONSTITUTION, issued_at=T0, not_before=T0,
    not_after=T0 + timedelta(seconds=300), nonce=secrets.token_hex(16))
evk = GuardianEvent(event_id="evt-p5k", event_type="pre_tool_call",
                    session_id="sess-smp", subject=d.subject,
                    action="anchor:acs/backup.run",
                    resource="backup:host-a", params=dict(PARAMS), ts=T0)
da = gk.handle_event(evk, presented_envelope=env)
db = gk.handle_event(evk, presented_envelope=env)
qa = authority.verify_capability(da.capability, d.trusted, now=T0)
qb = authority.verify_capability(db.capability, d.trusted, now=T0)
verdict("P5c kernel handle_event x2, same event_id",
        not (da.decision == "ALLOW" and db.decision == "ALLOW"),
        f"kernel minted TWICE for one event_id: {qa.capability_id[:8]}... "
        f"and {qb.capability_id[:8]}... — v1.0.1 has NO mint dedup; the "
        f"spec's 'prerequisite' is unmet in the kernel, and any second "
        f"in-process caller of handle_event double-mints")
d.gateway.close()

print()
print("=" * 78)
print("P6 — RESOLVE_PENDING + ALLOWLIST")
print("=" * 78)

# P6: gateway submit with an UNMAPPED verb — the adapter-side control.
d = dep("p6")
r = d.gateway.submit_intent(plane="shell", verb="anchor:shell/rm_rf_root",
                            target="/usr/bin/backup", principal=d.subject,
                            params=dict(PARAMS))
verdict("P6a unmapped verb via gateway", r.decision.decision == "DENY",
        f"adapter refused pre-forward: decision={r.decision.decision} "
        f"reason={str(r.decision.reason)[:80]}")

# P6b: ASK -> gateway resolve_approval under a FIXED clock.
d_ask = dep("p6b", decision_fn=lambda ev: "ASK")
ra = d_ask.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                 target="/usr/bin/backup",
                                 principal=d_ask.subject,
                                 params=dict(PARAMS))
assert ra.decision.decision == "ASK", ra.decision.decision
gw_pid = ra.decision.pending_id
rr = d_ask.gateway.resolve_approval(gw_pid, approved=True)
verdict("P6b gateway resolve_approval, fixed clock",
        rr.decision.decision == "ALLOW",
        f"re-ran identical translate() + §9.2 digest check, then "
        f"guardian.resolve_pending -> {rr.decision.decision}")

# P6c: ADVERSARIAL — same, but the clock moved between ASK and resolve.
# translate() is deterministic in `now`, so the re-translated envelope digest
# != ask_digest -> the gateway denies its OWN legitimate approval.
clock = {"t": T0}
d_ask2 = dep("p6c", decision_fn=lambda ev: "ASK", clock=clock)
ra = d_ask2.gateway.submit_intent(plane="shell", verb="anchor:shell/exec",
                                  target="/usr/bin/backup",
                                  principal=d_ask2.subject,
                                  params=dict(PARAMS))
gw_pid = ra.decision.pending_id
clock["t"] = T0 + timedelta(seconds=10)
rr = d_ask2.gateway.resolve_approval(gw_pid, approved=True)
verdict("P6c gateway resolve_approval, clock +10s (self-DoS)", 
        rr.decision.decision == "ALLOW",
        f"honest approval path -> {rr.decision.decision} "
        f"({str(rr.decision.reason)[:70]}): the §9.2 ASK-time digest re-check "
        f"compares against a now-dependent digest, so ANY clock movement "
        f"between ASK and resolve denies a legitimate approval — ASK "
        f"approvals are hostage to clock stasis")

# P6d: ADVERSARIAL — bypass the gateway: call the KERNEL's resolve_pending
# directly with a presented envelope whose verb the allowlist would refuse.
# Kernel validates principal/args_digest/policy_ref/window only; verb is
# kernel-opaque by design.
# v11d F1 fix: P6c's honest resolve now ALLOWs and consumes the pending
# binding, so P6d takes a fresh ASK (a different intent, to avoid P6c's
# decided dedup_key) for a live kernel pending_id.
ra_p6d = d_ask2.gateway.submit_intent(plane="shell",
                                     verb="anchor:shell/backup-ask",
                                     target="/usr/bin/backup-ask",
                                     principal=d_ask2.subject,
                                     params=dict(PARAMS))
assert ra_p6d.decision.decision == "ASK", ra_p6d.decision.decision
gw_pid_p6d = ra_p6d.decision.pending_id
kernel_pid = d_ask2.gateway._pending_by_id[gw_pid_p6d]["kernel_pending_id"]
import uuid as _uuid
evil = ActionEnvelope(
    action_id=_uuid.uuid4(), principal=d_ask2.subject,
    effect=Effect(plane="shell", verb="anchor:shell/rm_rf_root",
                  target="/usr/bin/backup",
                  args_digest=sha256_hex(dict(PARAMS))),
    policy_ref=CONSTITUTION, issued_at=clock["t"],
    not_before=clock["t"] - timedelta(seconds=5),
    not_after=clock["t"] + timedelta(seconds=300),
    nonce=secrets.token_hex(16))
rk = d_ask2.guardian.resolve_pending(kernel_pid, True,
                                     presented_envelope=evil)
if rk.decision == "ALLOW" and rk.capability:
    qk = authority.verify_capability(rk.capability, d_ask2.trusted, now=T0)
    verdict("P6d direct kernel resolve_pending, unmapped verb", False,
            f"kernel MINTED cap {qk.capability_id[:8]}... for verb "
            f"'anchor:shell/rm_rf_root' — the allowlist gates ONLY the "
            f"gateway; any in-process holder of the guardian reference "
            f"bypasses it entirely on the resolve path")
else:
    verdict("P6d direct kernel resolve_pending, unmapped verb", True,
            f"kernel refused: {rk.decision} {rk.reason}")

# P6e: same bypass on the submit path — direct handle_event on an ALLOW
# guardian with an unmapped presented envelope. The kernel is verb-opaque
# by design (red-team-2 P5 / THREAT_MODEL item 12), so it mints.
d6e = dep("p6e")  # default decision_fn -> ALLOW
rk2 = d6e.guardian.handle_event(
    GuardianEvent(event_id="evt-p6e", event_type="pre_tool_call",
                  session_id="sess-smp", subject=d6e.subject,
                  action="anchor:acs/backup.run", resource="backup:host-a",
                  params=dict(PARAMS), ts=T0),
    presented_envelope=ActionEnvelope(
        action_id=__import__("uuid").uuid4(), principal=d6e.subject,
        effect=Effect(plane="shell", verb="anchor:shell/rm_rf_root",
                      target="/usr/bin/backup",
                      args_digest=sha256_hex(dict(PARAMS))),
        policy_ref=CONSTITUTION, issued_at=T0, not_before=T0,
        not_after=T0 + timedelta(seconds=300), nonce=secrets.token_hex(16)))
if rk2.decision == "ALLOW" and rk2.capability:
    q2 = authority.verify_capability(rk2.capability, d6e.trusted, now=T0)
    verdict("P6e direct kernel handle_event, unmapped verb", False,
            f"kernel MINTED cap {q2.capability_id[:8]}... for verb "
            f"'anchor:shell/rm_rf_root' — verb/target are kernel-opaque; "
            f"the exact-match allowlist lives ONLY in the adapter, so "
            f"EVERY direct Guardian caller bypasses it on the submit path too")
else:
    verdict("P6e direct kernel handle_event, unmapped verb", True,
            f"kernel refused: {rk2.decision} {rk2.reason}")
d6e.gateway.close()
d.gateway.close(); d_ask.gateway.close(); d_ask2.gateway.close()

print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
n_pass = sum(1 for _, t, _ in results if t == "PASS")
n_fail = sum(1 for _, t, _ in results if t == "FAIL")
for name, tag, _ in results:
    print(f"  [{tag}] {name}")
print(f"\n{len(results)} probes: {n_pass} PASS, {n_fail} FAIL")
print("Polarity: PASS = attack repelled / claim held; FAIL = spec/reference")
print("claim BROKE under adversarial pressure.")
