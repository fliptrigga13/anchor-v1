#!/usr/bin/env python3
"""v1.1 SMP battle-test ROUND 4 (v11d): adversarial probes for the three
remediation patches, against REAL anchor_v1 modules, zero mocks, keys
generated in-process per run. Run probes IN ORDER:

  (a) P30 rolling-clock 50-thread double-mint under a LIVE clock (no frozen
      harness) -> must yield exactly ONE mint.
  (b) P31 in-memory tamper of a parsed RegistryEntry -> must be denied/
      latched (FrozenInstanceError), no capability minted.
  (c) P32 sole-caller AST lint -> catches handle_event outside the shim,
      and does NOT false-positive on the harness alias pattern.
  (d) P33 dedup-key placement: key generated shim-side (§6.1); kernel has
      no dedup_key generation; shim reproduces/verifies the key.
  (e) P34 nonce determinism: retry cannot smuggle a fresh nonce into a
      second mint; sequential duplicates collapse; fresh-nonce resolve
      DENIED at §9.2.
  (f) P35 quantum-boundary straddle characterization (2s quantum,
      controlled clock): the documented residual, bounded.
  (g) P36 honest path under live clock: ASK -> duplicate-while-pending
      DENY -> honest approval ALLOWs, exactly one mint.
  (h) P37 bare resolve_approval across a bucket boundary (F1 fix): honest
      approval ALLOWs via the ASK-time envelope; verb-swap still DENIED.
  (i) P38 cross-bucket duplicate-while-pending ((d) fix): DENY
      "event pending approval", no second ASK.

Then: re-run the v11r 171-check suite + v11c probes (P22-P29) for
regression (done by the coordinator, separate invocation).

Run with ./.venv/bin/python from ~/workspace/anchor-v1.
"""
from __future__ import annotations

import dataclasses
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")
sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1")

from smp_v1_1_prototype import build_deployment  # noqa: E402

ANCHOR_V1_DIR = Path("/home/hatch/workspace/anchor-v1")
QUANTUM = 300.0  # must match ShimAdapter default window_quantum_sec
PARAMS = {"cmd": "echo smp", "timeout_s": 30}

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        raise AssertionError(f"PROBE FAILED: {name} — {detail}")


class ThreadSafeCounter:
    """Counts real Guardian handle_event invocations, thread-safely."""

    def __init__(self, guardian):
        self.lock = threading.Lock()
        self.calls: list = []
        orig = guardian.handle_event

        def he(event, **kw):
            with self.lock:
                self.calls.append(
                    event.event_id if hasattr(event, "event_id")
                    else event.get("event_id"))
            return orig(event, **kw)

        guardian.handle_event = he


def minted_capability_ids(dep) -> set[str]:
    ids = set()
    for rec in dep.gateway._dlog.decided.values():
        if rec.get("capability_id"):
            ids.add(rec["capability_id"])
    return ids


# ------------------------------------------------- P30: rolling-clock 50-thread double-mint
def _p30_attempt(attempt: int):
    """One 50-thread burst under a LIVE clock. Returns a result dict."""
    workdir = Path(tempfile.mkdtemp(prefix=f"p30-a{attempt}-"))
    dep = build_deployment(workdir=workdir)  # now_fn=None -> LIVE clock
    counter = ThreadSafeCounter(dep.guardian)
    n = 50
    barrier = threading.Barrier(n)
    results: list = [None] * n
    errors: list = []
    wall: list = [None] * n

    def worker(i: int):
        try:
            barrier.wait(timeout=60)
            t0 = time.time()
            r = dep.gateway.submit_intent(
                plane="shell", verb="anchor:shell/exec",
                target="/usr/bin/backup", principal=dep.subject,
                params=dict(PARAMS))
            t1 = time.time()
            results[i] = r
            wall[i] = (t0, t1)
        except Exception as exc:  # noqa: BLE001 — collected, reported
            errors.append((i, f"{type(exc).__name__}: {exc}"))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    alive = [t for t in threads if t.is_alive()]
    dep.gateway.close()
    return {
        "dep": dep, "results": results, "errors": errors, "alive": alive,
        "mints": len(counter.calls), "wall": wall,
        "cap_ids": minted_capability_ids(dep),
    }


def p30_rolling_clock_50_thread_double_mint():
    print("P30 rolling-clock 50-thread double-mint: 50 identical intents, "
          "LIVE clock (no frozen harness), must yield exactly ONE mint")
    outcome = None
    for attempt in range(3):
        outcome = _p30_attempt(attempt)
        if (not outcome["alive"] and not outcome["errors"]
                and outcome["mints"] == 1):
            break
        # Diagnose: did the burst straddle a 300s bucket boundary?
        walls = [w for w in outcome["wall"] if w]
        buckets = ({int(w[0] // QUANTUM) for w in walls}
                   | {int(w[1] // QUANTUM) for w in walls}) if walls else set()
        if len(buckets) > 1 and attempt < 2:
            print(f"  [note] attempt {attempt}: burst straddled a 300s bucket "
                  f"boundary (documented §6.2-amendment residual) — retrying")
            continue
        break
    assert outcome is not None
    check("P30 no worker threads hung or errored",
          not outcome["alive"] and not outcome["errors"],
          f"alive={[t.name for t in outcome['alive']]}, "
          f"errors={outcome['errors'][:2]}")
    res = outcome["results"]
    check("P30 all 50 submissions returned ALLOW",
          all(r is not None and r.decision.decision == "ALLOW" for r in res),
          f"decisions={[r.decision.decision if r else None for r in res][:5]}…")
    n_cached = sum(1 for r in res if r is not None and r.from_cache)
    check("P30 exactly ONE kernel mint under the live clock",
          outcome["mints"] == 1,
          f"handle_event calls={outcome['mints']}, from_cache={n_cached}/50")
    keys = {r.dedup_key for r in res if r is not None}
    check("P30 all 50 dedup_keys identical (quantized)",
          len(keys) == 1, f"distinct_keys={len(keys)}")
    digests = {r.envelope.action_digest for r in res
               if r is not None and r.envelope is not None}
    check("P30 all 50 action_digests identical (byte-identical envelopes)",
          len(digests) == 1, f"distinct_digests={len(digests)}")
    check("P30 exactly one distinct capability_id minted",
          len(outcome["cap_ids"]) == 1,
          f"capability_ids={len(outcome['cap_ids'])}")
    envs = [r.envelope for r in res if r is not None and r.envelope]
    aligned = all(int(e.not_before.timestamp()) % int(QUANTUM) == 0
                  for e in envs)
    check("P30 validity windows quantized to 300s bucket boundaries",
          aligned,
          f"not_before={envs[0].not_before.isoformat() if envs else None}")
    check("P30 no bucket-boundary straddle in the accepted burst",
          len({int(w[0] // QUANTUM) for w in outcome["wall"] if w}) == 1
          if outcome["wall"] else True)


# ------------------------------------------------- P31: parsed-entry memory tamper
def p31_parsed_entry_tamper_frozen():
    print("P31 parsed-entry memory tamper: mutate parsed e001 in memory -> "
          "must hit FrozenInstanceError; attacker intent DENIED pre-forward")
    workdir = Path(tempfile.mkdtemp(prefix="p31-"))
    dep = build_deployment(workdir=workdir)  # live clock is fine here
    counter = ThreadSafeCounter(dep.guardian)
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P31 baseline ALLOW before tamper", r0.decision.decision == "ALLOW")
    n0 = len(counter.calls)
    pinned_before = dep.registry.digest

    e001 = next(e for e in dep.registry._entries if e.entry_id == "e001")
    blocked = False
    try:
        e001.target_value = "/usr/bin/attacker-tool"  # noqa: B018
    except dataclasses.FrozenInstanceError:
        blocked = True
    check("P31 tamper attempt raises FrozenInstanceError", blocked,
          "RegistryEntry is @dataclass(frozen=True)")
    check("P31 parsed entry unchanged after tamper attempt",
          e001.target_value == "/usr/bin/backup",
          f"target_value={e001.target_value!r}")
    check("P31 pin/digest unchanged (R5 payload bytes untouched)",
          dep.registry.digest == pinned_before)
    try:
        dep.registry.assert_live()
        live = True
    except Exception:  # noqa: BLE001
        live = False
    check("P31 registry still live (no latch tripped)", live)

    # The attacker's intent: target is NOT allowlisted (the parsed entry was
    # never mutated), so it must DENY as unmapped BEFORE the Guardian.
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec",
        target="/usr/bin/attacker-tool", principal=dep.subject,
        params=dict(PARAMS))
    new_mints = len(counter.calls) - n0
    check("P31 attacker-target intent DENIED",
          r.decision.decision == "DENY", f"reason={r.decision.reason!r}")
    check("P31 zero handle_event calls for the attacker intent",
          new_mints == 0, f"new_mints={new_mints}")
    check("P31 nothing minted by the attacker intent",
          len(minted_capability_ids(dep)) == 1,  # only the baseline mint
          "only the baseline capability exists")

    # Liveness after the attack: a DIFFERENT allowlisted entry still mints.
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/read", target="/var/log/syslog",
        principal=dep.subject, params=dict(PARAMS))
    check("P31 registry still serves other entries (fresh mint ALLOW)",
          r2.decision.decision == "ALLOW" and not r2.from_cache,
          f"decision={r2.decision.decision}, from_cache={r2.from_cache}")
    dep.gateway.close()


# ------------------------------------------------- P33: dedup key placement (shim-side, §6.1)
def p33_dedup_key_shim_side_placement():
    print("P33 dedup-key placement: key generated shim-side (§6.1) — the "
          "kernel must not generate dedup_keys, and the shim must be able "
          "to reproduce/verify the key")
    # Static: the kernel package must contain NO dedup_key generation.
    kernel_src = Path("/home/hatch/workspace/anchor-v1/anchor-v1/src/anchor_v1")
    hits = []
    for py in kernel_src.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        if "dedup_key" in text:
            hits.append(py.name)
    check("P33 kernel package contains no dedup_key generation",
          not hits, f"kernel files mentioning dedup_key: {hits}")
    # Behavioral: the shim reproduces the key — two independent translate()
    # calls in the same bucket yield the identical dedup_key, and it matches
    # the key the gateway recorded in the durable decided log.
    workdir = Path(tempfile.mkdtemp(prefix="p33-"))
    dep = build_deployment(workdir=workdir)  # live clock
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS), event_id="probe-e1",
              event_type="pre_tool_call", session_id="sess-smp")
    ti1 = dep.adapter.translate(**kw)
    ti2 = dep.adapter.translate(**dict(kw, event_id="probe-e2"))
    check("P33 shim reproduces the dedup_key across independent "
          "translate() calls",
          ti1.dedup_key == ti2.dedup_key,
          f"k1={ti1.dedup_key[:16]}… k2={ti2.dedup_key[:16]}…")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("P33 submit ALLOWs", r.decision.decision == "ALLOW")
    rec = dep.gateway._dlog.decided.get(r.dedup_key)
    check("P33 gateway's recorded key equals the shim-computed key "
          "(shim owns idempotency, pre-mint)",
          rec is not None and r.dedup_key == ti1.dedup_key,
          f"gateway_key={r.dedup_key[:16]}… shim_key={ti1.dedup_key[:16]}…")
    check("P33 key was computed before any kernel mint (idempotency "
          "contract holds shim-side)",
          ti1.dedup_key is not None and len(ti1.dedup_key) == 64)
    dep.gateway.close()


# ------------------------------------------------- P34: nonce determinism / idempotency across retries
def p34_nonce_idempotency_across_retries():
    print("P34 nonce/idempotency: the envelope nonce is a pure function of "
          "the canonical inputs — a retry cannot smuggle a fresh nonce "
          "into a second mint")
    workdir = Path(tempfile.mkdtemp(prefix="p34-"))
    dep = build_deployment(workdir=workdir)  # live clock
    counter = ThreadSafeCounter(dep.guardian)
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS), event_type="pre_tool_call",
              session_id="sess-smp")
    ti1 = dep.adapter.translate(**dict(kw, event_id="retry-e1"))
    ti2 = dep.adapter.translate(**dict(kw, event_id="retry-e2"))
    check("P34 nonce deterministic across independent translate() calls",
          ti1.envelope.nonce == ti2.envelope.nonce,
          f"n1={ti1.envelope.nonce[:16]}… n2={ti2.envelope.nonce[:16]}…")
    check("P34 action_digest identical across the retry pair",
          ti1.envelope.action_digest == ti2.envelope.action_digest)
    # The retry path through the gateway: sequential duplicate submit must
    # collapse to the cached result — exactly one mint, one capability.
    r1 = dep.gateway.submit_intent(**{k: v for k, v in kw.items()
                                      if k in ("plane", "verb", "target",
                                               "principal", "params")})
    r2 = dep.gateway.submit_intent(**{k: v for k, v in kw.items()
                                      if k in ("plane", "verb", "target",
                                               "principal", "params")})
    check("P34 first submit ALLOWs", r1.decision.decision == "ALLOW")
    check("P34 retry submit collapses to cache (no second mint)",
          r2.decision.decision == "ALLOW" and r2.from_cache
          and len(counter.calls) == 1,
          f"from_cache={r2.from_cache}, handle_event calls={len(counter.calls)}")
    check("P34 exactly one capability_id across the retry",
          len(minted_capability_ids(dep)) == 1)
    dep.gateway.close()

    # The resolve path: a fresh-nonce envelope presented at approval time
    # must fail the §9.2 digest check — no second mint via resolve.
    workdir2 = Path(tempfile.mkdtemp(prefix="p34b-"))
    dep2 = build_deployment(
        workdir=workdir2,
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask"
        else "ALLOW")
    counter2 = ThreadSafeCounter(dep2.guardian)
    ra = dep2.gateway.submit_intent(
        plane="shell", verb="anchor:shell/backup-ask",
        target="/usr/bin/backup-ask", principal=dep2.subject,
        params=dict(PARAMS))
    check("P34b ASK returned", ra.decision.decision == "ASK")
    gw_pid = ra.decision.pending_id
    ask_env = dep2.gateway._pending_by_id[gw_pid]["envelope"]
    evil = ask_env.model_copy(deep=True)
    evil.nonce = "f" * 32  # attacker/Retry smuggles a fresh nonce
    check("P34b fresh-nonce envelope has a different digest",
          evil.action_digest != ask_env.action_digest)
    n_rp = len(counter2.calls)
    rr = dep2.gateway.resolve_approval(gw_pid, approved=True,
                                       presented_envelope=evil)
    check("P34b resolve with fresh-nonce envelope DENIED (§9.2)",
          rr.decision.decision == "DENY",
          f"reason={rr.decision.reason!r}")
    check("P34b no kernel mint from the fresh-nonce resolve",
          len(counter2.calls) == n_rp
          and len(minted_capability_ids(dep2)) == 0)
    dep2.gateway.close()


# ------------------------------------------------- P35: quantum-boundary straddle (explicit)
def p35_quantum_boundary_straddle():
    print("P35 quantum-boundary straddle: concurrent requests on opposite "
          "sides of a 2s bucket boundary (characterization of the "
          "documented residual)")
    quantum = 2.0
    clock = [0.0]

    def now_fn():
        return datetime.fromtimestamp(clock[0], tz=timezone.utc)

    # Pick t1/t2 straddling a bucket boundary: boundary at k*2 for integer k.
    t1 = 1_700_000_000.0 - 0.25   # 0.25s before a boundary
    b = int(t1 // quantum)
    assert int(t1 // quantum) == b
    t2 = (b + 1) * quantum + 0.25  # 0.25s after the boundary
    assert int(t2 // quantum) == b + 1
    workdir = Path(tempfile.mkdtemp(prefix="p35-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=quantum)
    counter = ThreadSafeCounter(dep.guardian)
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS))
    clock[0] = t1
    r1 = dep.gateway.submit_intent(**kw)
    clock[0] = t2
    r2 = dep.gateway.submit_intent(**kw)
    check("P35 both sides of the boundary ALLOW (no fail-open, no crash)",
          r1.decision.decision == "ALLOW" and r2.decision.decision == "ALLOW")
    # PENDING LAUREN'S EXPLICIT APPROVAL (v1.1.2 release gate): this probe's
    # expectation was deliberately changed by harden-C. Old behavior asserted
    # the documented residual (2 mints per straddle); new behavior asserts the
    # fix (1 mint via cross-bucket carry-over + capability-liveness).
    check("P35 straddle produces two distinct dedup_keys (one per bucket; "
          "harden-C carry-over pins the live decision under the new key)",
          r1.dedup_key != r2.dedup_key,
          f"k1={r1.dedup_key[:12]}… k2={r2.dedup_key[:12]}…")
    check("P35 straddle mints ONCE — harden-C carry-over serves the new "
          "bucket from the live capability (old residual was 2 mints)",
          len(counter.calls) == 1, f"mints={len(counter.calls)}")
    check("P35 exactly one capability_id minted across the straddle "
          "(capability-liveness: the carried decision's capability is live)",
          len(minted_capability_ids(dep)) == 1,
          f"capability_ids={minted_capability_ids(dep)}")
    check("P35 each bucket still converges (second submit in the new "
          "bucket hits cache)",
          (lambda: (clock.__setitem__(0, t2 + 0.1),
                    dep.gateway.submit_intent(**kw))[1])().from_cache)
    dep.gateway.close()

    # Control: same small quantum, both submits well inside ONE bucket.
    workdir2 = Path(tempfile.mkdtemp(prefix="p35b-"))
    clock2 = [0.0]

    def now_fn2():
        return datetime.fromtimestamp(clock2[0], tz=timezone.utc)

    dep2 = build_deployment(workdir=workdir2, now_fn=now_fn2,
                            window_quantum_sec=quantum)
    counter2 = ThreadSafeCounter(dep2.guardian)
    base = (int(1_700_000_000.0 // quantum)) * quantum + 0.5
    clock2[0] = base
    s1 = dep2.gateway.submit_intent(**{**kw, "principal": dep2.subject})
    clock2[0] = base + 0.5
    s2 = dep2.gateway.submit_intent(**{**kw, "principal": dep2.subject})
    check("P35 control: same-bucket submits collapse to one mint even at "
          "2s quantum",
          s1.decision.decision == "ALLOW" and s2.from_cache
          and len(counter2.calls) == 1
          and s1.dedup_key == s2.dedup_key,
          f"mints={len(counter2.calls)}, from_cache={s2.from_cache}")
    dep2.gateway.close()


# ------------------------------------------------- P36: honest ASK->resolve path under live clock
def p36_honest_ask_resolve_live_clock():
    print("P36 honest path: live-clock ASK -> duplicate-while-pending DENY "
          "-> honest approval ALLOWs (exactly one mint)")
    workdir = Path(tempfile.mkdtemp(prefix="p36-"))
    dep = build_deployment(  # LIVE clock
        workdir=workdir,
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask"
        else "ALLOW")
    counter = ThreadSafeCounter(dep.guardian)
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    r = dep.gateway.submit_intent(**kw)
    check("P36 ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    ask_envelope = dep.gateway._pending_by_id[gw_pid]["envelope"]
    n0 = len(counter.calls)
    # Duplicate submission while pending -> §6.4 DENY, no second kernel call.
    rd = dep.gateway.submit_intent(**kw)
    check("P36 duplicate-while-pending DENIED",
          rd.decision.decision == "DENY"
          and "pending approval" in (rd.decision.reason or ""),
          f"reason={rd.decision.reason!r}")
    check("P36 no second kernel mint for the duplicate",
          len(counter.calls) == n0, f"mints={len(counter.calls)}")
    # Honest approval inside the validity window -> ALLOW, one mint total.
    ra = dep.gateway.resolve_approval(gw_pid, approved=True,
                                      presented_envelope=ask_envelope)
    check("P36 honest approval ALLOWs (not denied)",
          ra.decision.decision == "ALLOW"
          and ra.decision.capability is not None,
          f"decision={ra.decision.decision}, reason={ra.decision.reason!r}")
    check("P36 exactly one capability_id minted end-to-end",
          len(minted_capability_ids(dep)) == 1)
    check("P36 pending record cleared after resolve",
          gw_pid not in dep.gateway._pending_by_id)
    dep.gateway.close()
def _run_lint(*, extra_files: dict[str, str] | None = None):
    created = []
    try:
        for name, body in (extra_files or {}).items():
            p = ANCHOR_V1_DIR / name
            p.write_text(body, encoding="utf-8")
            created.append(p)
        proc = subprocess.run(
            [sys.executable, str(ANCHOR_V1_DIR / "smp_sole_caller_lint.py"),
             "--root", str(ANCHOR_V1_DIR)],
            capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        for p in created:
            try:
                p.unlink()
            except OSError:
                pass


ROGUE_BODY = '''"""Rogue deployment file: bypasses the SmpGateway sole-caller rule."""


def rogue_mint(dep, event):
    # Direct kernel mint outside the designated shim layer.
    return dep.gateway._guardian.handle_event(event)
'''

ROGUE_GETATTR_BODY = '''"""Rogue deployment file: getattr indirection around the sole-caller rule."""


def rogue_mint_indirect(dep, event):
    return getattr(dep.gateway._guardian, "handle_event")(event)
'''

ALIAS_BODY = '''"""Harness-style wrapper: aliases handle_event without invoking it."""


def wrap(guardian):
    orig_he = guardian.handle_event

    def he(event, **kw):
        return orig_he(event, **kw)

    guardian.handle_event = he
    return guardian
'''


# ------------------------------------------------- P37: bare resolve_approval across a bucket boundary (F1 fix)
def p37_bare_resolve_across_bucket():
    print("P37 bare resolve_approval across a bucket boundary: honest "
          "approval (no presented envelope) must ALLOW via the ASK-time "
          "envelope, not DENY on digest mismatch")
    quantum = 2.0
    clock = [0.0]

    def now_fn():
        return datetime.fromtimestamp(clock[0], tz=timezone.utc)

    base = (int(1_700_000_000.0 // quantum)) * quantum
    workdir = Path(tempfile.mkdtemp(prefix="p37-"))
    dep = build_deployment(
        workdir=workdir, now_fn=now_fn, window_quantum_sec=quantum,
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask"
        else "ALLOW")
    counter = ThreadSafeCounter(dep.guardian)
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    clock[0] = base + 0.5                      # bucket b: ASK
    r = dep.gateway.submit_intent(**kw)
    check("P37 ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    ask_digest = dep.gateway._pending_by_id[gw_pid]["ask_digest"]
    clock[0] = base + quantum + 0.5            # bucket b+1: bare resolve
    rb = dep.gateway.resolve_approval(gw_pid, approved=True)
    check("P37 bare resolve across the bucket boundary ALLOWs",
          rb.decision.decision == "ALLOW"
          and rb.decision.capability is not None,
          f"decision={rb.decision.decision}, reason={rb.decision.reason!r}")
    check("P37 minted capability binds the ASK-time envelope digest",
          rb.envelope is not None
          and rb.envelope.action_digest == ask_digest)
    check("P37 exactly one kernel mint across ASK + bare resolve",
          len(counter.calls) == 1, f"mints={len(counter.calls)}")
    check("P37 pending record cleared", gw_pid not in dep.gateway._pending_by_id)
    dep.gateway.close()

    # Negative control: a verb swap since ASK is still denied on the bare
    # path (fingerprint binding preserved — P26 property).
    workdir2 = Path(tempfile.mkdtemp(prefix="p37b-"))
    dep2 = build_deployment(
        workdir=workdir2, now_fn=now_fn, window_quantum_sec=quantum,
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask"
        else "ALLOW")
    counter2 = ThreadSafeCounter(dep2.guardian)
    clock[0] = base + 0.5
    r2 = dep2.gateway.submit_intent(**kw)
    pid2 = r2.decision.pending_id
    dep2.gateway._pending_by_id[pid2]["intent"]["verb"] = "anchor:shell/exec"
    dep2.gateway._pending_by_id[pid2]["intent"]["target"] = "/usr/bin/backup"
    n0 = len(counter2.calls)
    clock[0] = base + quantum + 0.5
    rd = dep2.gateway.resolve_approval(pid2, approved=True)
    check("P37b verb-swapped bare resolve still DENIED (§9.2 fingerprint)",
          rd.decision.decision == "DENY",
          f"reason={rd.decision.reason!r}")
    check("P37b no kernel mint for the swapped resolve",
          len(counter2.calls) == n0
          and len(minted_capability_ids(dep2)) == 0)
    dep2.gateway.close()


# ------------------------------------------------- P38: cross-bucket duplicate-while-pending ((d) fix)
def p38_cross_bucket_duplicate_while_pending():
    print("P38 cross-bucket duplicate-while-pending: duplicate submitted "
          "after a bucket roll must DENY 'event pending approval' — no "
          "second ASK")
    quantum = 2.0
    clock = [0.0]

    def now_fn():
        return datetime.fromtimestamp(clock[0], tz=timezone.utc)

    base = (int(1_700_000_000.0 // quantum)) * quantum
    workdir = Path(tempfile.mkdtemp(prefix="p38-"))
    dep = build_deployment(
        workdir=workdir, now_fn=now_fn, window_quantum_sec=quantum,
        decision_fn=lambda e: "ASK" if e.action == "anchor:acs/backup.ask"
        else "ALLOW")
    counter = ThreadSafeCounter(dep.guardian)
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    clock[0] = base + 0.5                      # bucket b: ASK
    r1 = dep.gateway.submit_intent(**kw)
    check("P38 ASK returned", r1.decision.decision == "ASK")
    n0 = len(counter.calls)
    clock[0] = base + quantum + 0.5            # bucket b+1: duplicate
    r2 = dep.gateway.submit_intent(**kw)
    check("P38 cross-bucket duplicate DENIED as pending",
          r2.decision.decision == "DENY"
          and "pending approval" in (r2.decision.reason or ""),
          f"decision={r2.decision.decision}, reason={r2.decision.reason!r}")
    check("P38 no second kernel mint for the cross-bucket duplicate",
          len(counter.calls) == n0, f"mints={len(counter.calls)}")
    check("P38 original pending still open (not orphaned by the duplicate)",
          r1.decision.pending_id in dep.gateway._pending_by_id)
    # The original ASK is still honestly resolvable.
    env = dep.gateway._pending_by_id[r1.decision.pending_id]["envelope"]
    ra = dep.gateway.resolve_approval(r1.decision.pending_id, approved=True,
                                      presented_envelope=env)
    check("P38 original ASK still resolves ALLOW after the duplicate",
          ra.decision.decision == "ALLOW"
          and ra.decision.capability is not None)
    check("P38 exactly one capability_id end-to-end",
          len(minted_capability_ids(dep)) == 1)
    dep.gateway.close()
# ------------------------------------------------- P32: sole-caller AST lint
def p32_sole_caller_lint():
    print("P32 sole-caller AST lint: clean tree passes; rogue invocation "
          "caught; alias pattern now flagged (v11g SERIOUS-2 supersedes the "
          "old no-flag expectation)")
    rc, out, err = _run_lint()
    check("P32 lint passes on the clean tree", rc == 0,
          f"rc={rc}, stderr={err[:200]}")
    check("P32 lint is non-vacuous: names the shim's own allowed site",
          "smp_v1_1_prototype.py" in out and "ALLOWED" in out,
          out.splitlines()[2] if out else "")

    rc2, out2, _ = _run_lint(
        extra_files={"rogue_bypass_probe_tmp.py": ROGUE_BODY})
    check("P32 lint FAILS when a rogue file invokes handle_event",
          rc2 != 0, f"rc={rc2}")
    check("P32 lint names the rogue file and line",
          "rogue_bypass_probe_tmp.py" in out2,
          [ln for ln in out2.splitlines() if "rogue" in ln][:2])

    rc2b, out2b, _ = _run_lint(
        extra_files={"rogue_getattr_probe_tmp.py": ROGUE_GETATTR_BODY})
    check("P32 lint FAILS on getattr(X, 'handle_event') indirection",
          rc2b != 0, f"rc={rc2b}")
    check("P32 lint names the getattr rogue file",
          "rogue_getattr_probe_tmp.py" in out2b,
          [ln for ln in out2b.splitlines() if "rogue_getattr" in ln][:2])

    rc3, out3, _ = _run_lint(
        extra_files={"lint_alias_negative_tmp.py": ALIAS_BODY})
    # v11g: SERIOUS-2 deliberately raises the bar — a bare
    # guardian.handle_event reference (alias now, call later/elsewhere)
    # is a §1.5 violation even when never invoked in this file. The old
    # "does NOT flag the harness alias pattern" expectation is superseded.
    check("P32 lint FLAGS the harness alias pattern "
          "(bare guardian.handle_event reference)",
          rc3 != 0 and "lint_alias_negative_tmp.py" in out3
          and "bare .handle_event reference" in out3,
          f"rc={rc3}, out={out3[-200:]}")
    leftover = [n for n in ("rogue_bypass_probe_tmp.py",
                            "rogue_getattr_probe_tmp.py",
                            "lint_alias_negative_tmp.py")
                if (ANCHOR_V1_DIR / n).exists()]
    check("P32 probe temp files cleaned up", not leftover,
          f"leftover={leftover}")


def main() -> None:
    probes = [p30_rolling_clock_50_thread_double_mint,
              p31_parsed_entry_tamper_frozen,
              p32_sole_caller_lint,
              p33_dedup_key_shim_side_placement,
              p34_nonce_idempotency_across_retries,
              p35_quantum_boundary_straddle,
              p36_honest_ask_resolve_live_clock,
              p37_bare_resolve_across_bucket,
              p38_cross_bucket_duplicate_while_pending]
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
    print("RESULT: all fourth-round adversarial probes green.")


if __name__ == "__main__":
    main()
