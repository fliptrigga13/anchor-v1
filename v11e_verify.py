#!/usr/bin/env python3
"""v11e verification: fifth-round battle-test of the four v11d-critic
remediations (S2 re-derive, S3 lint+CI, F2 WAL chain, F2c pending-expire).

Real modules, zero mocks. Run from ~/workspace/anchor-v1 with
./.venv/bin/python. Each V-probe asserts the FIXED (fail-closed)
behavior; the old exploit expectations from v11d_critic_probes2.py are
superseded and documented as such.

Probes:
  V-C1   privileged registry tamper -> DENY + latch, zero mints
  V-C2r  forged WAL decided record -> restart REFUSES (fail closed)
  V-C3r  mid-file WAL truncation -> restart REFUSES (fail closed);
         pure tail-truncation characterized as documented residual
  V-C8r  ASK -> restart -> PENDING orphaned -> fresh ASK -> resolve ALLOWs
  V-C10a rogue resolve_pending caller -> lint exit 1
  V-C10b unpinned handle_event call site added to the shim -> lint exit 1
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1/src")
sys.path.insert(0, "/home/hatch/workspace/anchor-v1/anchor-v1")

from smp_v1_1_prototype import (  # noqa: E402
    SmpGateway, ShimAdapter, SMPRefusal, build_deployment)

ANCHOR_V1_DIR = Path("/home/hatch/workspace/anchor-v1")
RESULTS: list[tuple[str, bool, str]] = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    if not cond:
        raise AssertionError(f"PROBE FAILED: {name} -- {detail}")


def count_calls(guardian, attr):
    n = [0]
    lock = threading.Lock()
    orig = getattr(guardian, attr)

    def wrapper(*a, **k):
        with lock:
            n[0] += 1
        return orig(*a, **k)

    setattr(guardian, attr, wrapper)
    return n


PARAMS = {"cmd": "echo smp", "timeout_s": 30}
Q = 300.0


def fixed_clock(t):
    def now_fn():
        return datetime.fromtimestamp(t, tz=timezone.utc)
    return now_fn


def restart_gateway(dep, now_fn):
    adapter2 = ShimAdapter(
        registry=dep.registry, translation_signer=dep.translation_signer,
        log_signer=dep.log_signer,
        constitution_hash="smp-proto-constitution-hash",
        capability_ttl_s=300.0, now_fn=now_fn, window_quantum_sec=Q)
    gw2 = SmpGateway(guardian=dep.guardian, adapter=adapter2,
                     issuer_trusted=dep.trusted,
                     wal_path=dep.gateway._dlog._path, now_fn=now_fn)
    return adapter2, gw2


# --- V-C1: privileged registry tamper -> DENY + latch, zero mints ---------
def v_c1_privileged_tamper_latched():
    print("V-C1 privileged registry tamper (object.__setattr__): must DENY, "
          "latch, zero mints")
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    workdir = Path(tempfile.mkdtemp(prefix="v-c1-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    he = count_calls(dep.guardian, "handle_event")
    e001 = next(e for e in dep.registry._entries if e.entry_id == "e001")
    object.__setattr__(e001, "target_value", "/usr/bin/attacker-tool")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec",
        target="/usr/bin/attacker-tool", principal=dep.subject,
        params=dict(PARAMS))
    check("V-C1 tampered-entry intent DENIED (fail-closed)",
          r.decision.decision == "DENY"
          and "MUTATION DETECTED" in (r.decision.reason or ""),
          f"decision={r.decision.decision}, reason={r.decision.reason!r}")
    check("V-C1 zero kernel mints for the tampered intent", he[0] == 0,
          f"handle_event calls={he[0]}")
    check("V-C1 adapter latched dead", dep.registry._dead is True)
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("V-C1 latch holds: later legitimate intent also DENIED, no mint",
          r2.decision.decision == "DENY" and he[0] == 0,
          f"decision={r2.decision.decision}, mints={he[0]}")
    dep.gateway.close()


# --- V-C2r: forged WAL decided record -> restart refuses -------------------
def v_c2r_forged_wal_refused():
    print("V-C2r WAL forgery: forged decided record must FAIL CLOSED on "
          "restart (no forged capability served)")
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    workdir = Path(tempfile.mkdtemp(prefix="v-c2r-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS))
    r0 = dep.gateway.submit_intent(**kw)
    check("V-C2r baseline ALLOW", r0.decision.decision == "ALLOW")
    dk = r0.dedup_key
    dep.gateway.close()
    wal = workdir / "decision.wal.jsonl"
    lines = wal.read_text(encoding="utf-8").splitlines()
    forged = 0
    out = []
    for line in lines:
        op = json.loads(line)
        if op.get("op") == "decided" and op.get("dedup_key") == dk:
            op["capability_id"] = "forged-cap-id"
            dec = op.get("decision") or {}
            dec["capability"] = {"__bytes_hex__": "deadbeef"}
            op["decision"] = dec
            forged += 1
        out.append(json.dumps(op, sort_keys=True))
    wal.write_text("\n".join(out) + "\n", encoding="utf-8")
    check("V-C2r forged the decided record", forged >= 1, f"forged={forged}")
    try:
        _, gw2 = restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("V-C2r restart REFUSES on forged WAL (fail closed)",
          not restarted, f"restarted={restarted}, why={why[:80] if not restarted else ''}")
    if restarted:
        gw2.close()


# --- V-C3r: mid-file truncation -> restart refuses -------------------------
def v_c3r_midfile_truncation_refused():
    print("V-C3r WAL mid-file truncation: dropping a non-tail record must "
          "FAIL CLOSED on restart")
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    workdir = Path(tempfile.mkdtemp(prefix="v-c3r-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    kw1 = dict(plane="shell", verb="anchor:shell/exec",
               target="/usr/bin/backup", principal=dep.subject,
               params=dict(PARAMS))
    kw2 = dict(plane="shell", verb="anchor:shell/read",
               target="/var/log/syslog", principal=dep.subject,
               params=dict(PARAMS))
    r1 = dep.gateway.submit_intent(**kw1)
    r2 = dep.gateway.submit_intent(**kw2)
    check("V-C3r two baseline ALLOWs",
          r1.decision.decision == "ALLOW" and r2.decision.decision == "ALLOW")
    dep.gateway.close()
    wal = workdir / "decision.wal.jsonl"
    lines = wal.read_text(encoding="utf-8").splitlines()
    # Drop the FIRST decided record (mid-file); keep later records so the
    # chain break is detectable.
    dropped = 0
    out = []
    for line in lines:
        op = json.loads(line)
        if op.get("op") == "decided" and dropped == 0:
            dropped += 1
            continue
        out.append(line)
    wal.write_text("\n".join(out) + "\n", encoding="utf-8")
    check("V-C3r dropped one mid-file decided record", dropped == 1)
    try:
        _, gw2 = restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("V-C3r restart REFUSES on mid-file truncation (fail closed)",
          not restarted, f"restarted={restarted}")
    if restarted:
        gw2.close()


def v_c3r_tail_truncation_residual():
    print("V-C3r-tail DOCUMENTED RESIDUAL: pure tail-truncation is "
          "indistinguishable from a crash (self-consistent prefix); "
          "control = backups + restrictive permissions")
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    workdir = Path(tempfile.mkdtemp(prefix="v-c3rt-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS))
    r0 = dep.gateway.submit_intent(**kw)
    check("V-C3r-tail baseline ALLOW", r0.decision.decision == "ALLOW")
    he0 = 1
    dep.gateway.close()
    wal = workdir / "decision.wal.jsonl"
    lines = wal.read_text(encoding="utf-8").splitlines()
    check("V-C3r-tail WAL has >=2 records", len(lines) >= 2,
          f"lines={len(lines)}")
    # Drop ALL decided records (the critic's C3r tail-truncation) -> the
    # remaining prefix (intent only) is self-consistent, i.e.
    # crash-indistinguishable.
    kept = [ln for ln in lines
            if json.loads(ln).get("op") != "decided"]
    check("V-C3r-tail dropped all decided records",
          len(lines) - len(kept) >= 1,
          f"dropped={len(lines) - len(kept)}")
    wal.write_text("\n".join(kept) + "\n", encoding="utf-8")
    try:
        _, gw2 = restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal:
        restarted = False
    check("V-C3r-tail restart ACCEPTS the self-consistent prefix "
          "(crash-indistinguishable; documented residual)",
          restarted)
    if restarted:
        he2 = count_calls(dep.guardian, "handle_event")
        r1 = gw2.submit_intent(**kw)
        check("V-C3r-tail resubmit re-mints (dedup memory was in the "
              "truncated tail) — expected under the documented residual",
              r1.decision.decision == "ALLOW" and he2[0] == 1,
              f"mints={he2[0]}")
        gw2.close()


# --- V-C8r: ASK orphaned on restart -> fresh ASK allowed --------------------
def v_c8r_pending_orphaned_fresh_ask():
    print("V-C8r pending lifecycle across restart: PENDING orphaned, fresh "
          "ASK allowed, resolve ALLOWs")
    workdir = Path(tempfile.mkdtemp(prefix="v-c8r-"))
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    dep = build_deployment(
        workdir=workdir, now_fn=now_fn, window_quantum_sec=Q,
        decision_fn=lambda e: "ASK"
        if e.action == "anchor:acs/backup.ask" else "ALLOW")
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    r = dep.gateway.submit_intent(**kw)
    check("V-C8r ASK returned", r.decision.decision == "ASK")
    gw_pid = r.decision.pending_id
    ask_dk = r.dedup_key
    dep.gateway.close()
    _, gw2 = restart_gateway(dep, now_fn)
    rec = gw2._dlog.decided.get(ask_dk, {})
    check("V-C8r PENDING record orphaned at replay",
          rec.get("state") == "PENDING" and rec.get("orphaned") is True,
          f"state={rec.get('state')}, orphaned={rec.get('orphaned')}")
    wal_text = (workdir / "decision.wal.jsonl").read_text(encoding="utf-8")
    check("V-C8r orphaned op appended to the WAL",
          '"op": "orphaned"' in wal_text)
    try:
        gw2.resolve_approval(gw_pid, approved=True)
        resolved = True
    except ValueError:
        resolved = False
    check("V-C8r old pending binding still unresolvable after restart",
          not resolved)
    r2 = gw2.submit_intent(**kw)
    check("V-C8r resubmit yields a FRESH ASK (not 'pending approval' DENY)",
          r2.decision.decision == "ASK"
          and "pending approval" not in (r2.decision.reason or ""),
          f"decision={r2.decision.decision}, reason={r2.decision.reason!r}")
    gw_pid2 = r2.decision.pending_id
    check("V-C8r fresh ASK has a new pending id", gw_pid2 != gw_pid)
    rb = gw2.resolve_approval(gw_pid2, approved=True)
    check("V-C8r fresh ASK resolves to ALLOW with a capability",
          rb.decision.decision == "ALLOW"
          and rb.decision.capability is not None,
          f"decision={rb.decision.decision}")
    gw2.close()


# --- V-C10: lint ------------------------------------------------------------
def _run_lint(extra_files=None):
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


ROGUE_RP_BODY = '''"""Rogue deployment file: resolve_pending outside the shim."""


def rogue_resolve(dep, pid):
    return dep.gateway._guardian.resolve_pending(pid, True)
'''


def v_c10_lint():
    print("V-C10 lint: rogue resolve_pending caught; unpinned in-shim "
          "call site caught; clean tree passes")
    rc, out, err = _run_lint()
    check("V-C10 lint passes on the clean tree", rc == 0,
          f"rc={rc}, stderr={err[:200]}")
    check("V-C10 lint output names the shim's ALLOWED pinned sites",
          "smp_v1_1_prototype.py" in out and "ALLOWED" in out)
    rc2, out2, _ = _run_lint(
        extra_files={"rogue_rp_probe_tmp.py": ROGUE_RP_BODY})
    check("V-C10 lint FAILS on a rogue resolve_pending caller", rc2 != 0,
          f"rc={rc2}")
    check("V-C10 lint names the rogue file",
          "rogue_rp_probe_tmp.py" in out2)
    # Unpinned call site added inside the shim module itself.
    proto = ANCHOR_V1_DIR / "smp_v1_1_prototype.py"
    original = proto.read_text(encoding="utf-8")
    try:
        proto.write_text(original + "\n\ndef _evil_extra(dep, event):\n"
                         "    return dep.gateway._guardian.handle_event(event)\n",
                         encoding="utf-8")
        rc3, out3, _ = _run_lint()
    finally:
        proto.write_text(original, encoding="utf-8")
    check("V-C10 lint FAILS on an unpinned in-shim call site", rc3 != 0,
          f"rc={rc3}")
    check("V-C10 lint names the unpinned site", "unpinned" in out3)
    rc4, _, _ = _run_lint()
    check("V-C10 shim restored: lint passes again", rc4 == 0)


def main() -> None:
    probes = [v_c1_privileged_tamper_latched,
              v_c2r_forged_wal_refused,
              v_c3r_midfile_truncation_refused,
              v_c3r_tail_truncation_residual,
              v_c8r_pending_orphaned_fresh_ask,
              v_c10_lint]
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
    print(f"V-CHECKS: {passed}/{total} passed")
    if failed:
        print(f"PROBES FAILED: {len(failed)}")
        for name, why in failed:
            print(f"  - {name}: {why}")
        sys.exit(1)
    print("RESULT: all v11e remediation probes green.")


if __name__ == "__main__":
    main()
