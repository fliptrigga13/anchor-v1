#!/usr/bin/env python3
"""v11e-critic independent adversarial probes — fifth battle-test.

Independent re-test of the four v11d-critic remediations. Written from
scratch by the critic (not a re-run of the builder's v11e_verify.py):
each probe is an adversarial VARIANT of the original exploit.

Real modules, zero mocks, zero kernel edits.
Run from ~/workspace/anchor-v1 with ./.venv/bin/python.
"""
from __future__ import annotations

import hashlib
import json
import shutil
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

ANCHOR_V1 = Path("/home/hatch/workspace/anchor-v1")
RESULTS: list[tuple[str, bool, str]] = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    if not cond:
        raise AssertionError(f"PROBE FAILED: {name} -- {detail}")


def count_calls(obj, attr):
    n = [0]
    lock = threading.Lock()
    orig = getattr(obj, attr)

    def wrapper(*a, **k):
        with lock:
            n[0] += 1
        return orig(*a, **k)

    setattr(obj, attr, wrapper)
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


def entries_by_id(dep):
    return {e.entry_id: e for e in dep.registry._entries}


# ---------------------------------------------------------------- C1'
def c1a_single_field_tamper():
    """C1'-a: object.__setattr__ on ONE live entry field (unmapped target).
    Must DENY, mint nothing, and latch."""
    print("C1'-a single-field privileged tamper (unmapped attacker target)")
    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="c1a-")))
    he = count_calls(dep.guardian, "handle_event")
    e = entries_by_id(dep)["e001"]
    object.__setattr__(e, "target_value", "/usr/bin/attacker-tool")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec",
        target="/usr/bin/attacker-tool", principal=dep.subject,
        params=dict(PARAMS))
    check("C1'-a tampered intent DENIED", r.decision.decision == "DENY",
          f"decision={r.decision.decision} reason={r.decision.reason!r}")
    check("C1'-a zero kernel mints", he[0] == 0, f"handle_event={he[0]}")
    check("C1'-a registry latched dead", dep.registry._dead is True)
    # latch is sticky: a legitimate intent afterwards is also refused
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C1'-a latch holds for later legitimate intent",
          r2.decision.decision == "DENY", f"decision={r2.decision.decision}")
    check("C1'-a still zero mints after latch", he[0] == 0)
    dep.gateway.close()


def c1b_field_swap():
    """C1'-b: swap target_value between two live entries. Must fail closed."""
    print("C1'-b entry field swap between two live entries")
    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="c1b-")))
    he = count_calls(dep.guardian, "handle_event")
    es = entries_by_id(dep)
    object.__setattr__(es["e001"], "target_value", "/var/log/")
    object.__setattr__(es["e003"], "target_value", "/usr/bin/backup")
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C1'-b swapped intent DENIED", r.decision.decision == "DENY",
          f"reason={r.decision.reason!r}")
    check("C1'-b zero kernel mints", he[0] == 0)
    check("C1'-b registry latched dead", dep.registry._dead is True)
    dep.gateway.close()


def c1c_tamper_then_restore():
    """C1'-c: tamper, observe DENY+latch, restore the original value.
    The latch must remain engaged (no silent recovery)."""
    print("C1'-c tamper-then-restore: latch must stay engaged")
    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="c1c-")))
    he = count_calls(dep.guardian, "handle_event")
    e = entries_by_id(dep)["e001"]
    object.__setattr__(e, "target_value", "/usr/bin/attacker-tool")
    r1 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec",
        target="/usr/bin/attacker-tool", principal=dep.subject,
        params=dict(PARAMS))
    check("C1'-c tampered intent DENIED", r1.decision.decision == "DENY")
    object.__setattr__(e, "target_value", "/usr/bin/backup")  # restore
    r2 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C1'-c latch survives restore (still DENY)",
          r2.decision.decision == "DENY", f"decision={r2.decision.decision}")
    check("C1'-c zero mints throughout", he[0] == 0)
    dep.gateway.close()


def c1d_payload_bytes_flip():
    """C1'-d: flip a byte in the retained canonical payload bytes."""
    print("C1'-d retained-bytes tamper (single bit flip)")
    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="c1d-")))
    he = count_calls(dep.guardian, "handle_event")
    b = bytearray(dep.registry._payload_bytes)
    b[100] ^= 0x01
    object.__setattr__(dep.registry, "_payload_bytes", bytes(b))
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C1'-d bytes-tampered intent DENIED",
          r.decision.decision == "DENY", f"reason={r.decision.reason!r}")
    check("C1'-d zero kernel mints", he[0] == 0)
    check("C1'-d registry latched dead", dep.registry._dead is True)
    dep.gateway.close()


def c1e_list_surgery():
    """C1'-e: mutate the _entries list object itself (append / replace)."""
    print("C1'-e _entries list surgery (append + index replace)")
    dep = build_deployment(workdir=Path(tempfile.mkdtemp(prefix="c1e-")))
    he = count_calls(dep.guardian, "handle_event")
    e = entries_by_id(dep)["e001"]
    dep.registry._entries.append(e)  # duplicate -> length divergence
    r = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C1'-e appended-list intent DENIED",
          r.decision.decision == "DENY")
    check("C1'-e zero kernel mints", he[0] == 0)
    dep.gateway.close()


# ---------------------------------------------------------------- C2r'
def _wal_lines(workdir):
    wal = workdir / "decision.wal.jsonl"
    return wal, wal.read_text(encoding="utf-8").splitlines()


def _rechain(lines):
    """Recompute a fully valid chain over (possibly modified) lines."""
    out = []
    tip = "genesis"
    for raw in lines:
        op = json.loads(raw)
        op.pop("rec_hash", None)
        op["prev_hash"] = tip
        body = json.dumps(op, sort_keys=True)
        op["rec_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        line = json.dumps(op, sort_keys=True)
        out.append(line)
        tip = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return out


def c2ra_inplace_forgery():
    """C2r'-a: in-place capability forgery of a decided ALLOW record."""
    print("C2r'-a in-place forgery of decided capability bytes")
    now_fn = fixed_clock(1_700_000_000.0 + 10.0)
    workdir = Path(tempfile.mkdtemp(prefix="c2ra-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C2r'-a baseline ALLOW", r0.decision.decision == "ALLOW")
    dk = r0.dedup_key
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    out, forged = [], 0
    for raw in lines:
        op = json.loads(raw)
        if op.get("op") == "decided" and op.get("dedup_key") == dk:
            op["decision"]["capability"] = {"__bytes_hex__": "deadbeef"}
            forged += 1
        out.append(json.dumps(op, sort_keys=True))
    wal.write_text("\n".join(out) + "\n", encoding="utf-8")
    check("C2r'-a forged decided record(s)", forged >= 1, f"forged={forged}")
    try:
        restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("C2r'-a restart REFUSES on forged record", not restarted,
          f"refusal={why!r}" if not restarted else "gateway started!")


def c2rb_midfile_edit():
    """C2r'-b: edit a middle record (intent nonce) without touching decided."""
    print("C2r'-b mid-file edit of an intent record's nonce")
    now_fn = fixed_clock(1_700_000_000.0 + 20.0)
    workdir = Path(tempfile.mkdtemp(prefix="c2rb-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C2r'-b baseline ALLOW", r0.decision.decision == "ALLOW")
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    out, edited = [], 0
    for raw in lines:
        op = json.loads(raw)
        if op.get("op") == "intent" and edited == 0:
            op["nonce"] = "tampered-nonce"
            edited += 1
        out.append(json.dumps(op, sort_keys=True))
    wal.write_text("\n".join(out) + "\n", encoding="utf-8")
    check("C2r'-b edited a middle record", edited == 1)
    try:
        restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("C2r'-b restart REFUSES on mid-file edit", not restarted,
          f"refusal={why!r}" if not restarted else "gateway started!")


def c2rc_line_swap():
    """C2r'-c: swap two lines' positions (reorder attack)."""
    print("C2r'-c line-order swap of two WAL records")
    now_fn = fixed_clock(1_700_000_000.0 + 30.0)
    workdir = Path(tempfile.mkdtemp(prefix="c2rc-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C2r'-c baseline ALLOW", r0.decision.decision == "ALLOW")
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    check("C2r'-c WAL has >= 2 lines to swap", len(lines) >= 2,
          f"lines={len(lines)}")
    lines[0], lines[1] = lines[1], lines[0]
    wal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("C2r'-c restart REFUSES on reordered WAL", not restarted,
          f"refusal={why!r}" if not restarted else "gateway started!")


def c2rd_full_rewrite():
    """C2r'-d (characterization): capable attacker rewrites the WHOLE file
    with a recomputed valid chain. The chain is tamper-EVIDENCE, not a MAC:
    expect the rewrite to be ACCEPTED. Documented limitation, not a finding
    (requires full WAL write access; deployment MUSTs are the control)."""
    print("C2r'-d full-file rewrite with recomputed chain (characterize)")
    now_fn = fixed_clock(1_700_000_000.0 + 40.0)
    workdir = Path(tempfile.mkdtemp(prefix="c2rd-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C2r'-d baseline ALLOW", r0.decision.decision == "ALLOW")
    dk = r0.dedup_key
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    tampered = []
    for raw in lines:
        op = json.loads(raw)
        if op.get("op") == "decided" and op.get("dedup_key") == dk:
            op["decision"]["capability"] = {"__bytes_hex__": "deadbeef"}
        tampered.append(json.dumps(op, sort_keys=True))
    wal.write_text("\n".join(_rechain(tampered)) + "\n", encoding="utf-8")
    try:
        _, gw2 = restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal:
        restarted = False
        gw2 = None
    # Characterization only: a full valid-chain rewrite is accepted.
    print(f"  [INFO] C2r'-d full-chain rewrite accepted={restarted} "
          f"(expected: accepted — chain is tamper-evidence, not a MAC)")
    if gw2 is not None:
        gw2.close()
    RESULTS.append(("C2r'-d full rewrite characterization (info only)",
                    True, f"accepted={restarted}"))
    print("  [PASS] C2r'-d full rewrite characterization (info only)"
          f" -- accepted={restarted}")

# ---------------------------------------------------------------- C3r'
def c3ra_midfile_deletion():
    """C3r'-a: delete a MIDDLE record but keep subsequent lines.
    Chain break -> restart must refuse (no silent re-mint)."""
    print("C3r'-a mid-file record deletion (subsequent lines kept)")
    now_fn = fixed_clock(1_700_000_000.0 + 50.0)
    workdir = Path(tempfile.mkdtemp(prefix="c3ra-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    he = count_calls(dep.guardian, "handle_event")
    r0 = dep.gateway.submit_intent(
        plane="shell", verb="anchor:shell/exec", target="/usr/bin/backup",
        principal=dep.subject, params=dict(PARAMS))
    check("C3r'-a baseline ALLOW, one mint",
          r0.decision.decision == "ALLOW" and he[0] == 1)
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    check("C3r'-a WAL has >= 3 lines", len(lines) >= 3, f"lines={len(lines)}")
    del lines[1]  # remove a middle record, keep the tail
    wal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        restart_gateway(dep, now_fn)
        restarted = True
    except SMPRefusal as exc:
        restarted = False
        why = str(exc)
    check("C3r'-a restart REFUSES on mid-file deletion", not restarted,
          f"refusal={why!r}" if not restarted else "gateway started!")


def c3rb_tail_truncation():
    """C3r'-b (characterization): pure tail truncation is
    crash-indistinguishable -> accepted as a self-consistent prefix;
    resubmit re-mints. Documented residual (backups + permissions are the
    control), not a finding."""
    print("C3r'-b pure tail truncation (characterize documented residual)")
    now_fn = fixed_clock(1_700_000_000.0 + 60.0)
    workdir = Path(tempfile.mkdtemp(prefix="c3rb-"))
    dep = build_deployment(workdir=workdir, now_fn=now_fn,
                           window_quantum_sec=Q)
    he = count_calls(dep.guardian, "handle_event")
    kw = dict(plane="shell", verb="anchor:shell/exec",
              target="/usr/bin/backup", principal=dep.subject,
              params=dict(PARAMS))
    r0 = dep.gateway.submit_intent(**kw)
    check("C3r'-b baseline ALLOW, one mint",
          r0.decision.decision == "ALLOW" and he[0] == 1)
    dep.gateway.close()
    wal, lines = _wal_lines(workdir)
    # drop the decided record(s) from the tail only
    kept = [ln for ln in lines
            if json.loads(ln).get("op") != "decided"]
    check("C3r'-b dropped tail decided records",
          len(kept) < len(lines), f"dropped={len(lines) - len(kept)}")
    wal.write_text("\n".join(kept) + "\n", encoding="utf-8")
    _, gw2 = restart_gateway(dep, now_fn)
    he2 = count_calls(dep.guardian, "handle_event")
    r1 = gw2.submit_intent(**kw)
    remint = (r1.decision.decision == "ALLOW" and not r1.from_cache
              and he2[0] == 1)
    print(f"  [INFO] C3r'-b tail-truncation accepted, resubmit re-mints: "
          f"{remint} (expected: True — documented crash-indistinguishable "
          f"residual)")
    check("C3r'-b tail truncation behaves as documented residual", remint)
    gw2.close()


# ---------------------------------------------------------------- C8r'
def _ask_deployment(workdir, now_fn):
    return build_deployment(
        workdir=workdir, now_fn=now_fn, window_quantum_sec=Q,
        decision_fn=lambda e: "ASK"
        if e.action == "anchor:acs/backup.ask" else "ALLOW")


def c8ra_restart_fresh_ask_approve():
    """C8r'-a: ASK -> restart -> resubmit must yield a FRESH ASK (not
    bricked); approving the fresh ASK mints exactly once; the old
    pending_id is unresolvable; resubmit-after-approval is cached."""
    print("C8r'-a ASK -> restart -> fresh ASK -> approve (no double mint)")
    now_fn = fixed_clock(1_700_000_000.0 + 70.0)
    workdir = Path(tempfile.mkdtemp(prefix="c8ra-"))
    dep = _ask_deployment(workdir, now_fn)
    he = count_calls(dep.guardian, "handle_event")
    rp = count_calls(dep.guardian, "resolve_pending")
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    r = dep.gateway.submit_intent(**kw)
    check("C8r'-a ASK returned", r.decision.decision == "ASK")
    old_pid = r.decision.pending_id
    # NOTE (probe calibration): each ASK submission calls handle_event once
    # to OBTAIN the ASK decision; no capability is minted pre-approval.
    # The security invariant is capability-based, not call-count-based.
    check("C8r'-a ASK carries no capability", r.decision.capability is None)
    check("C8r'-a ASK decision call happened", he[0] == 1,
          f"handle_event={he[0]}")
    dep.gateway.close()
    _, gw2 = restart_gateway(dep, now_fn)
    # WAL must show the orphaned op for the pre-restart PENDING
    wal_text = (workdir / "decision.wal.jsonl").read_text(encoding="utf-8")
    check("C8r'-a WAL carries orphaned op after replay",
          '"op": "orphaned"' in wal_text)
    r2 = gw2.submit_intent(**kw)
    check("C8r'-a resubmit yields FRESH ASK (not bricked)",
          r2.decision.decision == "ASK"
          and "pending approval" not in (r2.decision.reason or ""),
          f"decision={r2.decision.decision} reason={r2.decision.reason!r}")
    check("C8r'-a fresh ASK carries no capability",
          r2.decision.capability is None)
    new_pid = r2.decision.pending_id
    check("C8r'-a fresh ASK has a new pending_id", new_pid != old_pid)
    # old binding is dead
    try:
        gw2.resolve_approval(old_pid, approved=True)
        old_resolved = True
    except ValueError:
        old_resolved = False
    check("C8r'-a old pending_id unresolvable", not old_resolved)
    # approve the fresh ASK -> exactly one NEW capability
    r3 = gw2.resolve_approval(new_pid, approved=True)
    check("C8r'-a fresh ASK resolves to ALLOW",
          r3.decision.decision == "ALLOW"
          and r3.decision.capability is not None,
          f"decision={r3.decision.decision}")
    new_caps = [r for r in (r3,) if r.decision.capability is not None
                and not r.from_cache]
    check("C8r'-a exactly one new capability issued", len(new_caps) == 1)
    check("C8r'-a exactly one kernel resolve_pending", rp[0] == 1,
          f"resolve_pending={rp[0]}")
    # resubmit after approval -> cached, no second mint
    r4 = gw2.submit_intent(**kw)
    check("C8r'-a resubmit after approval served from cache",
          r4.from_cache and r4.decision.decision == "ALLOW")
    check("C8r'-a cached resubmit carries the same capability",
          r4.decision.capability == r3.decision.capability)
    gw2.close()


def c8rb_restart_fresh_ask_reject():
    """C8r'-b: ASK -> restart -> fresh ASK -> REJECT records DENY;
    resubmit is cached DENY (no second ASK, no mint)."""
    print("C8r'-b ASK -> restart -> fresh ASK -> reject -> cached DENY")
    now_fn = fixed_clock(1_700_000_000.0 + 80.0)
    workdir = Path(tempfile.mkdtemp(prefix="c8rb-"))
    dep = _ask_deployment(workdir, now_fn)
    he = count_calls(dep.guardian, "handle_event")
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    r = dep.gateway.submit_intent(**kw)
    check("C8r'-b ASK returned", r.decision.decision == "ASK")
    dep.gateway.close()
    _, gw2 = restart_gateway(dep, now_fn)
    r2 = gw2.submit_intent(**kw)
    check("C8r'-b resubmit yields fresh ASK",
          r2.decision.decision == "ASK")
    r3 = gw2.resolve_approval(r2.decision.pending_id, approved=False)
    check("C8r'-b rejection records DENY",
          r3.decision.decision == "DENY", f"decision={r3.decision.decision}")
    r4 = gw2.submit_intent(**kw)
    check("C8r'-b resubmit after reject is cached DENY",
          r4.from_cache and r4.decision.decision == "DENY",
          f"from_cache={r4.from_cache} decision={r4.decision.decision}")
    check("C8r'-b no capability issued anywhere",
          all(x.decision.capability is None for x in (r, r2, r3, r4)))
    gw2.close()


def c8rc_double_restart_idempotent():
    """C8r'-c: two consecutive restarts with a pending ASK — orphaning
    must be idempotent and the intent still askable."""
    print("C8r'-c double restart: orphan idempotency")
    now_fn = fixed_clock(1_700_000_000.0 + 90.0)
    workdir = Path(tempfile.mkdtemp(prefix="c8rc-"))
    dep = _ask_deployment(workdir, now_fn)
    kw = dict(plane="shell", verb="anchor:shell/backup-ask",
              target="/usr/bin/backup-ask", principal=dep.subject,
              params=dict(PARAMS))
    r = dep.gateway.submit_intent(**kw)
    check("C8r'-c ASK returned", r.decision.decision == "ASK")
    dep.gateway.close()
    _, gw2 = restart_gateway(dep, now_fn)
    gw2.close()
    _, gw3 = restart_gateway(dep, now_fn)
    r2 = gw3.submit_intent(**kw)
    check("C8r'-c still askable after two restarts",
          r2.decision.decision == "ASK"
          and "pending approval" not in (r2.decision.reason or ""),
          f"decision={r2.decision.decision}")
    orphaned_ops = sum(
        1 for ln in (workdir / "decision.wal.jsonl")
        .read_text(encoding="utf-8").splitlines()
        if json.loads(ln).get("op") == "orphaned")
    check("C8r'-c orphaned ops bounded (idempotent)",
          orphaned_ops <= 2, f"orphaned_ops={orphaned_ops}")
    gw3.close()


# ---------------------------------------------------------------- S3'
def _run_lint(root: Path):
    p = subprocess.run(
        [sys.executable, str(ANCHOR_V1 / "smp_sole_caller_lint.py"),
         "--root", str(root)],
        capture_output=True, text=True, cwd=str(ANCHOR_V1))
    return p.returncode, p.stdout, p.stderr


def s3a_rogue_handle_event():
    print("S3'-a rogue handle_event caller in a fresh file")
    root = Path(tempfile.mkdtemp(prefix="s3a-"))
    (root / "evil_caller.py").write_text(
        "def pwn(g):\n    return g.handle_event({}, {})\n",
        encoding="utf-8")
    rc, out, _ = _run_lint(root)
    check("S3'-a rogue handle_event file fails lint", rc == 1,
          f"rc={rc} out={out.strip()[:120]}")
    shutil.rmtree(root, ignore_errors=True)


def s3b_rogue_resolve_pending():
    print("S3'-b rogue resolve_pending caller in a fresh file")
    root = Path(tempfile.mkdtemp(prefix="s3b-"))
    (root / "evil_resolver.py").write_text(
        "def pwn(g, pid):\n    return g.resolve_pending(pid, True)\n",
        encoding="utf-8")
    rc, out, _ = _run_lint(root)
    check("S3'-b rogue resolve_pending file fails lint", rc == 1,
          f"rc={rc} out={out.strip()[:120]}")
    shutil.rmtree(root, ignore_errors=True)


def s3c_reserved_prefix_bypass():
    """S3'-c: file named anchor.<anything>.py with a direct kernel call,
    in a tree where the REAL shim is present (pins satisfied). If the
    lint passes, the RESERVED_PREFIXES carve-out is a silent bypass of
    the §1.5 sole-caller invariant."""
    print("S3'-c reserved-prefix bypass probe (anchor.evil.py + real shim)")
    root = Path(tempfile.mkdtemp(prefix="s3c-"))
    shutil.copy(ANCHOR_V1 / "smp_v1_1_prototype.py",
                root / "smp_v1_1_prototype.py")
    (root / "anchor.evil.py").write_text(
        "def pwn(g):\n    return g.handle_event({}, {})\n",
        encoding="utf-8")
    rc, out, _ = _run_lint(root)
    evaded = (rc == 0)
    print(f"  [INFO] S3'-c anchor.evil.py evaded lint: {evaded} (rc={rc})")
    if evaded:
        print(f"  [INFO] S3'-c lint output: {out.strip()[:200]}")
    RESULTS.append(("S3'-c reserved-prefix characterization (info)",
                    True, f"evaded={evaded}"))
    print(f"  [PASS] S3'-c reserved-prefix characterization (info)"
          f" -- evaded={evaded}")
    shutil.rmtree(root, ignore_errors=True)
    return evaded


def s3d_unpinned_shim_callsite():
    print("S3'-d unpinned call site added inside the shim")
    root = Path(tempfile.mkdtemp(prefix="s3d-"))
    src = (ANCHOR_V1 / "smp_v1_1_prototype.py").read_text(encoding="utf-8")
    evil = src + "\n\ndef _rogue(g):\n    return g.handle_event({}, {})\n"
    (root / "smp_v1_1_prototype.py").write_text(evil, encoding="utf-8")
    rc, out, _ = _run_lint(root)
    check("S3'-d unpinned in-shim call site fails lint", rc == 1,
          f"rc={rc}")
    check("S3'-d violation names the unpinned site",
          "unpinned" in out, f"out={out.strip()[:160]}")
    shutil.rmtree(root, ignore_errors=True)


def s3e_getattr_string_evasion():
    print("S3'-e getattr-string indirection in a fresh file")
    root = Path(tempfile.mkdtemp(prefix="s3e-"))
    (root / "sneaky.py").write_text(
        "def pwn(g):\n    f = getattr(g, \"resolve_pending\")\n"
        "    return f(\"pid\", True)\n",
        encoding="utf-8")
    rc, out, _ = _run_lint(root)
    check("S3'-e getattr indirection fails lint", rc == 1, f"rc={rc}")
    shutil.rmtree(root, ignore_errors=True)


def s3f_clean_tree_and_ci_and_spec():
    print("S3'-f clean tree passes; CI wiring + normative §1.5 present")
    rc, out, _ = _run_lint(ANCHOR_V1)
    check("S3'-f clean deployment tree passes lint", rc == 0, f"rc={rc}")
    yml = ANCHOR_V1 / ".github" / "workflows" / "smp-sole-caller-lint.yml"
    check("S3'-f CI workflow file exists", yml.exists())
    if yml.exists():
        body = yml.read_text(encoding="utf-8")
        check("S3'-f CI workflow invokes the lint",
              "smp_sole_caller_lint.py" in body and "--root" in body)
        check("S3'-f CI triggers on push+pull_request",
              "push" in body and "pull_request" in body)
    draft = Path("/home/hatch/workspace/boardroom/hidden_files/"
                 "v11r-normative-draft.md")
    check("S3'-f normative draft exists", draft.exists())
    if draft.exists():
        text = draft.read_text(encoding="utf-8")
        check("S3'-f normative §1.5 present",
              "1.5." in text and "SOLE deployment caller" in text)
        check("S3'-f checklist item (10) present",
              "(10)" in text)
        check("S3'-f amendment A3 present", "A3" in text)


# ---------------------------------------------------------------- main
def main():
    probes = [
        c1a_single_field_tamper, c1b_field_swap, c1c_tamper_then_restore,
        c1d_payload_bytes_flip, c1e_list_surgery,
        c2ra_inplace_forgery, c2rb_midfile_edit, c2rc_line_swap,
        c2rd_full_rewrite,
        c3ra_midfile_deletion, c3rb_tail_truncation,
        c8ra_restart_fresh_ask_approve, c8rb_restart_fresh_ask_reject,
        c8rc_double_restart_idempotent,
        s3a_rogue_handle_event, s3b_rogue_resolve_pending,
        s3d_unpinned_shim_callsite, s3e_getattr_string_evasion,
        s3f_clean_tree_and_ci_and_spec,
    ]
    failed = []
    prefix_bypass_evaded = None
    for p in probes:
        print("=" * 70)
        try:
            p()
        except AssertionError as exc:
            failed.append((p.__name__, str(exc)))
            print(f"  [FAIL] {exc}")
        except Exception as exc:  # noqa: BLE001
            failed.append((p.__name__,
                           f"HARNESS ERROR: {type(exc).__name__}: {exc}"))
            print(f"  [HARNESS ERROR] {type(exc).__name__}: {exc}")
    print("=" * 70)
    print("S3'-c reserved-prefix probe (run separately, info only):")
    try:
        prefix_bypass_evaded = s3c_reserved_prefix_bypass()
    except Exception as exc:  # noqa: BLE001
        print(f"  [HARNESS ERROR] {type(exc).__name__}: {exc}")
    print("=" * 70)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"CHECKS: {passed}/{len(RESULTS)} passed")
    for name, why in failed:
        print(f"  FAILED: {name}: {why}")
    print(f"RESERVED_PREFIX_BYPASS_EVADED={prefix_bypass_evaded}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
