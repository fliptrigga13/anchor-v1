#!/usr/bin/env python3
"""v11f-critic: sixth battle-test — fresh independent adversarial
re-adjudication of the SERIOUS-1 (v11e-critic) lint remediation.

Zero deference to the fix agent's claims: every probe here is a FRESH
variant (new filenames, new evasion shapes), not a re-run of the
fix-agent's or v11e-critic's probes.

Target: ~/workspace/anchor-v1/smp_sole_caller_lint.py + the real tree.
Rules: real modules, zero mocks, zero kernel edits. Temporary fixture
files are created inside the tree and ALWAYS removed (try/finally).

Probe groups:
  V11F-A  anchor.<arbitrary>.py with direct handle_event AND
          resolve_pending calls -> must FAIL (carve-out was deleted)
  V11F-B  nested subdir/<excluded-fixture-basename>.py with direct
          kernel calls -> must FAIL (basename-only match was removed)
  V11F-C  dynamic evasion variants: characterize caught vs passed.
          L9 (dataflow out of scope) stands ONLY IF constant-string
          getattr/eval/exec are still caught.
  V11F-D  pin-count correctness on an ISOLATED copy of the shim
          (never the real tree): missing pin / added call site -> must
          FAIL naming the site.
  V11F-E  clean deployment tree -> must PASS rc=0, exactly 3 pins.

Run from ~/workspace/anchor-v1 with ./.venv/bin/python.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TREE = Path("/home/hatch/workspace/anchor-v1")
LINT = TREE / "smp_sole_caller_lint.py"
PY = sys.executable

RESULTS: list[tuple[str, bool, str]] = []
_created: list[Path] = []


def check(name: str, cond: bool, detail: str = ""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    if not cond:
        raise AssertionError(f"PROBE FAILED: {name} -- {detail}")


def lint(root: Path) -> tuple[int, str]:
    p = subprocess.run([PY, str(LINT), "--root", str(root)],
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout + p.stderr


def make(rel: str, body: str) -> Path:
    p = TREE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    _created.append(p)
    return p


DIRECT = "g.handle_event(ev)\ng.resolve_pending(pid, True)\n"


def expect_fail(name: str, rel: str, body: str, *must_name: str):
    make(rel, body)
    try:
        rc, out = lint(TREE)
    finally:
        cleanup()
    ok = rc == 1 and all(m in out for m in must_name)
    check(name, ok, f"rc={rc} names={must_name} :: "
          + (out.strip().splitlines()[-1][:120] if rc == 1 else
             out[:200]))


def expect_pass(name: str, rel: str, body: str):
    make(rel, body)
    try:
        rc, out = lint(TREE)
    finally:
        cleanup()
    check(name, rc == 0, f"rc={rc} :: {out[:160]}")


def cleanup():
    for p in reversed(_created):
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass
    _created.clear()
    # remove dirs we created if empty
    for d in (TREE / "sub", TREE / "deep", TREE / "anchor.deep_nest"):
        try:
            d.rmdir()
        except OSError:
            pass


try:
    print("== V11F-A: anchor.<arbitrary>.py carve-out deletion ==")
    expect_fail("V11F-A1", "anchor.backdoor.py", DIRECT,
                "anchor.backdoor.py", "handle_event", "resolve_pending")
    expect_fail("V11F-A2", "anchor.py", DIRECT, "anchor.py")
    expect_fail("V11F-A3", "anchor.deep_nest/x.py", DIRECT,
                "anchor.deep_nest/x.py")
    cleanup()

    print("== V11F-B: subdir/<excluded-fixture-basename>.py ==")
    expect_fail("V11F-B1", "sub/v11d_smp_probes.py", DIRECT,
                "sub/v11d_smp_probes.py")
    expect_fail("V11F-B2", "deep/nested/v11r_smp_probes.py", DIRECT,
                "deep/nested/v11r_smp_probes.py")
    expect_fail("V11F-B3", "sub/v11e_verify.py", DIRECT,
                "sub/v11e_verify.py")
    cleanup()

    print("== V11F-C: dynamic evasion characterization ==")
    # constant-string forms MUST be caught (fail) — L9 precondition
    expect_fail("V11F-C1", "v11f_c1.py",
                'f = getattr(g, "handle_event")\nf(ev)\n',
                "getattr")
    expect_fail("V11F-C2", "v11f_c2.py",
                'getattr(g, "resolve_pending")(pid, True)\n',
                "getattr")
    expect_fail("V11F-C3", "v11f_c3.py",
                'eval("g.handle_event(ev)")\n', "eval()")
    expect_fail("V11F-C4", "v11f_c4.py",
                'exec("g.resolve_pending(pid, False)")\n', "exec()")
    expect_fail("V11F-C5", "v11f_c5.py",
                'getattr(__import__("mod"), "handle_event")(ev)\n',
                "getattr")
    # computed / dynamically-aliased forms are EXPECTED to pass lint
    # (accepted L9 limitation: dataflow analysis out of scope)
    expect_pass("V11F-C6", "v11f_c6.py",
                'getattr(g, "handle_" + "event")(ev)\n')
    expect_pass("V11F-C7", "v11f_c7.py",
                'ga = getattr\nga(g, "handle_event")(ev)\n')
    expect_pass("V11F-C8", "v11f_c8.py",
                'eval("g." + "handle_event" + "(ev)")\n')
    # v11g supersedes the L9 accepted limitation for BARE ALIASES: the
    # SERIOUS-2 fix now fails the lint on bare target-method references
    # (he = guardian.handle_event), so C9 is caught, not passed.
    expect_fail("V11F-C9", "v11f_c9.py",
                'h = g.handle_event\nh(ev)\n',
                "bare .handle_event reference")
    expect_pass("V11F-C10", "v11f_c10.py",
                'm = "handle_event"\ngetattr(g, m)(ev)\n')
    cleanup()

    print("== V11F-D: pin-count correctness (isolated shim copy) ==")
    tmp = Path(tempfile.mkdtemp(prefix="v11f_pin_"))
    try:
        shim_src = TREE / "smp_v1_1_prototype.py"
        shim = tmp / "smp_v1_1_prototype.py"
        shim.write_text(shim_src.read_text(encoding="utf-8"),
                        encoding="utf-8")
        rc, out = lint(tmp)
        check("V11F-D0 baseline isolated copy passes", rc == 0,
              f"rc={rc}")
        # D1: remove the pinned 1827 call (replace line, keep line count).
        # harden-B: pin moved 1209 -> 1827 (cross-process xproc_section
        # extraction line shift; call site itself unchanged). Scratch-only
        # probe maintenance.
        lines = shim.read_text(encoding="utf-8").splitlines(keepends=True)
        assert "handle_event" in lines[1826], lines[1826]
        lines[1826] = "                # REMOVED-BY-V11F-D1\n"
        shim.write_text("".join(lines), encoding="utf-8")
        rc, out = lint(tmp)
        check("V11F-D1 removed pin fails naming site",
              rc == 1 and "smp_v1_1_prototype.py:1827" in out
              and "not found" in out,
              f"rc={rc} :: {[l for l in out.splitlines() if '1827' in l]}")
        # D2: restore, then ADD an unpinned call site at end of file
        shim.write_text(shim_src.read_text(encoding="utf-8"),
                        encoding="utf-8")
        with shim.open("a", encoding="utf-8") as f:
            f.write("\n\ndef _v11f_rogue(g, ev):\n"
                    "    return g.handle_event(ev)\n")
        rc, out = lint(tmp)
        check("V11F-D2 added call site fails naming it",
              rc == 1 and "unpinned .handle_event(...) call site" in out,
              f"rc={rc} :: {[l for l in out.splitlines() if 'unpinned' in l]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("== V11F-E: clean deployment tree ==")
    cleanup()
    rc, out = lint(TREE)
    allowed = [l for l in out.splitlines() if l.strip().startswith("ALLOWED")]
    check("V11F-E1 clean tree rc=0", rc == 0, f"rc={rc}")
    check("V11F-E2 exactly 3 pinned sites", len(allowed) == 3,
          f"pins={allowed}")
    # harden-B: pins moved 1209/1386/1406 -> 1827/2056/2078 (cross-process
    # xproc_section extraction line shift; call sites themselves unchanged).
    # Scratch-only probe maintenance.
    check("V11F-E3 pinned sites are 1827/2056/2078",
          all(f":{n} " in " ".join(allowed) for n in (1827, 2056, 2078)),
          f"pins={allowed}")
    # zero stray v11f files remain in the tree. The shipped
    # v11f_critic_probes.py is a legitimate repo file (not a stray);
    # leftover attack fixtures are named v11f_c*.py and are still flagged.
    strays = [p.name for p in TREE.rglob("v11f_*")
              if p.name != "v11f_critic_probes.py"]
    strays += [p.name for p in TREE.rglob("anchor.*.py")]
    check("V11F-E4 no stray probe files in tree", not strays,
          f"strays={strays}")

    print(f"\nV11F RESULT: {sum(1 for _, ok, _ in RESULTS if ok)}/"
          f"{len(RESULTS)} probes green")
finally:
    cleanup()
