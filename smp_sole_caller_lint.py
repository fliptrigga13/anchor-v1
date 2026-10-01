#!/usr/bin/env python3
"""Sole-caller CI enforcement for guardian.handle_event and
guardian.resolve_pending (normative §1.5).

Normative basis (v11r-normative-draft.md §1.5): the deployment's
SmpGateway (the §1.1 shim's mint wrapper) is the SOLE deployment caller
of `AcsGuardian.handle_event` and `AcsGuardian.resolve_pending`. This
lint fails the build on:

  1. Any in-scope attribute call `.handle_event(...)` / `.resolve_pending(...)`
     in a scanned file other than the designated shim module — except a
     `self.`/`cls.` call where the lexically enclosing class DEFINES that
     method (the guardian calling itself is internal dispatch, not a
     deployment caller under §1.5). A `self.` call from a class that
     merely inherits the name is still flagged (fail-closed).
  2. Any call site of either method inside the shim module that is NOT in
     the pinned call-site set (fail on additions AND on missing pins —
     the pin is the contract; changing the shim's call sites requires a
     deliberate pin update).
  3. Indirect invocations via getattr / eval / exec that name either
     method anywhere in scope (including immediately-invoked
     getattr(X, "handle_event")(...)).

Scope: the deployment source tree. Skipped (not deployment runtime
callers under §1.5):
  * nested git repositories (e.g. the vendored anchor-v1/ kernel repo —
    the kernel's own unit tests must call the kernel to test it);
  * named test / probe / demo / redteam fixtures (exact relative paths
    and the redteam2/ directory) — adversarial harnesses whose purpose is
    to exercise or bypass the shim.

Only `smp_v1_1_prototype.py` is allowlisted, and only at the pinned
lines. Everything else in scope fails closed.

Usage (also wired in .github/workflows/smp-sole-caller-lint.yml):
    python3 smp_sole_caller_lint.py --root <repo-root>
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# Designated shim layer: the SmpGateway sole-caller module (normative §1.5).
ALLOW = {"smp_v1_1_prototype.py": "normative §1.5 designated shim layer"}

# Exact pinned call sites: (relative filename, line number, method name).
# Update deliberately when the shim's call sites change; both additions
# and disappearances fail the build.
PINNED_SITES = frozenset({
    ("smp_v1_1_prototype.py", 1192, "handle_event"),
    ("smp_v1_1_prototype.py", 1369, "resolve_pending"),
    ("smp_v1_1_prototype.py", 1389, "resolve_pending"),
})

TARGET_ATTRS = ("handle_event", "resolve_pending")

# Probe / harness / demo fixtures that deliberately call the kernel
# directly. They are not deployment runtime code, so §1.5 does not apply
# to them; they are excluded by exact relative path (root-level names —
# basename-only matching would let subdir/<fixture>.py evade the lint).
# The kernel's own unit tests (tests/test_*.py) and the reality-trial
# harness must call the kernel to test it — same documented category.
EXCLUDE_FILES = {
    "smp_sole_caller_lint.py",
    "v11d_smp_probes.py",
    "v11c_smp_probes.py",
    "v11r_smp_probes.py",
    "smp_adversarial_probes_v2.py",
    "v11d_critic_probes2.py",
    "v11d_critic_c11b.py",
    "v11e_verify.py",
    "v11e_critic_probes.py",
    "v11f_critic_probes.py",
    "seam_probe.py",
    "demo_governance.py",
    "reality_trial.py",
    "tests/test_acs_guardian.py",
    "tests/test_guardian_pep_integration.py",
    "tests/test_redteam2_fixes.py",
}

# Fixture directories (redteam/adversarial) excluded wholesale.
EXCLUDE_DIRS = {"redteam2"}


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.sites: list[tuple[int, str]] = []       # (lineno, attr)
        self.indirect: list[tuple[int, str]] = []    # (lineno, detail)
        # Method-name sets of the lexically enclosing classes, innermost
        # last. A self./cls. call to a target method is internal dispatch
        # (not a deployment caller under §1.5) only when the enclosing
        # class DEFINES that method — the guardian calling itself. A
        # subclass that merely inherits the name is still flagged.
        self._class_methods: list[set[str]] = []

    @staticmethod
    def _getattr_target(node: ast.AST) -> str | None:
        """If node is getattr(X, "<target-method>"), return the method."""
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in TARGET_ATTRS):
            return node.args[1].value
        return None

    def visit_ClassDef(self, node: ast.ClassDef):
        defined = {n.name for n in node.body
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self._class_methods.append(defined)
        self.generic_visit(node)
        self._class_methods.pop()

    def _is_self_call_to_own_method(self, func: ast.Attribute) -> bool:
        """True for self.X()/cls.X() where the enclosing class defines X."""
        return (isinstance(func.value, ast.Name)
                and func.value.id in ("self", "cls")
                and bool(self._class_methods)
                and func.attr in self._class_methods[-1])

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in TARGET_ATTRS:
            if not self._is_self_call_to_own_method(func):
                self.sites.append((func.lineno, func.attr))
        else:
            # getattr indirection: assigned (f = getattr(X, "m")) or
            # immediately invoked (getattr(X, "m")(...)).
            target = self._getattr_target(func)
            if target is None:
                target = self._getattr_target(node)
            if target is not None:
                self.indirect.append(
                    (node.lineno, f"getattr(..., {target!r})"))
            elif isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                for arg in node.args:
                    if (isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)
                            and any(a in arg.value for a in TARGET_ATTRS)):
                        self.indirect.append(
                            (node.lineno,
                             f"{func.id}() naming a target method"))
        self.generic_visit(node)


def _in_nested_repo(root: Path, path: Path) -> bool:
    """True if path lives under a nested git repository (vendored dep)
    strictly below root. root itself being a git checkout does not count
    — otherwise scanning a repo working tree would skip every file and
    the pin set would go vacuously unobserved (S3'' merge fix)."""
    rel = path.relative_to(root)
    for parent in rel.parents:
        if parent == Path("."):
            continue
        if (root / parent / ".git").exists():
            return True
    return False


def iter_py_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if ".venv" in parts or "__pycache__" in parts:
            continue
        # Exact relative path match only: a fixture basename placed in a
        # subdirectory must NOT inherit the exclusion (S3' fix).
        if path.relative_to(root).as_posix() in EXCLUDE_FILES:
            continue
        if any(d in EXCLUDE_DIRS for d in parts):
            continue
        if _in_nested_repo(root, path):
            continue
        yield path


def check_tree(root: Path) -> tuple[list[str], list[tuple[str, int, str]]]:
    """Return (violations, observed_pinned_sites)."""
    violations: list[str] = []
    observed: list[tuple[str, int, str]] = []
    for path in iter_py_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"),
                             filename=str(path))
        except (OSError, SyntaxError) as exc:
            violations.append(f"{rel}: unreadable ({exc})")
            continue
        visitor = _Visitor(rel)
        visitor.visit(tree)
        for lineno, attr in visitor.sites:
            if rel in ALLOW:
                observed.append((rel, lineno, attr))
                if (rel, lineno, attr) not in PINNED_SITES:
                    violations.append(
                        f"{rel}:{lineno}: unpinned .{attr}(...) call site — "
                        f"not in the §1.5 pinned set; update the pin "
                        f"deliberately or remove the call")
            else:
                violations.append(
                    f"{rel}:{lineno}: .{attr}(...) call outside the "
                    f"designated shim — violates normative §1.5 sole-caller "
                    f"invariant")
        for lineno, detail in visitor.indirect:
            violations.append(
                f"{rel}:{lineno}: indirect target-method invocation "
                f"{detail} — violates normative §1.5")
    # Non-vacuous: the pinned set must be fully observed. A missing pin
    # means the shim was refactored without a deliberate pin update.
    for pin in sorted(PINNED_SITES):
        if pin not in observed:
            violations.append(
                f"{pin[0]}:{pin[1]}: pinned .{pin[2]}(...) call site not "
                f"found — shim refactored without a deliberate pin update")
    return violations, observed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CI lint: normative §1.5 sole-caller invariant")
    parser.add_argument("--root", default=".",
                        help="repository root to scan (default: .)")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    violations, observed = check_tree(root)
    if violations:
        print("SOLE-CALLER LINT FAILED (normative §1.5):")
        for v in violations:
            print(f"  - {v}")
        return 1
    for rel, lineno, attr in sorted(observed):
        print(f"  ALLOWED {rel}:{lineno} .{attr}(...) (pinned, §1.5)")
    print(f"sole-caller lint OK: {len(observed)} pinned call site(s), "
          f"no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
