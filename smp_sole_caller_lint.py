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
  4. Bare (non-call) references to either method — aliases
     (he = guardian.handle_event), functools.partial / conditional /
     decorator arguments, etc. A bare reference is a call-site indirection
     the pin set cannot see; fail closed. The self./cls. exemption in (1)
     applies unchanged.
  5. Constant-string target-name indirections: operator.methodcaller("m"),
     X.__getattribute__("m") / X.__getattr__("m"), and
     X.__dict__["m"], where "m" names either method. Computed
     (non-constant) names remain the documented dataflow limitation.
  6. Import-alias resolution (v11h): a per-file map built from
     ast.Import / ast.ImportFrom (e.g. `from operator import
     methodcaller as mc` -> mc resolves to operator.methodcaller;
     `from builtins import getattr as g`; `import operator as op` was
     already covered via the Attribute form). Bare-Name calls resolved
     through the map to methodcaller / getattr / __getattribute__ /
     __getattr__ / eval / exec are flagged exactly like their unaliased
     forms (the constant-string rules in (3)/(5) apply unchanged).
     Assignment aliases (ga = getattr) remain the documented L9
     dataflow limitation — only import statements are resolved
     (v11f-critic probe C7 pins that behaviour). A name bound by any
     other statement (assignment, def, lambda arg, ...) shadows the
     import and is dropped from the map, so local bindings cannot
     produce false positives.

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
# v11g: pins moved 1192/1369/1389 -> 1200/1377/1397 -> 1209/1386/1406 (L8 doc note) (deliberate pin
# maintenance for the SERIOUS-1 _append-lock line shift; call sites
# themselves unchanged).
# harden-A: pins moved 1209/1386/1406 -> 1291/1468/1488 (deliberate pin
# maintenance for the _replay torn-tail recovery line shift; call sites
# themselves unchanged).
# harden-F: pins moved 1291/1468/1488 -> 1313/1490/1510 (deliberate pin
# maintenance for the clock-watermark line shift; call sites themselves
# unchanged).
# harden-C: pins moved 1313/1490/1510 -> 1402/1611/1633 (deliberate pin
# maintenance for the cross-bucket carry-over line shift; call sites
# themselves unchanged).
# harden-G: pins moved 1402/1611/1633 -> 1501/1709/1731 (deliberate pin
# maintenance for the per-key-lock TTL-eviction line shift; call sites
# themselves unchanged).
# harden-B: pins moved 1501/1709/1731 -> 1827/2056/2078 (deliberate pin
# maintenance for the cross-process xproc_section extraction line shift —
# submit/resolve critical sections moved into _submit_under_key_lock /
# _resolve_under_section; the three call sites themselves unchanged).
PINNED_SITES = frozenset({
    ("smp_v1_1_prototype.py", 1827, "handle_event"),
    ("smp_v1_1_prototype.py", 2056, "resolve_pending"),
    ("smp_v1_1_prototype.py", 2078, "resolve_pending"),
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


class _AliasMapVisitor(ast.NodeVisitor):
    """v11h: per-file import-alias map.

    Only ast.Import / ast.ImportFrom bindings are resolved — import
    statements are static and unambiguous. Runtime assignment aliases
    (``ga = getattr``) remain the documented L9 dataflow limitation
    (v11f-critic probe C7 pins that behaviour: assignment aliases pass
    the lint). A name bound by any other statement (assignment,
    function/class/lambda/comprehension binding) shadows the import and
    is dropped from the map, so local bindings cannot produce false
    positives through the alias path.
    """

    def __init__(self):
        self.aliases: dict[str, tuple[str, ...]] = {}
        self.shadow: set[str] = set()

    def visit_Import(self, node: ast.Import):
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            self.aliases[local] = tuple(a.name.split("."))

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module is None:
            return  # relative import — cannot resolve statically
        for a in node.names:
            if a.name == "*":
                continue
            local = a.asname or a.name.split(".")[0]
            self.aliases[local] = tuple(node.module.split(".")) + (a.name,)

    # --- shadowing bindings (every non-import binding site) ---
    def _bind_target(self, target: ast.AST):
        for n in ast.walk(target):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                self.shadow.add(n.id)
            elif isinstance(n, ast.arg):
                self.shadow.add(n.arg)

    def _bind_args(self, args: ast.arguments):
        for a in (args.posonlyargs + args.args + args.kwonlyargs):
            self.shadow.add(a.arg)
        if args.vararg:
            self.shadow.add(args.vararg.arg)
        if args.kwarg:
            self.shadow.add(args.kwarg.arg)

    def visit_Assign(self, node: ast.Assign):
        for t in node.targets:
            self._bind_target(t)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        self._bind_target(node.target)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        self._bind_target(node.target)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.shadow.add(node.target.id)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self._bind_target(node.target)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With):
        for item in node.items:
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            self.shadow.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.shadow.add(node.name)
        self._bind_args(node.args)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        self.shadow.add(node.name)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda):
        self._bind_args(node.args)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension):
        self._bind_target(node.target)
        self.generic_visit(node)


def _build_alias_map(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Per-file import-alias map with shadowed names removed."""
    visitor = _AliasMapVisitor()
    visitor.visit(tree)
    return {k: v for k, v in visitor.aliases.items()
            if k not in visitor.shadow}


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str,
                 aliases: dict[str, tuple[str, ...]] | None = None):
        self.rel = rel
        self._aliases = aliases or {}
        self.sites: list[tuple[int, str]] = []       # (lineno, attr)
        self.indirect: list[tuple[int, str]] = []    # (lineno, detail)
        self.bare: list[tuple[int, str]] = []        # (lineno, attr)
        # Method-name sets of the lexically enclosing classes, innermost
        # last. A self./cls. call to a target method is internal dispatch
        # (not a deployment caller under §1.5) only when the enclosing
        # class DEFINES that method — the guardian calling itself. A
        # subclass that merely inherits the name is still flagged.
        self._class_methods: list[set[str]] = []
        # id()s of Attribute nodes already recorded as call funcs, so the
        # bare-reference pass does not double-report a pinned call site.
        self._call_attr_ids: set[int] = set()

    def _call_kind(self, func: ast.AST) -> tuple[str | None, str]:
        """Invocation kind of a call func, resolving bare Names through
        the per-file import-alias map. Returns (kind, alias_note)."""
        if isinstance(func, ast.Attribute):
            return func.attr, ""
        if isinstance(func, ast.Name):
            alias = self._aliases.get(func.id)
            if alias is not None:
                return (alias[-1],
                        f" [import alias {func.id} -> {'.'.join(alias)}]")
            return func.id, ""
        return None, ""

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in TARGET_ATTRS:
            if not self._is_self_call_to_own_method(func):
                self.sites.append((func.lineno, func.attr))
                self._call_attr_ids.add(id(func))
        else:
            # Immediately-invoked indirection: getattr(X, "m")(...) — the
            # indirection call is the func; its args carry the name.
            inner = func if isinstance(func, ast.Call) else node
            kind, via = (self._call_kind(inner.func)
                        if isinstance(inner, ast.Call) else (None, ""))
            if kind == "getattr":
                # getattr indirection: assigned (f = getattr(X, "m")) or
                # immediately invoked (getattr(X, "m")(...)).
                if (len(inner.args) >= 2
                        and isinstance(inner.args[1], ast.Constant)
                        and inner.args[1].value in TARGET_ATTRS):
                    self.indirect.append(
                        (node.lineno,
                         f"getattr(..., {inner.args[1].value!r}){via}"))
            elif kind in ("methodcaller", "__getattribute__",
                          "__getattr__"):
                # Constant-string target-name indirections: computed
                # (non-constant) names remain the documented dataflow
                # limitation and are NOT flagged.
                if (inner.args
                        and isinstance(inner.args[0], ast.Constant)
                        and inner.args[0].value in TARGET_ATTRS):
                    self.indirect.append(
                        (node.lineno,
                         f"{kind}(..., {inner.args[0].value!r}){via}"))
            elif kind in ("eval", "exec"):
                for arg in inner.args:
                    if (isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)
                            and any(a in arg.value
                                    for a in TARGET_ATTRS)):
                        self.indirect.append(
                            (node.lineno,
                             f"{kind}() naming a target method{via}"))
        self.generic_visit(node)

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

    def visit_Attribute(self, node: ast.Attribute):
        # v11g (SERIOUS-2a): a bare reference to a target method —
        # alias (he = guardian.handle_event), functools.partial /
        # conditional / decorator argument — is a call-site indirection
        # the pin set cannot see. Flag it even when not called here.
        # The self./cls. internal-dispatch exemption applies unchanged:
        # only self./cls. where the enclosing class DEFINES the method
        # is exempt. Call funcs recorded above are skipped by id so a
        # pinned call site is not double-reported.
        if (node.attr in TARGET_ATTRS
                and id(node) not in self._call_attr_ids
                and not self._is_self_call_to_own_method(node)):
            self.bare.append((node.lineno, node.attr))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # v11g (SERIOUS-2b): X.__dict__["handle_event"] with a constant
        # target name, e.g. type(g).__dict__["handle_event"].__get__(g).
        value = node.value
        if (isinstance(value, ast.Attribute)
                and value.attr == "__dict__"
                and isinstance(node.slice, ast.Constant)
                and node.slice.value in TARGET_ATTRS):
            self.indirect.append(
                (node.lineno,
                 f"__dict__[{node.slice.value!r}] indirection"))
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
        visitor = _Visitor(rel, _build_alias_map(tree))
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
        for lineno, attr in visitor.bare:
            # Bare references are call-site indirections the pin set
            # cannot see: fail closed everywhere, including the shim
            # (the pinned call sites are recorded as calls, not bare).
            where = ("inside the designated shim but outside the pinned "
                     "call set" if rel in ALLOW
                     else "outside the designated shim")
            violations.append(
                f"{rel}:{lineno}: bare .{attr} reference {where} — "
                f"violates normative §1.5 sole-caller invariant")
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
