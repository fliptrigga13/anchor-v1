# ANCHOR v1 — Authoritative Repository Inventory
Generated: 2026-09-27 | Commit HEAD: b991727 | Python 3.12 target

## 1. Repository Topology

```
repo/
├── pyproject.toml                     version = "1.1.0"
├── README.md                          5,978 chars
├── CHANGELOG.md                       116 lines
├── adversarial_harness.py             3,042 chars (attack runner)
├── src/anchor_v1/                     25 Python modules
│   ├── __init__.py                    2 lines
│   ├── acs_guardian.py                ACS Guardian integration
│   ├── agent_identity.py              did:key + COSE capability assertions
│   ├── anchored_checkpoints.py        OTS hand-rolled codec
│   ├── authority.py                   Core authority engine
│   ├── cbor.py                        Deterministic CBOR (RFC 8949)
│   ├── canonical.py                   Canonical encoding
│   ├── cose.py                        COSE_Sign1 (RFC 9052)
│   ├── crypto.py                      Ed25519 + SHA-256 primitives
│   ├── envelope.py                    ActionEnvelope + digest binding
│   ├── identity_adapters.py           SPIFFE SVID / OIDC / Entra
│   ├── models.py                      StrictModel base
│   ├── multisig_constitution.py       m-of-n quorum
│   ├── pep.py                         ShellPEP + EgressProxy
│   ├── planes.py                      MCP/A2C plane reframe
│   ├── policy_providers.py            Native + Cedar/Rego subsets
│   ├── provenance.py                  Provenance-bound read caps
│   ├── scitt.py                       RFC 9943 evidence mapping
│   ├── store.py                       SQLite CapabilityStore
│   ├── state_binding.py               TOCTOU defense (EffectPreview)
│   ├── stepup.py                      WebAuthn + m-of-n challenge ledger
│   └── (modules referenced from changelog: authority, store, pep,
│       envelope, cbor, cose, crypto, acs_guardian, agent_identity,
│       policy_providers, identity_adapters, stepup, state_binding,
│       scitt, provenance, planes, mcp_gateway, a2a,
│       anchored_checkpoints, multisig_constitution, models)
├── tests/                             15 test files, 929 test_ functions (static)
│   ├── test_conformance.py            12 named guarantees
│   ├── test_guardian_pep_integration.py  13 tests + 1 xfail
│   ├── test_redteam2_fixes.py         P5 tripwire + redteam fixes
│   ├── test_acs_guardian.py           77 tests (65 unit + 12 adversarial)
│   ├── test_authority.py              authority + store unit tests
│   ├── test_a2a.py                    A2A gateway tests
│   ├── test_mcp_gateway.py            MCP gateway tests
│   ├── test_policy_providers.py       policy tests
│   ├── test_state_binding.py          state binding tests
│   ├── test_scitt.py                  SCITT tests
│   ├── test_provenance.py             provenance tests
│   ├── test_envelope.py               envelope tests
│   ├── test_delegation_chains.py      delegation chain tests
│   ├── test_stepup.py                 stepup tests
│   └── (additional wave test files)
├── docs/
│   ├── SBOM.md                        92 lines, 3rd-party dependency audit
│   ├── SPEC.md                        134 lines, formal spec summary
│   ├── THREAT_MODEL.md                10,417 chars, 45-scenario adversary harness
│   ├── REPRODUCIBLE_BUILDS.md         4,898 chars, determinism evidence
│   ├── SIGSTORE.md                    101 lines, release-day run-book
│   └── research/                      4 dossiers
│       ├── RESEARCH_DELEGATION_AND_IETF_STANDARDS.md
│       ├── RESEARCH_OWASP_ACS_GUARDIAN.md
│       ├── RESEARCH_TOCTOU_STATE_BINDING.md
│       └── SWARM_COMMAND_DISPATCH.md
├── tla/                               TLA+ formal verification
│   ├── authority.tla                  460 lines, 7 invariants (I1–I7)
│   ├── authority.cfg                  27 lines (TLC config)
│   ├── authority-small.cfg            26 lines (reduced model)
│   ├── README.md                      213 lines, TLC run-book
│   └── TLC_RUN_RESULTS.txt            3,224 chars, TLC output
├── rust/verifier/                     Rust canonical/CBOR verifier
│   ├── src/                           19 .rs files, 2,171 lines
│   ├── fuzz/                          fuzz targets (canonical_json, cbor_decode)
│   ├── fixtures/                      JSON test fixtures (6 files)
│   ├── Cargo.toml / Cargo.lock
│   ├── deny.toml                      deny(…)-warnings config
│   ├── rust-toolchain.toml
│   └── README.md
└── .github/workflows/
    ├── ci.yml                         push to anchor-v1 + PRs, Python 3.12
    ├── security-ci.yml                security scan CI
    └── release-sign.yml               release signing workflow
```

## 2. Test Suite Summary

| Source | Static test_ functions | Pytest collected (historical) | Notes |
|---|---|---|---|
| Wave 0 ACS Guardian | 77 | 77 | 65 unit + 12 adversarial |
| Wave 1 Envelope/COSE | 82 | 82 | 15 adversarial all rejected |
| Wave 2 Authority | 74 | 74 | 57 unit + 17 adversarial |
| Guardian integration | 90 | 90 | Suite 450/450 at that point |
| Wave 3 Planes | (MCP + A2A full files) | — | 82 tests claimed |
| Wave 4 Trust core | 90 (28+35+27) | — | Suite 697→703 |
| Wave 5 Enterprise | 302 | — | Suite 1005/1005 |
| Wave 6 Conformance | 12 | — | Suite 1017/1017 |
| Wave 7 Guardian<->PEP | 13 + 1 xfail | — | Suite 1030/1030 |
| **Total (claimed)** | | **1044 collected** | **1043 pass + 1 xfail** |

**Current environment note**: `pip install -e ".[test]"` fails because the shell Python is 3.11.9 (pyproject.toml requires >=3.12). The suite cannot be collected or run in the current environment. The 1044/1043+1 numbers are historical runs on Python 3.12.14 (aarch64).

Static count of `def test_` / `async def test_` across all test files: **929**.
With parametrization, the documented collected count is **1,044**.

## 3. Adversarial Harness Results (docs/THREAT_MODEL.md)

45 scenarios: 43 PASS, 2 FLAG, 0 FAIL
- FLAG-1 (line 48): cross-plane verb/target mapping — P5 residual, documented limitation
- FLAG-2 (line 66): guardian PEP double-mint replay tripwire — intentional xfail

## 4. TLA+ Verification (tla/)

- `authority.tla`: 460 lines, 7 invariants
- TLC config: `authority.cfg` (27 lines) + `authority-small.cfg` (26 lines)
- TLC results: `TLC_RUN_RESULTS.txt` (3,224 chars) — run documented in `tla/README.md`

## 5. Rust Verifier (rust/verifier/)

- 19 source files, 2,171 lines in `src/`
- Fuzz targets: `canonical_json.rs`, `cbor_decode.rs`
- Fixtures: canonical.json, cbor.json, chain.json, cose.json, envelope.json, holder.json, inclusion.json
- `deny.toml`: clippy deny-warnings config

## 6. Git Metadata (verified)

- Tags: v1.0.0, v1.0.1, v1.1.0
- HEAD: b991727 (v1.1.0)
- v1.0.0 tag → b1949ccd1a9b7f2e8be68e50fecfc292d5d015bf ✓ (annotated tag confirmed)
- pyproject.toml version: 1.1.0 ✓
- README release claim: "Release v1.0.0 (annotated tag on commit b1949cc)" ✓ matches

## 7. Discrepancies / Findings

1. **Test collection failure in current env**: Python 3.11.9 on PATH; pyproject.toml requires >=3.12. Suite cannot be executed without activating a venv with Python 3.12+. The 1044/1043+1 numbers are from a prior Python 3.12.14 (aarch64) run.
2. **README "1043 passed, 1 xfailed" vs CHANGELOG "1030/1030"**: The CHANGELOG ends at Wave 7 (1030/1030). The README's 1044 collected/1043 pass figure includes Waves 0-7 plus any subsequent additions. Wave 7 added 13 tests + 1 xfail to the 1017 conformance suite → 1030. The README's 1043 includes additional tests beyond Wave 7 (13 more).
3. **docs/SBOM.md generated path**: says `/home/hatch/workspace/anchor-v1/.venv/bin/python` — Linux path, but repo is on Windows (C:/Users/fyou1/anchor-v1/repo). SBOM was generated on a Linux hatch machine, not the current Windows dev box.
4. **Static test count (929) vs collected (1,044)**: ~115 tests come from pytest parametrization. The parametrization matrix is not documented; a `--collect-only -v` dump from the correct Python env would confirm the exact mapping.
5. **rust/verifier/ not mentioned in CHANGELOG**: The Rust verifier exists but has no wave attribution in the changelog.

## 8. Dependency Audit (from docs/SBOM.md)

Runtime: cryptography 50.0.1, pydantic 2.13.5
Test: pytest 9.1.1
Transitive: annotated-types, cffi, iniconfig, packaging, pluggy, pycparser, pydantic_core, Pygments, typing-inspection, typing_extensions
Installed-unused: beautifulsoup4, certifi, charset-normalizer, filelock, gdown, idna, opentimestamps, pycryptodomex, PySocks, python-bitcoinlib, requests, soupsieve, tqdm, urllib3
