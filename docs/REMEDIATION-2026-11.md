# Remediation notes — 2026-11

This document records the audit and remediation applied to IAMosaic in November 2026.
It is additive: the original README, SECURITY.md, CONTRIBUTING.md and example files
remain in the repository and were updated only where they were inaccurate or
inconsistent.

## Method

Every source file was read line by line and each suspected defect was confirmed with
an executable regression test. The new tests were first run against the previously
published revision to confirm the defect was real (red phase: 26 failing tests), and
only then were the fixes applied (green phase: 39 passing tests).

## Defects fixed

| Severity | Defect | Fix |
| --- | --- | --- |
| Medium | `statement_index` reported the position in the *filtered* statement list, so a finding could point at the wrong statement whenever an earlier entry was malformed | `_statement_entries` keeps the original index; findings and edges now report the position in the exported file |
| Medium | A wildcard (public) principal was never detected, so a policy granting `Principal: "*"` produced no finding at all | New rule `CG002` |
| Medium | Grants by exclusion (`NotAction` / `NotResource`) were invisible: such a statement allows everything except the excluded scope | New rule `CG003` |
| Medium | The command line raised a raw Python traceback for a missing file, invalid JSON, a byte-order mark, or a JSON root that was not an object | `cli.main` reports one-line messages and uses exit codes `0` / `1` / `2` |
| Medium | A report could not be written to a file, and a CI pipeline had no way to fail on findings | `--output` and `--fail-on-findings` options, with an explicit error when the report cannot be written |
| Low | `policy_edges` exposed `Principal` as a raw string, list or map, so a graph consumer had to handle three shapes | Edges keep the raw value for compatibility and add a normalized `principals` list |
| Low | The package exposed no public API, and the report carried no format marker | `iamosaic.__all__`, `iamosaic.__version__`, and `schema_version` in the report |

## Documentation and spelling corrections

- `LICENSE` shipped a truncated MIT text: the warranty and liability clauses were
  missing. The complete, canonical MIT text is now in place.
- Spelling was inconsistent across the same file set (`behaviour` in `CONTRIBUTING.md`
  against `authorization` in `SECURITY.md` and `normalized` in `README.md`). The
  prose now uses one convention throughout.
- The roadmap listed "Documentation and contribution guide" as unfinished while
  `CONTRIBUTING.md`, `SECURITY.md` and this file exist. The checklist now reflects
  reality, and "Stable public API and versioned report schema" is marked complete.
- The README documented no command-line usage and no rule catalogue, although the
  project ships a console script and three rules. Both are now documented.
- A dictionary spelling scan (`codespell`) now reports no misspelling in this
  repository.

## Continuous integration hardening

The workflow previously ran the test suite only. It now also runs a credential scan
on every push and pull request.

| Job | What it does |
| --- | --- |
| `secret-scan` | Runs `scripts/scan-secrets.py`, which fails the build when the repository contains a high-confidence credential pattern (cloud keys, tokens, private key blocks, JWTs) or a file that must never be committed (`.env`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, credential files) |

The scanner is the one already used by the Gravion Toolkit split repositories, so
every toolkit project now shares one definition of what counts as a secret. A
"soft" match, such as a dummy `api_key` inside a test fixture, is reported for
review but does not fail the build.

### Executable bit on the secret scanner

The first run of the new pipeline failed on the Ubuntu runner with
`EXE001 Shebang is present but file is not executable`. Git on Windows has no
execute bit, so `scripts/scan-secrets.py` was published with mode `100644`
although it carries a `#!/usr/bin/env python3` shebang, and the checkout on
the runner produced a non-executable file. The scanner is now committed with
mode `100755`, which is what the shebang promises, and it can also be run
directly as `./scripts/scan-secrets.py .`.

## Verification

| Check | Before | After |
| --- | --- | --- |
| Secret scan in CI | absent | present |
| Secret scanner file mode | `100644` (not executable) | `100755` (executable) |
| Tests | 9 | 39 |
| `ruff check .` | clean | clean |
| New rules | 1 (`CG001`) | 3 (`CG001`, `CG002`, `CG003`) |

## Residual limitations

- Detection is intentionally conservative: it reports wildcards, public principals and
  grants by exclusion. It does not evaluate `Condition` blocks, so a wildcard grant
  constrained by a condition is still reported for analyst review.
- The analyzer does not validate the policy against the AWS IAM grammar. A statement
  with an unknown `Effect` value is treated as `Allow`, matching the previous behavior.
- Findings are review hints. IAMosaic cannot confirm whether a granted permission is
  actually required, and it never contacts a cloud API.
