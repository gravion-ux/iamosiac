# IAMosaic

> Offline cloud-IAM policy review and permission-relationship visualization data.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Parse normalized IAM policy JSON.
- Flag wildcard actions and resources for review.
- Flag wildcard (public) principals and grants by exclusion.
- Emit permission-relationship edges for visualization.
- Provide least-privilege remediation hints.
- Emit a machine-readable JSON report for CI pipelines.

## Rules

| Rule | Detects | Severity |
| --- | --- | --- |
| `CG001` | Wildcard action (`*`) or wildcard resource (`*`) in an `Allow` statement | `high` when both are wildcards, otherwise `medium` |
| `CG002` | Wildcard principal (`*`) in an `Allow` statement | `high` together with a wildcard action or resource, otherwise `medium` |
| `CG003` | `Allow` statement that grants by exclusion (`NotAction` / `NotResource`) | `high` |

`Deny` statements are never reported: they remove permissions instead of granting them.
Every finding carries the `statement_index` of the statement in the exported file, so a
finding can be traced back to the exact statement the analyst sees.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Command line

```bash
iamosaic path/to/policy.json
iamosaic path/to/policy.json --output report.json
iamosaic path/to/policy.json --fail-on-findings
```

| Exit code | Meaning |
| --- | --- |
| `0` | The policy was analyzed and no error occurred |
| `1` | The policy could not be parsed, the report could not be written, or findings were reported with `--fail-on-findings` |
| `2` | The policy file is missing or unreadable |

The report is JSON and carries a `schema_version` field, so downstream tooling can
detect format changes.

## Python API

```python
from iamosaic import analyze_policy, policy_edges, policy_version

findings = analyze_policy(policy)
edges = policy_edges(policy)
version = policy_version(policy)
```

## Safety and scope
Offline policy analysis only. No cloud credentials, account access, API calls, or resource modification are performed.

## Roadmap
- [x] Stable public API and versioned report schema
- [ ] More unit, integration and adversarial tests
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [x] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE).
