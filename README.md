# IAMosaic

> Offline cloud-IAM policy review and permission-relationship visualization data.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Parse normalized IAM policy JSON.
- Flag wildcard actions/resources for review.
- Emit relationship edges.
- Provide least-privilege remediation hints.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Safety and scope
Offline policy analysis only. No cloud credentials, account access, API calls, or resource modification are performed.

## Roadmap
- [ ] Stable public API and versioned schemas
- [ ] More unit, integration and adversarial tests
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [ ] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE).
