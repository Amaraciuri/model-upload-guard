# Contributing

1. Fork the repository and create a focused branch.
2. Add or update tests for every behavior change.
3. Run `python -m unittest discover -s tests -v`.
4. Do not weaken default exclusions, protected paths, confirmation gates, or sandbox flags without a documented threat-model discussion.
5. Never include real credentials in fixtures or issues.

Security-sensitive changes should be small, auditable, and accompanied by regression tests.
