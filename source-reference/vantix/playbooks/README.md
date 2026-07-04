# SecHive/SecHive Playbook Suite

This directory is the canonical runtime source for agent-guided authorized testing workflows.

## Layout

- `schema.json` defines the playbook manifest contract.
- `registry.yaml` lists every runtime playbook id. Each id resolves to `templates/<id>.playbook.yaml`.
- `references.yaml` tracks external reference metadata used by playbooks.
- `templates/*.playbook.yaml` define agent rosters, required modes, target requirements, steps, evidence gates, and proof-continuation behavior.

## Validation

Run:

```bash
scripts/sechive playbooks validate
```

Validation loads the registry, resolves every template, validates each manifest against `schema.json`, checks duplicate ids, checks scope gates, checks agent rosters, and verifies each step has an evidence gate.

## Runtime Model

Agents route through the suite instead of ad hoc testing:

1. Start with `playbook.scope_roe_intake_and_policy_matrix`.
2. Route through `playbook.agent_orchestrated_bug_bounty_run` for master orchestration when the mode is bug bounty, pentest, own-source, or private source audit.
3. Branch into the selected domain playbook and supporting proof/reporting playbooks.
4. Record evidence for each step contract.
5. Promote only when scope reference, replay or closure artifact, false-positive checks, redaction decision, severity rationale, and affected asset reference are present.

Blocked active actions must create a `blocked_record` or `closure_note`.
