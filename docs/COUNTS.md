# ProxyForge README Badge Counts

These counts were generated from the uploaded ProxyForge README and are intended for the GitHub README badge/header package.

| Metric | Value | Source / method |
| --- | ---: | --- |
| Version | `0.1.0-alpha.1` | User-provided release version |
| Workbench / UI surfaces | 20 | Counted directly from `src/types.ts` ToolId union |
| Current feature lanes | 35 | Top-level bullets under `## Current Features` |
| AI providers | 3 | Codex, Claude, OpenAI-compatible local endpoints |
| Agent control flows | 9 | Named `proxyforge-agent` control lanes in README |
| Active scanner check families named | 7 | Security header, CORS, cache-key, OPTIONS, auth-state comparison, JWT, GraphQL |
| Intruder modes | 4 | Sniper, Battering Ram, Pitchfork, Cluster Bomb |
| Report / CI export formats | 6 | Markdown, HTML, JSON, PDF, SARIF, JUnit |
| Verification commands | 21 | Commands under `## Verification` |

## Important count note

The private repository tree was not fully mounted into this file-generation environment, so exact live file counts for `agent_skills/`, `playbooks/`, `.anvil`, extension manifests, and template registries should be refreshed by running:

```bash
python scripts/count_proxyforge_assets.py
```

from the real ProxyForge repository root.

The current README badge package avoids unverified exact file-count claims for skills and playbooks. It uses README-derived product counts and includes the counter script for a final pre-release pass.
