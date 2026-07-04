# Project SBOM Guide

ProxyForge generates a Software Bill of Materials (SBOM) for the active project artifact — every captured exchange, evidence record, extension, third-party listener, signed audit export, and template run.

This is distinct from the application binary SBOM produced at release time.

## Formats

- **CycloneDX 1.5 JSON** — machine-readable, validator-compatible.
- **SPDX 2.3 tag-value + JSON** — compliance-friendly, toolchain-portable.

## Generating an SBOM

```bash
proxyforge-agent --json <<EOF
{"op":"report.export","projectId":"<id>","format":"sbom-cyclonedx"}
EOF
```

Or from the GUI: **Reports → Export SBOM**.

## Contents

Each SBOM includes:

- Project metadata (ID, name, creation date, scope)
- Captured exchange references (count, date range, host set)
- Scanner evidence matrices referenced in issues
- Exploit template runs linked to issues
- Extensions loaded during the project
- OAST listeners configured
- AI provider calls (redacted content, preserved metadata)
- Signed evidence bundle digests
- Audit log reference (not content — the audit log itself is a separate export)

## Validation

The generated SBOM validates against the official CycloneDX and SPDX validators:

```bash
# CycloneDX
cyclonedx-cli validate --input-file project.sbom.cdx.json --input-format json

# SPDX
spdx-tools verify project.sbom.spdx.json
```

## Tests

- `tests/sbom-cyclonedx-roundtrip.mjs`
- `tests/sbom-spdx-roundtrip.mjs`
- `tests/sbom-includes-evidence-references.mjs`
