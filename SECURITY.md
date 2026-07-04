# Security Policy

ProxyForge is a security testing tool. Use it only on systems you own or are explicitly authorized to assess.

## Alpha Scope

The open-source alpha is intended for local, authorized assessment workflows. It includes active scanning, replay, Intruder-style payload execution, OAST/callback handling, exploit validation helpers, and AI/agent control surfaces, so operators are responsible for scope, rate limits, approvals, and stop conditions.

## Reporting Vulnerabilities

Please report vulnerabilities in ProxyForge itself through a private GitHub Security Advisory for this repository: https://github.com/the-vibe-dev/proxyforge-public/security/advisories/new

Use public issues only for non-sensitive bugs. Do not include live third-party secrets, raw customer traffic, reusable exploit tokens, exploitable proof-of-concept details, or unrelated private data in public reports.

## Secret Handling

Operational workspaces intentionally preserve full-fidelity tokens, cookies, keys, callbacks, raw requests, raw responses, replay material, scanner probes, and exploit validation data so operators and agents can reproduce findings. Redaction is expected only in report/export artifacts prepared for submission.

## Responsible Use

Do not use ProxyForge to attack systems without authorization. The maintainers may decline support for unlawful, unsafe, or out-of-scope activity.
