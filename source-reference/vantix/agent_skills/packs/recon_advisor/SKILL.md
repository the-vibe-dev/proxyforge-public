---
name: recon_advisor
description: Recon Advisor: network and service enumeration methodology.
---
# Recon Advisor

## Use When
network and service enumeration methodology. Apply this pack for roles: recon, researcher.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Prefer quiet discovery, save raw output, and identify service/version facts.

## Same-Host Side-Service Loopback
- When source/config/runtime evidence references localhost, 127.0.0.1, container-local services, Unix sockets, high ports, or mapped side services, treat it as a same-host service mapping task, not a generic network scan.
- Correlate the hinted protocol, banner, app output, container/deploy clues, existing ports, and current target host before asking for more enumeration.
- If the authorized target is host-scoped and the current port inventory is shallow, perform or request one scoped same-host high-port inventory, then stop expanding.
- For each plausible mapped candidate, save a read-only protocol/banner or harmless request/response proof. Record negative mapped-port evidence before handing the lane back to Exploit Chainer.
- Never broaden to adjacent hosts, brute force, destructive probes, or service disruption from a side-service hint.

## Tooling
- Service & version inventory: `nmap -sS -sU --top-ports <N> -sV -O --reason -oA <out> <scope>`.
- SMB / RPC: `enum4linux-ng -A <host>`; `smbclient -L //<host>/ -N`; `rpcclient -U "" -N <host>` (anonymous probes only).
- NFS: `showmount -e <host>`; `rpcinfo -p <host>`.
- SNMP: `onesixtyone -c communities.txt <hosts>`; `snmpwalk -v2c -c <community> <host>`.
- IPMI: `nmap -sU -p 623 --script ipmi-cipher-zero,ipmi-version <host>`.
- NTP amplifiers: `ntpq -c rv <host>`; `nmap -sU -p 123 --script=ntp-monlist <host>` (read-only — never run amplification senders).
- LLMNR/NBT-NS/mDNS: `responder -I <iface> -A` (listen/analyze only — disable poisoning unless lab).

## Theories This Pack Owns
- `net.snmp_default_community`
- `net.smb_null_session_and_signing`
- `net.nfs_export_unrestricted`
- `net.ipmi_cipher0_or_passthrough`
- `net.llmnr_nbns_mdns_poison`
- `net.ntp_monlist_amplification`

## Playbook
- Primary: `playbook.network_protocol_review`.
- Supporting: hands off relayable SMB / NTLM coercion paths to `ad_attacker` via `playbook.ad_attack_path_orchestration`.

## Evidence Requirements
- Scope record for hosts and segments; raw scanner outputs (nmap XML/grepable); per-protocol probe transcripts; quoted budget for any UDP probe; for poisoning theories, packet capture of broadcast traffic with no spoofed responses outside lab.

## Memory-Aware Attack Surface Ranking

Raw recon output is a list of hosts, ports, and routes — not an attack plan. Ranking turns a 500-line subdomain list into a 10-line "hunt these first" order.

### Ranking signals (additive)

| Signal | Weight | Why |
|---|---|---|
| Authenticated surface discovered | +3 | Most paid bugs sit behind login |
| Admin / internal / debug route returns 401/403 | +3 | High value behind the door (chain with `access_control_bypass`) |
| Verified secret in JS bundle | +3 | Direct path to Medium/High via `secrets_scanner` |
| Dangling CNAME / takeover candidate | +3 | Standalone $500–$5k, chain into Critical |
| OAuth / SSO / SAML endpoint | +2 | Highest auth-bug density |
| Payment / billing / refund / wallet endpoint | +2 | Highest dev-shortcut density |
| New feature (<30 days, fresh commit in public repo) | +2 | Unreviewed surface |
| API with sequential IDs | +2 | IDOR candidates |
| File upload / import / export | +2 | Upload / parser / SSRF chain starters |
| GraphQL endpoint | +2 | Introspection + auth bypass density |
| Disclosed program reports mention this endpoint | +1 | Triagers know the route — high signal-to-noise |
| Sibling of a previously-paid endpoint | +1 | A→B signal (see `exploit_chainer`) |
| Generic static landing / brochure page | −2 | Almost never the target |

### Memory integration

When a hunt has prior session memory (per `shared/memory_protocol.md`), each surface is annotated with what's been tested before:

- `tested_class`: which vuln classes have been attempted (XSS, IDOR, SSRF, …).
- `tested_session_id_hash`: under which identity (anonymous / low-priv / high-priv).
- `negative_evidence`: families that returned negative evidence at depth.
- `last_revisit`: timestamp.

The ranker decays a surface's priority based on `tested_class` saturation. A subdomain where every class returned negative evidence drops to the bottom; a subdomain where only XSS was tested but contains a fresh payment endpoint rises.

### Output

The ranked list is written to the run state as:

```
rank=1 host=admin.target.com why=admin-route-401+oauth-endpoint score=8 tested=[xss:neg] next=access_control_bypass
rank=2 host=api.target.com  why=graphql+api+jwt-endpoint     score=7 tested=[]         next=web_hunter
...
```

The next executor pulls from `rank=1` first. When stagnation triggers (per `shared/adaptive_attack_theory.md`), the ranker re-runs with updated tested annotations.

This is a planning aid, not a substitute for the operator's intuition. Override freely; the ranker exists to keep a tired or stuck operator from wandering randomly.

## Corpus Recon Methodology (resources vs findings; complexity-first)

Backing reference: `docs/agent-learning/bug-bounty-methodology-playbook.md`
§3–§4 (learning sources `corpus.bb.defcon_automation`,
`corpus.bb.recon_to_manual`, `corpus.bb.ai_assisted`); retrieve via
`learn_engine.py --root . lookup tag:complexity-target-selection --format prompt`.

Recon produces **resources**, not findings — the pipeline must end in
prioritized manual tests, not undirected output. Passive-first ordering
(scope → passive DNS → CT logs → cert SAN/CN → reverse DNS → code-search →
light spider → vhost → only-then targeted fuzzing); brute force is a last
resort. Score assets for **complexity signals** (multiple auth methods,
roles, tenants, clients-per-backend, websockets, import/export,
shared SSO/CORS, staging/legacy) and surface the highest-signal,
least-tested, in-scope assets first (theory
`recon.complexity_target_selection`, the existing recon platform
`recon_assets`, scorer rules in `agent_ops/config/bug_hiding_places.yaml`).
Optional LLM-assisted program/target ranking is delegated to
`llm_assisted_hunting` and every recommendation is re-verified against live
platform scope. Bug-class-first: pick the class, then find structurally
likely targets.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions. No active LLMNR/NBT-NS/mDNS poisoning or NTLM relaying outside an authorized lab. No UDP amplification packet generation (responses observed read-only via small directed probes).
