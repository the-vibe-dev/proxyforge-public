---
name: crypto_attacker
description: Crypto protocol and primitive attacker — padding oracle, ECB recovery, weak RNG, length-extension, IV reuse, hash-collision misuse.
---
# Crypto Attacker

## Use When
The engagement scope includes tokens, cookies, MACs, encrypted blobs, signed identifiers, or export formats whose construction is in scope for cryptanalytic review. Apply this pack when current evidence shows ciphertext that an attacker can submit, an oracle for verification (error vs success, timing), or visible plaintext-ciphertext pairs.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Read-first: classify the value (encoding, hash-like, signed token, encrypted token, sequential, random, app-specific) and identify any oracle channel before any cryptanalytic work.
- Never guess secret keys. Never run brute-force against production rate limits. Padding-oracle and hash-cracking probes use minimal request volume; quote rate budget in advance.
- Lab demonstrations are preferred for full plaintext recovery or forgery proofs; production proofs cap at a single bytewise oracle confirmation plus a handoff for remediation.

## Tooling
- Padding oracle: `padbuster <url> <ciphertext> <blocksize> -cookies <session> -error <pattern>`.
- Hash identification: `hash-identifier`; `hashcat --identify <hash>`.
- Hash cracking (lab only): **dispatch to the GPU crack node — do not run a
  bare bounded in-sandbox crack.** The in-sandbox box has no GPU; a short
  `john --max-run-time=N` will fail on anything past the smallest wordlist and
  is a false negative. Instead:
  - `scripts/crack-dispatch.sh --node staging-backend --hash-file <file> --hash-mode <m>`
    runs a staged GPU pipeline (straight large wordlist → wordlist×rule chain →
    bounded mask escalation) on the operator's GPU node, async. The GPU node
    is resolved by capability — see `agent_skills/shared/compute_nodes.md`.
  - Poll `scripts/crack-status.sh --job-id <id>`; collect with
    `scripts/crack-fetch-results.sh --job-id <id>` (`cracked.txt`/`potfile.txt`).
  - First identify the mode: `hashcat --identify <hash>` / `hash-identifier`.
  - Treat "not cracked after the full pipeline" as evidence the password is
    out of wordlist+rule+bounded-mask reach — record it as negative evidence,
    do not silently downgrade the finding or assume the value.
- Custom: short Python scripts using `cryptography`/`pycryptodome` for ECB block-arithmetic, MT19937 cloning, length-extension (`hashpumpy`), and IV-reuse XOR analysis.

## Theories This Pack Owns
- `crypto.cbc_padding_oracle`
- `crypto.ecb_plaintext_recovery`
- `crypto.weak_rng_predictable_token`
- `crypto.length_extension_md_mac`
- `crypto.stream_or_ctr_iv_reuse`
- `crypto.hash_collision_misuse`

## Playbook
- Primary: `playbook.crypto_token_review`.

## Evidence Requirements
- Token value (sanitized), construction inferred, oracle channel evidence, request budget consumed, plaintext or forgery sample, and a paired negative control where applicable.

## Exclusions
No destructive actions, no DoS, no persistence, no out-of-scope tokens or accounts, no online brute force of secret keys, no large-scale token harvesting.
