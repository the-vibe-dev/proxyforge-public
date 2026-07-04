---
name: fuzzing_harness
description: Fuzzing Harness — locked active skill for building, running, and managing local libFuzzer/AFL++/honggfuzz/fuzzilli/atheris/cargo-fuzz/domato/radamsa/zzuf campaigns against authorized native or managed targets. Owns corpus minimization, coverage merge, sanitizer builds, and resource-capped runners.
---
# Fuzzing Harness

## Use When
The engagement covers an authorized native/managed target (Chromium component, third-party native dep, internal parser, language-runtime API) where:
- A target function or interface is identified and a harness can be authored against a local debug+sanitizer build, AND
- The operator has explicitly enabled this pack for the run (it is **locked-by-default**).

Do not use this pack to fuzz remote endpoints, third-party services you do not own, or production targets. Fuzzing is a development activity against locally built binaries.

## Operating Rules
- Pack is **gated / locked**. Each run requires explicit per-run enablement. Out-of-scope or absent authorization → refuse, record `blocked_record`.
- All runs execute under a **resource cap** (cgroup or `prlimit`): CPU seconds, RSS, disk. The runner aborts cleanly on cap, records `fuzz_run_summary`, never lets a run consume the host.
- Sanitizer build is mandatory: ASAN, UBSAN, MSAN, or TSAN selected per theory family; libFuzzer/AFL++/honggfuzz harness emits to a sanitizer-instrumented binary.
- Crashes are routed through `crash_triage`: `parse_sanitizer_log` + `bucket_id` produce a stable bucket before any hypothesis is filed. New buckets seed a `crash_to_root_cause` step; known buckets dedup against the knowledge base.
- Corpus management uses `afl-cmin` / `libFuzzer -merge` to keep the working set minimal. Every campaign records seed lineage (initial set + minimization tool + size + entropy floor).
- Coverage merge runs `llvm-profdata` + `llvm-cov` to surface unexplored blocks. The harness writes a `coverage_report` artifact and (when stalled) a "dead zone" hypothesis explaining why coverage halted.
- Defensive only — never weaponize a finding, never construct an exploit chain, never export an attack payload outside the local sanitizer build.

## Tooling
- **Native fuzzers (advisory choice, fallback chain):** `afl++` (AFL_USE_ASAN, persistent mode), `honggfuzz` (sanitizer + branch coverage), `libFuzzer` (clang `-fsanitize=fuzzer,address`).
- **Language-specific:** `atheris` (Python), `cargo-fuzz` (Rust libFuzzer wrapper).
- **Grammar / DOM-aware:** `domato` (DOM grammar fuzzer), `fuzzilli` (V8 IR-level fuzzer).
- **Mutators:** `radamsa`, `zzuf` (file-level mutation for protocols/parsers without harness binding).
- **Coverage:** `llvm-profdata`, `llvm-cov` (gcov-style file/line/branch report).
- **Symbolize:** `llvm-symbolizer` (primary). Crashes carry symbolized stacks before bucketing.

## Role Focus
- `developer`: writes harness source, registers target_function, builds with sanitizer, tunes seed corpus.
- `executor`: launches the campaign under cgroup/prlimit caps, watches for healthy stop conditions, ships crashes into `crash_triage`.
- `analyst`: reviews `coverage_report`, identifies dead zones, and seeds the next harness iteration with grammar/seed adjustments.

## Stop Conditions
- New unique buckets/hour drops below threshold for N consecutive intervals → archive corpus, mark "stable, low-yield".
- Coverage delta has been zero across the configured window → emit dead-zone hypothesis, do not extend run blindly.
- Resource cap hit → flush corpus + summary, do not retry without operator review.
- Any finding triggers a `crash_to_root_cause` branch and pauses the campaign for triage.

## Forbidden
- Fuzzing targets you do not own or are not explicitly authorized to fuzz.
- Bypassing the resource cap or running without sanitizer build.
- Weaponizing sanitizer findings, constructing exploit chains, exfiltrating crash inputs to third-party services.
- Persistence, destructive operations, denial of service, out-of-scope work.
