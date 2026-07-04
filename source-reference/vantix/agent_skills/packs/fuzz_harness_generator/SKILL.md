---
name: fuzz_harness_generator
description: Generate ready-to-run fuzz harnesses (Jazzer for JVM, libFuzzer/AFL for native, Foundry/Echidna for Solidity) targeting resource accounting, signature aggregation, ABI / RLP / proto parsers, exception-path state rollback. Operator runs them out-of-band; crash reports loop back via the deephunt journal. Phase 6 of deep_audit_orchestrator.
---
# Fuzz Harness Generator

Many of the deepest bugs in protocol code — signature aggregation edge cases, fee/reward accounting overflows, parser-state confusion, exception-path partial-state corruption — only surface under **random input**. Static reading misses them because the bug isn't in the obvious control flow; it's in the unobvious corner of a 256-bit input space that no code-reader's mental model covers.

This pack generates **ready-to-run fuzz harnesses** AND (when an operator-owned compute node is registered) **dispatches them in-loop via `compute_node_dispatcher`**. If no matching compute node is registered, the pack falls back to the original out-of-band model: harness + runbook get written and the operator runs them manually. Crash reports loop back to the `/deephunt` journal either way.

Composes with `packs/deep_audit_orchestrator/SKILL.md` (Phase 6 driver), `packs/compute_node_dispatcher/SKILL.md` (in-loop dispatch when nodes are registered), `packs/skeptic_validator/SKILL.md` (every crash needs skeptic review), `packs/triage_validation/SKILL.md`.

## When to Use

- Phase 6 of a `/deephunt` marathon.
- After a static-analysis invariant sweep produces UPHELD matches in a math/parser function — fuzz the candidate path to confirm exploitability under random input.
- After an inline source audit flags a path with deep input-space combinations the auditor can't enumerate.

## Operating Rules

- **Never fuzz against production**. Harnesses target locally-built libraries. No live nodes, no live RPC endpoints, no live mainnet state.
- **Corpus hygiene**: seed corpus must not contain secrets, private keys, or real customer data. Use only synthetic test vectors.
- **Crash classification**: not every crash is a bug. Some are infrastructure (Java OOM, classloader race). The crash-triage pass filters these.
- **Harness validity**: a harness is only useful if it isolates the in-scope function from the rest of the system. If the harness pulls in 200MB of dependencies, the fuzzer spends 99% of its time in dependency code. Trim aggressively.

## What to harness — priority list (per `/deephunt` Phase 6)

The orchestrator delegates one harness target per agent. Default priority:

1. **Signature aggregation loops** — every multisig / batch-validate-sig path. Random signature arrays + random recovered-address combinations. Catches dedup-by-bytes-not-address class.
2. **Resource accounting** — bandwidth/energy/fee math under random inputs (`increase`, `consumeBandwidth`, refund paths). Catches integer overflow + rounding-edge + windowSize precision bugs.
3. **ABI / RLP / proto parsers** — random bytes to `DataWord.parseArray`, `RLP.decode`, `Transaction.parseFrom`. Catches parser-state confusion.
4. **JSON-RPC handlers** — random JSON to public RPC entry points. Catches type confusion + over-length + null-handling.
5. **State-rollback paths** — random exceptions injected into `actuator.execute()` mid-mutation. Catches partial-state corruption.
6. **Crypto primitives** — random inputs to `ECRecover`, `Sha256`, `Ripemd160`, `Bn128Pairing`. Catches edge cases at curve boundary, identity, infinity.

## Harness template (Jazzer for JVM)

```java
// agent_skills/shared/fuzz_harnesses/jazzer/SignatureAggregationFuzzer.java
package fuzz.harnesses;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class SignatureAggregationFuzzer {

    @FuzzTest
    void fuzzValidateMultiSign(FuzzedDataProvider data) {
        // 1. Build random hash + random signature array
        byte[] hash = data.consumeBytes(32);
        if (hash.length != 32) return; // jazzer skip
        int sigCount = data.consumeInt(0, 32);
        byte[][] signatures = new byte[sigCount][];
        for (int i = 0; i < sigCount; i++) {
            signatures[i] = data.consumeBytes(65);
        }

        // 2. Build a random Permission with random keys
        // ... (operator fills in with local Permission builder)

        // 3. Call the target
        // Pair<Boolean, byte[]> result = validateMultiSignPrecompile.execute(...);

        // 4. Property assertion: if returns true, totalWeight >= threshold.
        // Property: if signatures contain duplicate recovered-address pairs,
        // total weight should NOT exceed the unique-key-weight sum.
        // ... (operator fills in)
    }
}
```

## Harness template (Foundry for Solidity)

```solidity
// agent_skills/shared/fuzz_harnesses/foundry/PrecompileInvariantTest.t.sol
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract PrecompileInvariantTest is Test {
    // Property: ValidateMultiSign should return true only if
    // there exist N distinct signers whose weights sum to threshold.
    function testValidateMultiSign_NoDuplicateSigner(
        bytes32 hash,
        uint8 sigCount,
        bytes[] memory sigs
    ) public {
        vm.assume(sigCount <= 5);
        vm.assume(sigs.length == sigCount);
        // ... call precompile 0x0a, assert invariant
    }
}
```

## Harness template (Echidna for Solidity contracts)

```yaml
# echidna.config.yaml shipped with the harness
testMode: property
testLimit: 100000
shrinkLimit: 5000
```

## Runbook (ships alongside harnesses)

```markdown
# Runbook — Fuzz harnesses for <target> from /deephunt session <session-id>

## Prerequisites
- Java 11+ for Jazzer
- `jazzer-launcher.jar` (JVM coverage-guided fuzzer)
- Foundry (if Solidity harness applies)

## Build the harness
[per-harness build steps]

## Run
```bash
java -jar jazzer-launcher.jar \
  --cp=<target-jar>:fuzz-harnesses.jar \
  --target_class=fuzz.harnesses.SignatureAggregationFuzzer
```

## Capture crashes
Crashes land in `./crashes/`. Each crash file is a serialized FuzzedDataProvider input.

## Loop back
For each crash:
1. Reproduce: rerun with `--repro=crash-<hash>`
2. Triage: minimize via `jazzer-minimize`
3. Classify: append to `<target>/deephunt-journal.jsonl` with event `fuzz_crash_classified`
4. The next `/deephunt --resume` will pick up the crash for Phase 8 synthesis
```

## Harness lifecycle

Harnesses live under `docs/local/bugbounty/<target>/fuzz-harnesses/` (gitignored, operator-local). The pack does NOT commit harnesses to the public repo — they may reference proprietary local builds.

## Theories This Pack Owns

- `fuzz.signature_aggregation_invariants`
- `fuzz.resource_accounting_overflow`
- `fuzz.parser_state_confusion`
- `fuzz.exception_path_state_rollback`
- `fuzz.crypto_edge_inputs`

## Tooling

- **Jazzer** — JVM coverage-guided fuzzer (libFuzzer/Atheris descendant). Primary tool for java-tron family targets.
- **Kelinci** — Jazzer alternative; older but supports plain JUnit tests directly.
- **Foundry** — Solidity property-based testing via forge fuzz.
- **Echidna** — Trail of Bits' Solidity invariant fuzzer.
- **libFuzzer / AFL++** — native code; relevant when audit target has C/C++ components.
- **jqwik** — JUnit-native property-based tests; lower-power than Jazzer but easier to integrate.

## See Also

- `packs/deep_audit_orchestrator/SKILL.md` — Phase 6 driver
- `packs/skeptic_validator/SKILL.md` — crash triage gate
- `packs/triage_validation/SKILL.md` — pre-submission gates for confirmed crashes
- `agent_skills/shared/fuzz_harnesses/` — shipped harness templates (operator copies + customizes)

## Exclusions

No fuzzing against live infrastructure. No corpus that contains secrets / keys / real customer data. No harness that auto-submits crashes — operator always triages. No harness without explicit time-box per run (default 1h per harness; raise only with operator consent).
