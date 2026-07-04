# Compute Node Map (canonical)

Single source for operator-owned compute nodes. Skills/agents resolve a node
by **canonical name** or **capability** — never hardcode a host/IP. Seeded by
`scripts/seed-compute-nodes.py`; queried via `ComputeNodeService.match_capability`
(API `GET/POST /api/v1/compute-nodes`, CLI `vantix node {list,pick}`).

| Name | Host | Runner | Capabilities | Use for |
|---|---|---|---|---|
| `aitts` | 192.168.1.94 | ssh | cpu, kvm | KVM/syzkaller-style kernel exec, capped-CPU triage, libfuzzer fallback; hosts the Android device |
| `aitts-android-pixel` | 192.168.1.94 | adb-host | android | Frida/intent/deeplink/WebView/APK dynamic on the USB device |
| `lenovohouse` | lenovohouse.local | ssh | win11, win11-gpu, gpu | Chrome VRP repro, Electron dynamic, GPU hashcat/john cracking |
| `win11prorunner` | 192.168.1.100 | ssh | win11, browser, authenticated-browser | Authenticated-browser intercepting-proxy capture, Win11 non-GPU browser validation |
| `staging-backend` | 192.168.1.176 | sechive-runner :8844 | cpu, gpu, kvm | Heavy native build/decompile/fuzz, syzkaller kernel runs, GPU crack, designated `native_research` / Chromium VRP executor |

Authorization: all five are operator-owned lab nodes under the standing lab
authorization (`agent_skills/shared/authorization_anchor.md`). Routine in-scope
work on them does not need re-prompting.

## Resolve by capability (preferred)

- GPU crack → `staging-backend` (or `lenovohouse`); dispatch via
  `scripts/crack-dispatch.sh` / capability `gpu`.
- Authenticated browser / MITM → `win11prorunner`; capability
  `authenticated-browser`.
- Kernel / KVM fuzzing → `aitts` (low-CPU KVM) with `staging-backend` for
  build/prep; capability `kvm`.
- Heavy parser/native fuzzing → `staging-backend`; capability `cpu`.
- Android dynamic → `aitts-android-pixel`; capability `android`.

`match_capability(capability, job_kind=..., preferred_node_id=...)` does strict
capability + allowed-job-kind matching (no wrong-cap fallback). Empty
`allowed_job_kinds` = accept-all (back-compat).

## Research lane → preferred node

`secops.research.authorized_mode.preferred_node_for_lane(lane)`:

- `oss_parser_fuzzing`, `patch_diff_variant` → `staging-backend`
- `syzkaller_kernel`, `container_boundary`, `hypervisor_device_model` → `aitts`
- `ai_app_security` → `win11prorunner`

Long-running research jobs on `aitts`/`staging-backend` must stay ≤85% host
CPU and default to one VM/proc unless the operator approves more load.

Load order on resume: `claude_bbp.md` lab block → this map → memory anchors.
