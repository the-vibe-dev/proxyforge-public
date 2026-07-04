---
name: passive_port_discovery
description: Passive-then-active port discovery verifying only passively-claimed ports and only under scope plus active-enabled.
---
# Passive Port Discovery

Passive-then-active port discovery verifying only passively-claimed ports and only under scope plus active-enabled.

**Active, scope-gated.** Requires `settings.recon_active_enabled` AND a `ScopeDecisionService` pass; fail-closed when no scope evaluator is supplied.

Backed by the recon data platform component `recon.ports`. Observations land in `recon_assets`/`recon_observations`, fuse into `recon_asset_fusion` (frozen `ReconAssetService.serialize()` contract), and emit `recon_change_log` events. Composes with `shared/scope_guard.md`, `recon_advisor`, and the findings-funnel metrics.

## Method

- Record passive port claims with source and confidence
- Active verify only passively-claimed ports
- Broader active scanning is never the default
- Old ports in passive datasets are useful signal

## Evidence

- recon_observations rows (source, confidence, observed_at, content_hash)
- recon_asset_fusion entry (authoritative source by trust tier)
- recon_change_log events for new/changed assets
- recon_source_metric for source-efficiency attribution

## Forbidden

- Out-of-scope targets; destructive or DoS behavior
- Active probing without scope + recon_active_enabled
