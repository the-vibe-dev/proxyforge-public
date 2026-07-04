---
name: passive_first_recon
description: Passive-before-brute-force surface collection with per-source cost/latency/unique-yield metadata in the recon data platform.
---
# Passive-First Recon

Passive-before-brute-force surface collection with per-source cost/latency/unique-yield metadata in the recon data platform.

**Passive only.** This pack issues no active probes; it composes with the continuous recon ingestion pipeline.

Backed by the recon data platform component `ReconIngestService (passive due-ordering)`. Observations land in `recon_assets`/`recon_observations`, fuse into `recon_asset_fusion` (frozen `ReconAssetService.serialize()` contract), and emit `recon_change_log` events. Composes with `shared/scope_guard.md`, `recon_advisor`, and the findings-funnel metrics.

## Method

- Seed apex targets from in-scope ReconAsset rows
- Run passive sources first; brute force is a separate opt-in phase
- Persist cursor per source; dedupe into recon_assets/observations
- Never active-probe in this pack

## Evidence

- recon_observations rows (source, confidence, observed_at, content_hash)
- recon_asset_fusion entry (authoritative source by trust tier)
- recon_change_log events for new/changed assets
- recon_source_metric for source-efficiency attribution

## Forbidden

- Out-of-scope targets; destructive or DoS behavior
- Any active probing (this pack is passive)
