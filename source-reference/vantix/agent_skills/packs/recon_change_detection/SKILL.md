---
name: recon_change_detection
description: Detect new changed and disappeared assets over time and launch targeted follow-up instead of full rescans.
---
# Recon Change Detection

Detect new changed and disappeared assets over time and launch targeted follow-up instead of full rescans.

**Passive only.** This pack issues no active probes; it composes with the continuous recon ingestion pipeline.

Backed by the recon data platform component `recon.ingest.detect_change_followups + recon_change_log`. Observations land in `recon_assets`/`recon_observations`, fuse into `recon_asset_fusion` (frozen `ReconAssetService.serialize()` contract), and emit `recon_change_log` events. Composes with `shared/scope_guard.md`, `recon_advisor`, and the findings-funnel metrics.

## Method

- Diff fusion snapshot into new changed gone events
- Each change enqueues a TARGETED followup, not a full rescan
- Preserve historical observations
- Prioritize new JS hashes new endpoints new takeover candidates

## Evidence

- recon_observations rows (source, confidence, observed_at, content_hash)
- recon_asset_fusion entry (authoritative source by trust tier)
- recon_change_log events for new/changed assets
- recon_source_metric for source-efficiency attribution

## Forbidden

- Out-of-scope targets; destructive or DoS behavior
- Any active probing (this pack is passive)
