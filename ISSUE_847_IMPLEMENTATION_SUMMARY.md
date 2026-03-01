# Issue #847: Adaptive Risk Engine v2 (Policy + ML Ensemble)

## Overview

Implemented an adaptive risk engine that replaces static risk thresholds with:

- Versioned weighted policy engine
- Deterministic calibrated ML ensemble scorer
- Per-tenant policy support
- Explainable risk factors for each decision
- Drift monitoring for feature distribution shifts
- Reproducible decision logs with rollback-safe policy lifecycle

## Core Components Added

### New Models

- `models/RiskPolicyVersion.js`
  - Stores policy versions per tenant
  - Supports active/archived lifecycle
  - Enables version history and rollback-safe publishing

- `models/RiskDecisionLog.js`
  - Stores reproducible risk decisions with:
    - policy version
    - model version
    - policy checksum
    - input hash
    - reproducibility key
    - explainability factors

- `models/RiskDriftMetric.js`
  - Tracks model drift per tenant/model version
  - Stores baseline/current feature stats and drift status

### New Config

- `config/adaptiveRiskPolicy.v2.json`
  - Default policy for global tenant bootstrap
  - Includes rule weights, model coefficients, calibration, thresholds, and drift settings

### New Services

- `services/adaptiveRiskEngineV2Service.js`
  - Policy bootstrap/retrieval
  - Rule scoring + ML ensemble scoring
  - Score calibration
  - Final decision routing (allowed/monitor/challenged/blocked)
  - Explainability generation
  - Drift metric updates
  - Policy publish and rollback

### Updated Service

- `services/suspiciousLoginDetectionService.js`
  - Replaced static additive thresholds with adaptive risk engine v2 evaluation
  - Added policy/model metadata to security event details
  - Added explainability-linked risk flags

### New Routes

- `routes/adaptiveRiskEngine.js`
  - `GET /api/risk-engine/policy`
  - `PUT /api/risk-engine/policy`
  - `POST /api/risk-engine/policy/rollback`
  - `GET /api/risk-engine/history`
  - `GET /api/risk-engine/drift`
  - `GET /api/risk-engine/decisions`

### Server Integration

- `server.js`
  - Registered risk engine API route:
    - `app.use('/api/risk-engine', adaptiveRiskEngineRoutes)`

## Acceptance Criteria Mapping

### Replace static thresholds

Done via weighted policy + calibrated ensemble in `adaptiveRiskEngineV2Service`.

### Per-tenant rules

Done via `tenantId`-scoped policy versions with global fallback.

### Explainable risk factors

Done via persisted factor contributions and top factors in decision logs and response payload.

### Drift monitoring

Done via EWMA-based feature drift tracking with stable/watch/alert statuses.

### Reproducible, versioned, rollback-safe decisions

Done through:

- policy versioning and checksums
- input hashes
- reproducibility keys
- rollback endpoint and publish lifecycle
