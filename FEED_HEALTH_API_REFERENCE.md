# Feed Health & Resilience API - Quick Reference

## Base URL
```
http://localhost:3000/api/feed-health
```

## Provider Management

### Get All Providers
```bash
GET /providers
```
**Response:**
```json
{
  "success": true,
  "count": 5,
  "providers": [
    {
      "providerId": "HIBP",
      "type": "credential_breach",
      "healthScore": 92,
      "status": "HEALTHY",
      "metrics": {
        "latency": { "avg": 150, "p95": 200, "p99": 300 },
        "availability": { "uptime": 99.5 },
        "errors": { "rate": 0.5 },
        "accuracy": 98.5,
        "freshness": 3600
      }
    }
  ]
}
```

### Get Provider Details
```bash
GET /providers/{providerId}
```

### Record Provider Metrics
```bash
POST /providers/{providerId}/record-request
Content-Type: application/json

{
  "latency": 150,
  "success": true,
  "timeout": false
}
```

### Get Provider Rankings
```bash
GET /providers/rank/by-health
```
**Response:**
```json
{
  "success": true,
  "ranking": [
    { "rank": 1, "providerId": "HIBP", "healthScore": 95, "status": "HEALTHY" },
    { "rank": 2, "providerId": "INTERNAL", "healthScore": 88, "status": "HEALTHY" }
  ]
}
```

---

## Feed Management

### Get All Feeds
```bash
GET /feeds
```

### Get Feed Health Report
```bash
GET /feeds/{feedId}
```
**Example Response:**
```json
{
  "success": true,
  "feedId": "credential-breach-feed",
  "overallHealth": 92,
  "healthStatus": "EXCELLENT",
  "quality": {
    "completeness": 98,
    "consistency": 95,
    "reliability": 92,
    "timeliness": 100,
    "validity": 99
  },
  "consensus": {
    "agreementRate": 95,
    "conflictCount": 12,
    "lastConflict": "2024-01-15T10:30:00Z"
  },
  "safeMode": {
    "enabled": false,
    "reason": null,
    "fallbackProvider": null
  },
  "alerts": 0
}
```

### Run Quality Check
```bash
POST /feeds/{feedId}/check-quality
```
**Response:**
```json
{
  "success": true,
  "feedId": "credential-breach-feed",
  "quality": {
    "completeness": 98,
    "consistency": 95,
    "reliability": 92,
    "timeliness": 100,
    "validity": 99
  },
  "overallHealth": 96,
  "healthStatus": "EXCELLENT",
  "safeModeStatus": false,
  "alerts": 0
}
```

### Detect Drift
```bash
POST /feeds/{feedId}/detect-drift
Content-Type: application/json

{
  "currentDataPoints": 10500
}
```
**Response:**
```json
{
  "success": true,
  "driftDetected": false,
  "driftPercentage": "8.5",
  "currentDataPoints": 10500,
  "baseline": 9650,
  "threshold": 20
}
```

### Calibrate Confidence
```bash
POST /feeds/{feedId}/calibrate-confidence
Content-Type: application/json

{
  "validationData": [
    { "correct": true },
    { "correct": true },
    { "correct": false },
    { "correct": true }
  ]
}
```
**Response:**
```json
{
  "success": true,
  "baselineAccuracy": "75.00",
  "calibrationFactor": "0.83",
  "sampleSize": 4
}
```

### Get Consensus Statistics
```bash
GET /feeds/{feedId}/consensus-stats
```

---

## Consensus Resolution

### Resolve Single Conflict
```bash
POST /consensus/resolve
Content-Type: application/json

{
  "feedId": "credential-breach-feed",
  "providerResults": [
    {
      "providerId": "HIBP",
      "result": { "breached": true, "count": 150 }
    },
    {
      "providerId": "EXTERNAL_FEED",
      "result": { "breached": true, "count": 148 }
    },
    {
      "providerId": "INTERNAL",
      "result": { "breached": false }
    }
  ]
}
```
**Response:**
```json
{
  "consensus": true,
  "resolvedValue": { "breached": true, "count": 149 },
  "strategy": "WEIGHTED_VOTE",
  "confidence": 0.68,
  "providers": [
    {
      "providerId": "HIBP",
      "result": { "breached": true, "count": 150 },
      "weight": 0.35,
      "contribution": 0.35
    }
  ],
  "conflictResolved": true,
  "alternatives": [false]
}
```

### Batch Resolve Conflicts
```bash
POST /consensus/batch-resolve
Content-Type: application/json

{
  "feedId": "credential-breach-feed",
  "providerResultsBatch": [
    [
      { "providerId": "HIBP", "result": "value1" },
      { "providerId": "EXTERNAL", "result": "value1" }
    ],
    [
      { "providerId": "HIBP", "result": "value2" },
      { "providerId": "INTERNAL", "result": "value3" }
    ]
  ]
}
```

---

## Routing & Failover

### Get Routing Status
```bash
GET /routing/{feedId}
```
**Response:**
```json
{
  "success": true,
  "feedId": "credential-breach-feed",
  "safeModeEnabled": false,
  "fallbackProvider": null,
  "providers": [
    {
      "providerId": "HIBP",
      "healthScore": 95,
      "status": "HEALTHY",
      "circuitState": "CLOSED"
    },
    {
      "providerId": "EXTERNAL_FEED",
      "healthScore": 88,
      "status": "HEALTHY",
      "circuitState": "CLOSED"
    }
  ]
}
```

### Route Request with Failover
```bash
POST /routing/{feedId}/request
Content-Type: application/json

{
  "primaryProviders": ["HIBP", "EXTERNAL_FEED", "INTERNAL"],
  "requestPayload": {
    "query": "user@example.com"
  }
}
```
**Response (Success):**
```json
{
  "success": true,
  "data": { "breached": true, "count": 150 },
  "providerId": "HIBP",
  "routingStrategy": "PRIMARY_CHAIN",
  "fromSafeMode": false
}
```

**Response (Fallback):**
```json
{
  "success": true,
  "data": { "breached": true },
  "providerId": "INTERNAL",
  "safeMode": "CONSERVATIVE",
  "confidenceThreshold": 0.85,
  "fromSafeMode": true
}
```

### Force Failover
```bash
POST /routing/{feedId}/failover
Content-Type: application/json

{
  "toProviderId": "INTERNAL"
}
```

---

## Safe Mode Management

### Activate Safe Mode
```bash
POST /feeds/{feedId}/safe-mode/activate
Content-Type: application/json

{
  "reason": "Manual activation due to high error rate",
  "fallbackProvider": "INTERNAL",
  "mode": "CONSERVATIVE"
}
```
**Modes:** CONSERVATIVE | PASSTHROUGH | MANUAL_REVIEW

### Deactivate Safe Mode
```bash
POST /feeds/{feedId}/safe-mode/deactivate
```

---

## Monitoring

### Get Critical Feeds
```bash
GET /critical-feeds
```
**Response:**
```json
{
  "success": true,
  "count": 2,
  "feeds": [
    {
      "feedId": "suspected-breach-feed",
      "overallHealth": 35,
      "healthStatus": "CRITICAL",
      "safeMode": true,
      "alerts": 5
    }
  ]
}
```

### Get Safe Mode Feeds
```bash
GET /safe-mode-feeds
```
**Response:**
```json
{
  "success": true,
  "count": 1,
  "feeds": [
    {
      "feedId": "credential-breach-feed",
      "reason": "Feed health degraded to 45%",
      "fallbackProvider": "INTERNAL",
      "mode": "CONSERVATIVE",
      "activatedAt": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Get Drift-Detected Feeds
```bash
GET /drift-detected-feeds
```
**Response:**
```json
{
  "success": true,
  "count": 1,
  "feeds": [
    {
      "feedId": "phishing-feed",
      "driftPercentage": 25.5,
      "threshold": 20,
      "lastDetected": "2024-01-15T11:00:00Z",
      "safeMode": true
    }
  ]
}
```

---

## Status Codes & Errors

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Successful request |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid parameters |
| 404 | Not Found | Feed or provider not found |
| 500 | Internal Server Error | Server error |

**Error Response:**
```json
{
  "success": false,
  "error": "Feed not found"
}
```

---

## Common Workflows

### Workflow 1: Resolve Provider Conflict

1. **Receive conflicting results** from multiple providers
2. **Call Consensus Resolve API**
   ```bash
   POST /consensus/resolve
   ```
3. **Get resolved value** with confidence score
4. **Use resolved value** for decision making

### Workflow 2: Monitor Feed Quality

1. **Periodically run quality check**
   ```bash
   POST /feeds/{feedId}/check-quality
   ```
2. **Review quality scores** (5 metrics)
3. **If quality drops**, system auto-activates safe mode
4. **Monitor overallHealth** score
5. **Take manual action** if needed

### Workflow 3: Detect and Handle Drift

1. **Feed receives new data points**
2. **Trigger drift detection**
   ```bash
   POST /feeds/{feedId}/detect-drift
   { "currentDataPoints": 10500 }
   ```
3. **If drift detected >threshold**:
   - Review recent changes
   - Investigate data source
   - Potentially activate safe mode
4. **Calibrate confidence** after verification
   ```bash
   POST /feeds/{feedId}/calibrate-confidence
   { "validationData": [...] }
   ```

### Workflow 4: Handle Provider Failure

1. **Provider health drops** below threshold
2. **Circuit breaker opens** after 5 failures
3. **Request routing switches** to fallback
4. **Safe mode may activate** if widespread issue
5. **Monitor circuit state** for recovery
6. **Manual failover option** available

---

## JavaScript SDK Usage

```javascript
// Using the dashboard
const dashboard = feedHealthDashboard;

// Refresh dashboard
await dashboard.refresh();

// Activate safe mode for feed
await dashboard.activateSafeMode('credential-feed');

// Deactivate safe mode
await dashboard.deactivateSafeMode('credential-feed');

// View feed details
dashboard.viewFeedDetails('credential-feed');

// Investigate drift
dashboard.investigateDrift('phishing-feed');
```

---

## Performance Tips

1. **Batch Operations**: Use batch-resolve for multiple conflicts
2. **Caching**: Cache provider rankings between requests
3. **Monitoring Intervals**: Adjust refresh intervals based on feed volatility
4. **Historical Data**: Keep last 100 entries for space efficiency
5. **Circuit Breaker**: Automatic protection from cascading failures

---

## Debugging

### Check Feed Health
```bash
curl -s http://localhost:3000/api/feed-health/feeds/credential-feed | jq .
```

### Check Provider Ranking
```bash
curl -s http://localhost:3000/api/feed-health/providers/rank/by-health | jq .
```

### View Critical Status
```bash
curl -s http://localhost:3000/api/feed-health/critical-feeds | jq .
```

### Monitor Safe Mode
```bash
curl -s http://localhost:3000/api/feed-health/safe-mode-feeds | jq .
```

---

## Related Documentation

- ISSUE_895_IMPLEMENTATION_SUMMARY.md - Full technical documentation
- feed-health-dashboard.js - Dashboard source code
- services/feedQualityControlService.js - Quality monitoring
- services/weightedConsensusEngine.js - Conflict resolution
- services/safeModeRoutingService.js - Failover logic
- models/ProviderSLA.js - Provider tracking
- models/FeedHealthScore.js - Feed metrics

