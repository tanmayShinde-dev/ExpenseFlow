# Feed Health System - Configuration Guide

## Core Configuration Files

### 1. Environment Variables

Create a `.env` file in your project root:

```bash
# Feed Health Monitoring
FEED_HEALTH_REFRESH_INTERVAL=30000          # Dashboard refresh interval (ms)
FEED_QUALITY_CHECK_INTERVAL=300000          # Quality check interval (ms)
DRIFT_DETECTION_THRESHOLD=20                # Drift percentage threshold
DRIFT_BASELINE_WINDOW=604800000             # Baseline window (7 days)

# Safe Mode
SAFE_MODE_ACTIVATION_THRESHOLD=70           # Health score threshold
SAFE_MODE_ALERT_THRESHOLD=50                # Alert threshold
SAFE_MODE_DEFAULT_MODE=CONSERVATIVE         # Default: CONSERVATIVE|PASSTHROUGH|MANUAL_REVIEW

# Circuit Breaker
CIRCUIT_BREAKER_THRESHOLD=5                 # Consecutive failures before open
CIRCUIT_BREAKER_RESET_TIMEOUT=300000        # Reset timeout (ms)
CIRCUIT_BREAKER_MAX_RETRIES=3               # Max retry attempts

# Consensus
MIN_CONSENSUS_THRESHOLD=0.6                 # 60% minimum agreement
MAJORITY_CONSENSUS_THRESHOLD=0.5            # 50% for majority
UNANIMOUS_CONSENSUS_THRESHOLD=0.95          # 95% for unanimous

# Providers
PROVIDER_WEIGHT_MIN=0.2                     # Minimum weight
PROVIDER_WEIGHT_MAX=10.0                    # Maximum weight

# Monitoring
HEALTH_HISTORY_RETENTION=100                # Keep last N entries
DRIFT_HISTORY_RETENTION=100                 # Keep last N drift events
CONFLICT_HISTORY_RETENTION=100              # Keep last N conflicts
ALERT_RETENTION_DAYS=30                     # Keep alerts for N days
```

### 2. Quality Metrics Weights

Configure the five-factor quality calculation:

```javascript
// In feedQualityControlService.js
config.dataQualityWeights = {
  completeness: 0.20,  // 20% - All expected fields present
  consistency: 0.25,   // 25% - Data matches across providers
  reliability: 0.25,   // 25% - Availability and accuracy
  timeliness: 0.20,    // 20% - Data freshness/update frequency
  validity: 0.10       // 10% - Data format and integrity
};
```

**Adjustment Examples:**

**Example 1: Prioritize Data Freshness**
```javascript
config.dataQualityWeights = {
  completeness: 0.15,
  consistency: 0.20,
  reliability: 0.20,
  timeliness: 0.35,    // Increased from 0.20
  validity: 0.10
};
```

**Example 2: Prioritize Consistency**
```javascript
config.dataQualityWeights = {
  completeness: 0.20,
  consistency: 0.35,   // Increased from 0.25
  reliability: 0.20,
  timeliness: 0.15,    // Decreased from 0.20
  validity: 0.10
};
```

### 3. Provider SLA Configuration

Configure per-provider SLA targets in database:

```javascript
// Example: Create provider with custom SLA
const provider = await ProviderSLA.create({
  providerId: 'HIBP',
  providerType: 'credential_breach',
  weight: 1.5,  // Higher weight = more trustworthy
  
  slaTargets: {
    avgLatency: 500,        // Target: 500ms average
    p95Latency: 1000,       // Target: 1000ms p95
    p99Latency: 2000,       // Target: 2000ms p99
    uptime: 99.5,           // Target: 99.5% uptime
    errorRate: 0.5,         // Target: <0.5% errors
    accuracyScore: 98.0,    // Target: 98% accuracy
    dataFreshness: 3600     // Target: <1 hour old
  },
  
  weights: {
    latency: 0.20,
    availability: 0.30,
    errors: 0.20,
    accuracy: 0.20,
    freshness: 0.10
  }
});
```

### 4. Feed Configuration

Configure feed-specific settings:

```javascript
// Example: Create feed with custom settings
const feed = await FeedHealthScore.create({
  feedId: 'credential-breach-feed',
  
  drift: {
    driftThreshold: 20,  // Alert if deviation > 20%
    baselineDataPoints: 8000
  },
  
  safeMode: {
    enabled: false,
    mode: 'CONSERVATIVE'  // Default mode
  },
  
  confidenceCalibration: {
    baselineAccuracy: 90,
    calibrationFactor: 1.0
  }
});
```

### 5. Dashboard Configuration

Configure dashboard behavior in `feed-health-dashboard.js`:

```javascript
const dashboard = new FeedHealthDashboard();

dashboard.config = {
  refreshInterval: 30000,      // Auto-refresh every 30 seconds
  chartUpdateInterval: 60000,  // Update charts every 60 seconds
  alertDisplayTime: 10000      // Show alerts for 10 seconds
};
```

### 6. Consensus Resolution Strategy

Configure consensus behavior per feed:

```javascript
// Get appropriate strategy for feed
const strategy = await weightedConsensusEngine.getConsensusStrategy(
  'credential-feed',
  3  // number of providers
);

// Strategy selection logic:
// - 3 or fewer providers: WEIGHTED_VOTE
// - More providers: MAJORITY
// - Drift detected: UNANIMOUS (strictest)
// - High conflict rate: MAJORITY
```

**Strategy Behaviors:**
- **UNANIMOUS** (95%+): All providers must agree
- **MAJORITY** (50%+): 50% approval needed
- **WEIGHTED_VOTE**: Provider health-based voting
- **FALLBACK**: Historical winner selection

### 7. Alert Configuration

Configure alert thresholds:

```javascript
// Critical alerts (auto-escalate)
const CRITICAL_ALERT_TRIGGERS = {
  healthScoreDrop: 40,        // Alert if health < 40%
  failureRate: 10,            // Alert if >10% failures
  driftDetection: 30,         // Alert if drift > 30%
  allProvidersFailed: true,   // Alert on total failure
  consensusBreakdown: 30      // Alert if agreement < 30%
};

// Warning alerts
const WARNING_ALERT_TRIGGERS = {
  healthScoreDrop: 60,        // Warn if health < 60%
  failureRate: 5,             // Warn if >5% failures
  driftDetection: 20,         // Warn if drift > 20%
  consensusBreakdown: 50      // Warn if agreement < 50%
};

// Info alerts
const INFO_ALERT_TRIGGERS = {
  safeModeActivation: true,
  providerFailover: true,
  configurationChange: true,
  driftDetection: 10          // Info if drift > 10%
};
```

### 8. Logging Configuration

Configure logging levels:

```javascript
// In server.js or logging setup
const Feed_HEALTH_LOG_LEVELS = {
  CONSENSUS: 'debug',       // Log all consensus operations
  DRIFT_DETECTION: 'info',  // Log drift detection
  SAFE_MODE: 'warn',        // Log safe mode changes
  ROUTING: 'debug',         // Log routing decisions
  QUALITY_CHECK: 'info',    // Log quality check results
  CIRCUIT_BREAKER: 'warn'   // Log circuit breaker state changes
};
```

### 9. Performance Tuning

Optimize for different scenarios:

#### High-Volume Scenario (1000+ requests/min)
```javascript
// Increase batch sizes and reduce check frequency
config = {
  driftCheckInterval: 600000,    // Check every 10 minutes
  healthHistoryRetention: 50,    // Keep fewer entries
  batchResolveTimeout: 5000,     // Longer batch window
  refreshInterval: 60000         // Slower dashboard refresh
};
```

#### Low-Latency Scenario
```javascript
// Minimize overhead
config = {
  driftCheckInterval: 60000,     // Check frequently
  healthHistoryRetention: 20,    // Minimal history
  maxRetries: 1,                 // Minimal retries
  circuitBreakerThreshold: 3     // Faster failover
};
```

#### Compliance Scenario (auditing important)
```javascript
// Maximize data retention
config = {
  healthHistoryRetention: 1000,  // Keep detailed history
  driftHistoryRetention: 1000,
  conflictHistoryRetention: 1000,
  alertRetentionDays: 365,       // Keep 1 year of alerts
  auditLogging: true
};
```

### 10. Integration Configuration

Configure integration with existing systems:

#### Slack Notifications
```javascript
// services/feedQualityControlService.js
const SLACK_CONFIG = {
  webhookUrl: process.env.SLACK_WEBHOOK_URL,
  channel: '#feed-health-alerts',
  postCriticalAlerts: true,
  postWarningAlerts: false,
  postSafeModeActivation: true
};
```

#### Email Alerts
```javascript
const EMAIL_CONFIG = {
  smtpServer: process.env.SMTP_SERVER,
  fromAddress: 'feed-health@expenseflow.com',
  recipientList: ['ops@expenseflow.com'],
  alertLevelsToSend: ['CRITICAL', 'WARNING']
};
```

#### Metrics Export (Prometheus, etc.)
```javascript
const METRICS_CONFIG = {
  enabled: true,
  endpoint: '/metrics',
  includeMetrics: [
    'feed_health_score',
    'provider_health_score',
    'consensus_agreement_rate',
    'drift_detection_count',
    'circuit_breaker_state'
  ]
};
```

---

## Configuration Templates

### Template 1: Development Environment

```bash
# .env.development
FEED_HEALTH_REFRESH_INTERVAL=5000
FEED_QUALITY_CHECK_INTERVAL=60000
DRIFT_DETECTION_THRESHOLD=25
CIRCUIT_BREAKER_THRESHOLD=3
CIRCUIT_BREAKER_RESET_TIMEOUT=60000
HEALTH_HISTORY_RETENTION=20
LOG_LEVEL=debug
```

### Template 2: Staging Environment

```bash
# .env.staging
FEED_HEALTH_REFRESH_INTERVAL=30000
FEED_QUALITY_CHECK_INTERVAL=300000
DRIFT_DETECTION_THRESHOLD=20
CIRCUIT_BREAKER_THRESHOLD=5
CIRCUIT_BREAKER_RESET_TIMEOUT=300000
HEALTH_HISTORY_RETENTION=100
LOG_LEVEL=info
```

### Template 3: Production Environment

```bash
# .env.production
FEED_HEALTH_REFRESH_INTERVAL=60000
FEED_QUALITY_CHECK_INTERVAL=600000
DRIFT_DETECTION_THRESHOLD=15
CIRCUIT_BREAKER_THRESHOLD=7
CIRCUIT_BREAKER_RESET_TIMEOUT=600000
HEALTH_HISTORY_RETENTION=500
LOG_LEVEL=warn
```

---

## Dynamic Configuration Updates

Update configuration without restarting:

```javascript
// API endpoint to update configuration
app.post('/api/feed-health/admin/config', async (req, res) => {
  const { key, value } = req.body;
  
  // Validate key
  if (!isValidConfigKey(key)) {
    return res.status(400).json({ error: 'Invalid config key' });
  }
  
  // Update configuration
  updateConfig(key, value);
  
  // Log change
  console.log(`Config updated: ${key} = ${value}`);
  
  res.json({ success: true, config: getConfig() });
});

// Example: Update drift threshold
POST /api/feed-health/admin/config
{ "key": "driftThreshold", "value": 25 }
```

---

## Validation Rules

### Provider Weight Validation
```javascript
// Weight must be between MIN and MAX
0.2 ≤ weight ≤ 10.0
```

### Health Score Thresholds
```javascript
// Status determination
HEALTHY: 90-100
DEGRADED: 70-89
UNHEALTHY: 50-69
DOWN: 0-49
```

### Quality Metrics Validation
```javascript
// All quality metrics must be 0-100%
0 ≤ completeness ≤ 100
0 ≤ consistency ≤ 100
0 ≤ reliability ≤ 100
0 ≤ timeliness ≤ 100
0 ≤ validity ≤ 100
```

### Drift Threshold Validation
```javascript
// Drift threshold must be positive percentage
0 < driftThreshold ≤ 100
```

---

## Monitoring Configuration

Enable different monitoring levels:

```javascript
// Minimum monitoring
console.log only errors

// Development monitoring
console.log + file logging

// Production monitoring
Structured logging + metrics + alerts
```

---

## Related Files

- ISSUE_895_IMPLEMENTATION_SUMMARY.md - Implementation details
- FEED_HEALTH_API_REFERENCE.md - API documentation
- feed-health-dashboard.js - Dashboard configuration
- services/feedQualityControlService.js - Service configuration
- services/weightedConsensusEngine.js - Consensus configuration
- services/safeModeRoutingService.js - Routing configuration

