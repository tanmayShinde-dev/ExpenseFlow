# Cross-Session Threat Correlation - Quick Start Guide

## Overview
The Cross-Session Threat Correlation system detects coordinated attacks across multiple user sessions by analyzing behavioral patterns, IP addresses, device fingerprints, and attack vectors.

## Quick Setup

### 1. Add Middleware to Routes

**Standard Protection (Non-blocking)**:
```javascript
const { correlationCheck } = require('./middleware/crossSessionCorrelation');

app.use('/api/data', correlationCheck, dataRoutes);
```

**High Security (Blocking)**:
```javascript
const { strictCorrelationCheck } = require('./middleware/crossSessionCorrelation');

app.use('/api/admin', strictCorrelationCheck, adminRoutes);
```

**Protect Sensitive Operations**:
```javascript
const { protectHighValueOperation } = require('./middleware/crossSessionCorrelation');

app.post('/api/transfer', protectHighValueOperation, transferHandler);
```

### 2. Add Correlation Context

```javascript
const { addCorrelationContext } = require('./middleware/crossSessionCorrelation');

app.use(addCorrelationContext);

// Now access correlation data in routes
app.get('/api/dashboard', auth, (req, res) => {
  const riskLevel = req.correlationContext.riskLevel;
  const activeClusters = req.correlationContext.activeClusters;
  
  res.json({ riskLevel, clusters: activeClusters });
});
```

## Common Use Cases

### Use Case 1: Detect Same IP Attacking Multiple Accounts

**Scenario**: An attacker uses the same IP to compromise 3+ accounts

**How it works**:
1. User sessions are analyzed in real-time
2. System groups sessions by IP address
3. When 3+ users access from same IP, cluster is created
4. Containment action is triggered (lock accounts or revoke sessions)

**Configuration**:
```javascript
// In crossSessionThreatCorrelationService.js
ipCorrelationThreshold: 3  // Minimum users to trigger
```

### Use Case 2: Device Fingerprint Reuse

**Scenario**: Same device is used to access 2+ different accounts

**How it works**:
1. Device fingerprints are tracked per session
2. System detects when same device ID appears across accounts
3. Correlation cluster created with DEVICE_REUSE type
4. Accounts locked pending investigation

**Configuration**:
```javascript
deviceReuseThreshold: 2  // Minimum accounts to trigger
```

### Use Case 3: Coordinated Privilege Escalation

**Scenario**: Multiple users escalate privileges within 15-minute window

**How it works**:
1. Permission changes are monitored
2. Time-windowed analysis groups escalations
3. Pattern detected when 2+ users escalate simultaneously
4. High-severity alert triggered

**Configuration**:
```javascript
privilegeEscalationThreshold: 2
timeWindowMinutes: 15
```

### Use Case 4: ML Anomaly Clustering

**Scenario**: Multiple users show similar abnormal behavior patterns

**How it works**:
1. ML anomaly scores from Issue #878 are consumed
2. Sessions with high anomaly scores are clustered
3. Behavioral similarity computed using ML features
4. Groups of 4+ similar anomalies trigger correlation

**Configuration**:
```javascript
anomalyClusterThreshold: 4
anomalyScoreThreshold: 0.75
```

### Use Case 5: Attack Vector Correlation

**Scenario**: Same attack pattern targets multiple users

**How it works**:
1. Security events are categorized by attack type
2. System groups users experiencing same attack vector
3. When 3+ users show same attack pattern, cluster created
4. Campaign-level threat identified

**Configuration**:
```javascript
attackVectorThreshold: 3
```

## API Quick Reference

### Check User Correlation Status
```bash
GET /api/correlation/my-status
Authorization: Bearer <token>

Response:
{
  "success": true,
  "status": {
    "riskLevel": "MODERATE",
    "activeClusters": 1,
    "activeContainments": 0,
    "recentEvents": 3
  },
  "clusters": [...],
  "containments": [],
  "events": [...]
}
```

### Request Trusted Relationship
```bash
POST /api/correlation/relationships/request
Authorization: Bearer <token>
Content-Type: application/json

{
  "targetUserEmail": "family_member@example.com",
  "relationshipType": "FAMILY",
  "description": "My spouse",
  "expiresInDays": 365
}

Response:
{
  "success": true,
  "message": "Relationship request sent",
  "relationship": { ... }
}
```

### Approve Relationship
```bash
POST /api/correlation/relationships/:id/approve
Authorization: Bearer <token>

Response:
{
  "success": true,
  "message": "Relationship approved",
  "relationship": { ... }
}
```

### Appeal Containment (User)
```bash
POST /api/correlation/appeal-containment/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "reason": "I was traveling and accessed from hotel wifi",
  "evidence": "Booking confirmation attached"
}

Response:
{
  "success": true,
  "message": "Appeal submitted successfully",
  "appealId": "..."
}
```

### View Active Clusters (Analyst)
```bash
GET /api/correlation/clusters?severity=HIGH
Authorization: Bearer <analyst-token>

Response:
{
  "success": true,
  "clusters": [
    {
      "correlationType": "IP_BASED",
      "severity": "HIGH",
      "userIds": [...],
      "indicators": { ... },
      "firstDetected": "2024-01-15T10:30:00Z"
    }
  ],
  "count": 1
}
```

### Approve Containment Action (Analyst)
```bash
POST /api/correlation/containments/:id/approve
Authorization: Bearer <analyst-token>
Content-Type: application/json

{
  "notes": "Confirmed malicious activity. Proceeding with account locks."
}

Response:
{
  "success": true,
  "message": "Containment action approved",
  "action": { ... }
}
```

### Reverse Containment Action (Analyst)
```bash
POST /api/correlation/containments/:id/reverse
Authorization: Bearer <analyst-token>
Content-Type: application/json

{
  "reason": "False positive - users are family members"
}

Response:
{
  "success": true,
  "message": "Containment action reversed",
  "action": { ... },
  "reverseDetails": {
    "accountsUnlocked": 3,
    "permissionsRestored": 3
  }
}
```

## Environment Variables

```bash
# Enable/Disable
CORRELATION_ENABLED=true

# Thresholds
CORRELATION_IP_THRESHOLD=3
CORRELATION_DEVICE_THRESHOLD=2
CORRELATION_PRIVILEGE_THRESHOLD=2
CORRELATION_ANOMALY_THRESHOLD=4
CORRELATION_ATTACK_VECTOR_THRESHOLD=3

# Time Windows
CORRELATION_TIME_WINDOW_MINUTES=15

# Containment
CONTAINMENT_AUTO_EXECUTE=false
CONTAINMENT_AUTO_EXECUTE_DELAY=15
CONTAINMENT_REQUIRE_APPROVAL=true

# Relationships
RELATIONSHIP_DEFAULT_EXPIRY=365
RELATIONSHIP_AUTO_SUGGEST=true
```

## Severity Levels

### LOW
- Single correlation detected
- No immediate threat
- Monitor only

### MODERATE
- Multiple correlations from same source
- Potential coordinated activity
- Enhanced monitoring enabled

### HIGH
- Clear coordinated attack pattern
- Multiple accounts compromised
- Requires analyst review

### CRITICAL
- Large-scale coordinated attack
- Active compromise in progress
- Immediate containment required
- Analyst approval bypassed for critical actions

## Best Practices

### 1. Configure Trusted Relationships First
Before enabling strict correlation, ensure users can establish trusted relationships with legitimate shared-access scenarios (family, team members).

### 2. Start with Monitor-Only Mode
Begin with `correlationCheck` middleware (non-blocking) to observe patterns before enabling strict enforcement.

### 3. Tune Thresholds for Your Use Case
Adjust correlation thresholds based on your user base:
- **B2C Apps**: Lower thresholds (more sensitive)
- **B2B Apps with Teams**: Higher thresholds (account for shared IPs)
- **Family Apps**: Enable trusted relationships heavily

### 4. Review False Positives Weekly
Check clusters marked as false positives to tune your configuration.

### 5. Enable Auto-Suggestions
Let users see suggested trusted relationships based on their usage patterns.

### 6. Set Up Analyst Dashboards
Create monitoring dashboards for security analysts to review pending containments.

### 7. Configure Alert Thresholds
Set up alerts for:
- CRITICAL severity clusters (Slack/PagerDuty)
- Pending containment approvals (Email)
- High false positive rate (Weekly report)

## Troubleshooting

### Issue: Users Being Flagged as False Positives

**Solution**: Create trusted relationships
```bash
# User A requests relationship with User B
POST /api/correlation/relationships/request
{
  "targetUserEmail": "userb@example.com",
  "relationshipType": "FAMILY"
}

# User B approves
POST /api/correlation/relationships/:id/approve
```

### Issue: Correlation Not Detecting Threats

**Check**:
1. Service initialization succeeded
2. Thresholds not too high
3. ML anomaly detection is running (for ANOMALY_CLUSTER type)

**Debug**:
```bash
# Check service status
GET /api/correlation/statistics

# View recent events
GET /api/correlation/events?hours=24
```

### Issue: Containment Actions Not Executing

**Check**:
1. Analyst approval requirements
2. Auto-execute configuration
3. Containment system initialization

**Fix**:
```bash
# Manually approve pending actions
GET /api/correlation/containments?status=pending
POST /api/correlation/containments/:id/approve
```

## Performance Tips

### 1. Use Indexes
Ensure MongoDB indexes on:
- `Session.userId`, `Session.ip`, `Session.deviceFingerprint`
- `SessionCorrelationCluster.status`, `SessionCorrelationCluster.severity`
- `ContainmentAction.status`, `ContainmentAction.affectedUsers`

### 2. Configure Caching
Use Redis for hot correlation data:
```javascript
// Cache active clusters
redis.setex(`clusters:active`, 300, JSON.stringify(clusters));
```

### 3. Async Analysis
Correlation analysis runs asynchronously by default (via `setImmediate`). For high-traffic apps, consider:
- Separate worker processes
- Queue-based processing (Bull, RabbitMQ)

### 4. Batch Processing
Process correlation analysis in batches during off-peak hours:
```bash
# Cron job for nightly batch analysis
0 2 * * * node scripts/batch-correlation-analysis.js
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/expenseflow/issues
- Security Email: security@expenseflow.com
- Documentation: /docs/correlation

---

**Last Updated**: 2024
**Version**: 1.0.0
