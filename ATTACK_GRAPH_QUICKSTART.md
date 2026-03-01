# Attack Graph Detection - Quick Start Guide

## What is This?

A graph-based security system that detects coordinated account takeover campaigns by analyzing patterns across multiple data points (IPs, devices, users, etc.) that would be invisible when looking at individual users.

## Key Features

✅ **Automatic Detection**
- Low-and-slow distributed credential stuffing
- Rapid burst attacks (botnets)
- Coordinated attack campaigns
- Impossible travel patterns

✅ **Graph Analysis**
- Entities: IP, Device, ASN, User Agent, Location, User, Session
- Relationships: Tracks how entities connect
- Connected component clustering
- Risk scoring with confidence levels

✅ **Incident Management**
- Auto-groups related security events
- Evidence chains with "why clustered" reasoning
- Campaign metrics and attack velocity tracking
- Analyst workflow support

✅ **Response Tooling**
- Mass session revocation
- Entity blocklisting (IPs, devices, etc.)
- Graph traversal and visualization
- Audit trail of all actions

## Installation

### 1. Dependencies Already Included

The system uses existing dependencies:
- `mongoose` - Database models
- `geolib` - Geographic calculations
- `node-cron` - Scheduled analysis

### 2. Auto-Initialization

The system initializes automatically when the server starts:

```javascript
// In server.js - already added
const attackGraphIntegrationService = require('./services/attackGraphIntegrationService');

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    // ... other initialization
    attackGraphIntegrationService.initialize();
  });
```

### 3. Database Indexes

MongoDB will automatically create indexes on first run:
- Entity lookups (type, value, risk score)
- Relationship queries
- Incident filtering

## Quick Test

After starting the server, verify the system is running:

```bash
# Check integration status
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/attack-graph/integration/status

# View dashboard
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/attack-graph/dashboard
```

## How It Works

### 1. Event Processing (Automatic)

The system monitors these security events:
- `LOGIN_ATTEMPT`
- `SUSPICIOUS_LOGIN`
- `BRUTE_FORCE_ATTEMPT`
- `2FA_FAILURE`
- `SESSION_ANOMALY_DETECTED`
- `IMPOSSIBLE_TRAVEL_DETECTED`

Events are automatically processed in batches every 5 seconds.

### 2. Graph Building

For each event, the system:
1. Extracts entities (IP, device, user, etc.)
2. Creates relationships between entities
3. Updates risk scores
4. Analyzes timing patterns

### 3. Attack Detection

The system runs detection algorithms:
- **Real-time**: Burst attack detection (5-minute window)
- **Near real-time**: Distributed attacks (batch processing)
- **Scheduled**: Full graph analysis every 6 hours

### 4. Incident Creation

When patterns are detected:
- Events grouped into incidents
- Confidence score calculated (0-100)
- Severity assigned (low/medium/high/critical)
- Evidence chain built
- "Why clustered" reasoning generated

### 5. Analyst Investigation

Analysts use the API to:
- Review incident dashboard
- Investigate entity relationships
- Traverse attack graphs
- Take response actions

## Configuration

Edit `services/attackGraphDetectionService.js`:

```javascript
this.config = {
  lowAndSlowWindowMs: 24 * 60 * 60 * 1000,  // 24 hours
  burstWindowMs: 5 * 60 * 1000,              // 5 minutes
  minEventsForIncident: 3,
  minConfidenceScore: 50,
  maxGraphDepth: 4,
  burstThreshold: 10,        // events per 5 min = burst
  lowAndSlowThreshold: 50,   // events per 24 hrs = campaign
  distributedIpThreshold: 5  // unique IPs = distributed
};
```

Edit `services/attackGraphIntegrationService.js`:

```javascript
this.config = {
  batchSize: 50,                              // Events per batch
  processingIntervalMs: 5000,                 // Batch frequency
  fullAnalysisSchedule: '0 */6 * * *',       // Cron schedule
  enableRealTimeProcessing: true
};
```

## API Quick Reference

All endpoints require authentication + `security:analyst` role.

### View Incidents
```
GET /api/attack-graph/incidents
GET /api/attack-graph/incidents/:incidentId
GET /api/attack-graph/incidents/:incidentId/graph
```

### Investigate Entities
```
GET /api/attack-graph/entities/:entityId
POST /api/attack-graph/entities/:entityId/traverse
GET /api/attack-graph/entities/high-risk
```

### Take Action
```
POST /api/attack-graph/entities/:entityId/blocklist
POST /api/attack-graph/incidents/:incidentId/revoke-sessions
POST /api/attack-graph/incidents/:incidentId/assign
PUT /api/attack-graph/incidents/:incidentId/status
```

### Monitoring
```
GET /api/attack-graph/metrics
GET /api/attack-graph/dashboard
POST /api/attack-graph/analyze  (admin only)
```

## Example Workflow

### Scenario: Distributed Credential Stuffing

1. **Detection** (automatic)
   - System detects 8 IPs trying same user credentials
   - Creates incident: `DISTRIBUTED_CREDENTIAL_STUFFING`
   - Confidence: 75/100, Severity: HIGH

2. **Investigation**
   ```bash
   # View incident details
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/attack-graph/incidents/INC-20260301-ABC123
   
   # Visualize attack graph
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/attack-graph/incidents/INC-20260301-ABC123/graph
   ```

3. **Response**
   ```bash
   # Blocklist all attacking IPs
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason": "Credential stuffing", "expiresInHours": 168}' \
     http://localhost:3000/api/attack-graph/entities/IP_ENTITY_ID/blocklist
   
   # Revoke all related sessions
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason": "Security incident"}' \
     http://localhost:3000/api/attack-graph/incidents/INC-20260301-ABC123/revoke-sessions
   ```

4. **Resolution**
   ```bash
   # Update status
   curl -X PUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"status": "MITIGATED", "notes": "All IPs blocked, sessions revoked"}' \
     http://localhost:3000/api/attack-graph/incidents/INC-20260301-ABC123/status
   
   # Validate for metrics
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"isTruePositive": true}' \
     http://localhost:3000/api/attack-graph/incidents/INC-20260301-ABC123/validate
   ```

## Monitoring

### System Health

Check integration service status:
```bash
# Status check
curl http://localhost:3000/api/attack-graph/integration/status

# Should return:
{
  "initialized": true,
  "queueSize": 0,
  "isProcessing": false,
  "config": { ... }
}
```

### Performance Metrics

Monitor from logs:
```
[Attack Graph Integration] Processing batch of 50 events
[Attack Graph Integration] Batch complete: 50 successful, 0 failed
[Attack Graph Integration] Starting scheduled full graph analysis
[Attack Graph Integration] Full analysis complete: { eventsAnalyzed: 1247, durationMs: 3421 }
```

### Detection Metrics

View system performance:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/attack-graph/metrics
```

Key metrics:
- **Precision**: % of incidents that are real threats
- **Active Incidents**: Currently under investigation
- **High-Risk Entities**: Entities requiring attention

## Troubleshooting

### No Incidents Being Created

**Check:**
1. Is integration service initialized?
   ```bash
   # Check logs for: "[Attack Graph Integration] Initialized successfully"
   ```

2. Are security events being created?
   ```javascript
   // Check SecurityEvent collection in MongoDB
   db.securityevents.find().limit(10).sort({createdAt: -1})
   ```

3. Are thresholds too high?
   - Lower `minEventsForIncident` in config
   - Lower `minConfidenceScore` in config

### Performance Issues

**Solutions:**
1. Increase `batchSize` to process more events at once
2. Increase `processingIntervalMs` to reduce frequency
3. Reduce `maxGraphDepth` to limit traversal depth
4. Add more MongoDB indexes

### False Positives

**To reduce:**
1. Increase `minConfidenceScore` threshold
2. Increase `burstThreshold` and `lowAndSlowThreshold`
3. Increase `distributedIpThreshold`
4. Mark incidents as false positives for metrics

**Remember:** Always validate incidents to improve detection over time!

### Memory Usage

If event queue grows too large:
1. Check MongoDB change streams are working
2. Increase batch processing frequency
3. Reduce analysis window sizes

## Security Considerations

### Access Control

- All endpoints require `security:analyst` role
- Manual analysis requires `security:admin` role
- Session revocation tracked per analyst
- Blocklisting requires reason documentation

### Data Retention

Consider implementing:
- Archive old incidents (>90 days)
- Purge resolved incidents (>1 year)
- Rotate entity data
- Clean expired blocklist entries

### Audit Trail

All actions are logged:
- Who blocked/unblocked entities
- Who revoked sessions
- Who changed incident status
- All analyst notes timestamped

## Files Reference

### Models (3 files)
- `models/AttackGraphEntity.js` - Graph nodes
- `models/AttackGraphRelationship.js` - Graph edges
- `models/SecurityIncident.js` - Incident grouping

### Services (2 files)
- `services/attackGraphDetectionService.js` - Detection engine
- `services/attackGraphIntegrationService.js` - Event processing

### Routes (1 file)
- `routes/attackGraph.js` - API endpoints

### Documentation (2 files)
- `ISSUE_848_IMPLEMENTATION_SUMMARY.md` - Full technical docs
- `ATTACK_GRAPH_ANALYST_PLAYBOOK.md` - Analyst guide

### Integration
- `server.js` - Routes registered, service initialized

## Support

For detailed documentation, see:
- **Technical Docs**: `ISSUE_848_IMPLEMENTATION_SUMMARY.md`
- **Analyst Guide**: `ATTACK_GRAPH_ANALYST_PLAYBOOK.md`

For issues:
- Check server logs
- Review MongoDB collections
- Verify RBAC permissions

---

**Status**: ✅ Production Ready  
**Issue**: #848  
**Implementation Date**: March 1, 2026
