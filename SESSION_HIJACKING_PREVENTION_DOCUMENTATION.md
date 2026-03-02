# Session Hijacking Prevention & Recovery System
## Issue #881 Implementation

## Overview

The Session Hijacking Prevention & Recovery System provides comprehensive protection against session hijacking attacks through real-time detection, immediate containment, and guided recovery mechanisms.

## Architecture

### Core Components

1. **Detection Engine** (`sessionHijackingDetectionService.js`)
   - Real-time behavioral analysis
   - Impossible location detection
   - Device fingerprint tracking
   - Privilege escalation monitoring
   - Request pattern analysis

2. **Recovery Service** (`sessionHijackingRecoveryService.js`)
   - Immediate session containment
   - User notification system
   - Step-up authentication
   - Guided recovery process
   - Account security reinforcement

3. **Forensics Service** (`sessionForensicsService.js`)
   - Session replay capability
   - Data access auditing
   - Timeline reconstruction
   - Attack vector analysis
   - Forensic reporting

4. **Detection Middleware** (`sessionHijackingDetection.js`)
   - Request interception
   - Real-time risk assessment
   - Automatic containment triggering
   - Behavioral tracking

## Detection Methods

### 1. Behavioral Divergence Detection

Monitors user behavior patterns and detects anomalies:

- **Request Cadence**: Tracks the timing between requests
- **Endpoint Patterns**: Monitors which endpoints are accessed
- **Activity Levels**: Detects sudden changes in activity
- **Navigation Flows**: Analyzes typical user navigation patterns

**Baseline Establishment**: Requires 50 requests to establish a behavioral baseline.

**Detection Algorithm**:
```javascript
// Cadence Anomaly: deviation > 3 standard deviations
if (cadenceDeviation > (3 * cadenceStdDev)) {
  // Anomaly detected
}

// Endpoint Anomaly: accessing rare endpoints (< 1% frequency)
if (endpointFrequency < 0.01) {
  // Potential suspicious access
}
```

### 2. Impossible Location Detection

Identifies sessions that couldn't physically occur:

- **Simultaneous Sessions**: Detects active sessions from geographically distant locations within minutes
- **Impossible Travel**: Calculates required travel speed between locations
- **Distance Threshold**: Significant if > 100 km apart
- **Time Window**: Checks activities within 5-minute windows

**Detection Algorithm**:
```javascript
requiredSpeed = distance / (timeDiff / 3600000); // km/h

if (requiredSpeed > 900) { // Faster than commercial flight
  // Impossible travel detected
}
```

### 3. Device Fingerprint Swap Detection

Monitors device changes during active sessions:

- **Fingerprint Tracking**: Unique device identifiers
- **Rapid Swaps**: Detects device changes within minutes
- **New Device Alerts**: Flags first-time device usage
- **Suspicious Patterns**: Multiple device switches in short periods

**Detection Criteria**:
- Device fingerprint change within 3 minutes
- Multiple devices active within 3-minute window
- High risk if combined with other indicators

### 4. Privilege Escalation Detection

Identifies unauthorized privilege access attempts:

- **Privileged Endpoint Monitoring**: Tracks access to admin/security endpoints
- **Time-based Analysis**: Detects access during unusual hours
- **Rapid Escalation**: Flags multiple escalation attempts within 1 minute
- **Context Awareness**: Considers user's normal access patterns

**Protected Endpoints**:
- `/api/admin/*`
- `/api/users/*/promote`
- `/api/roles/*`
- `/api/permissions/*`
- `/api/settings/security`
- `/api/audit/*`
- `/api/backups/*`

### 5. Request Pattern Anomaly Detection

Analyzes request characteristics:

- **HTTP Method Anomalies**: Unusual method usage for endpoints
- **Rapid-Fire Requests**: Detects automated/bot behavior
- **Cadence Changes**: Significant departures from normal timing
- **Automation Detection**: Requests faster than 500ms average

## Risk Scoring System

### Score Calculation

Each detection method contributes to an overall risk score (0-100):

```javascript
totalRiskScore = 
  behavioralScore +
  locationScore +
  fingerprintScore +
  privilegeScore +
  patternScore;
```

### Risk Thresholds

| Level    | Score Range | Action                          |
|----------|-------------|---------------------------------|
| Low      | 0-24        | Monitor only                    |
| Medium   | 25-49       | Increase monitoring             |
| High     | 50-74       | Issue security challenge        |
| Critical | 75-100      | Immediate containment           |

### Confidence Level

Confidence is calculated based on:
- Number of indicators detected
- Risk score magnitude

```javascript
confidence = (indicatorCount / 3) * 0.4 + (riskScore / 100) * 0.6
```

## Containment Actions

When hijacking is detected (risk score ≥ 75), automatic containment executes:

### 1. Session Termination
- Immediately revoke compromised session
- Update session status to 'revoked'
- Log termination reason and timestamp

### 2. User Notification
- **In-App Notification**: Critical priority alert
- **Email Alert**: Detailed security notification with recovery link
- **Push Notification** (if enabled): Immediate mobile alert

### 3. Account Locking (Critical Risk ≥ 90)
- Lock account to prevent further access
- Require recovery process to unlock
- Notify administrators

### 4. Recovery Session Creation
- Generate unique recovery token
- Create authenticated recovery session
- Set expiration (default: 1 hour)
- Initialize step-up authentication

### 5. 2FA Enforcement
- Require 2FA during recovery
- Recommend enabling if not active
- Generate backup codes

## Recovery Process

### Step 1: Identity Verification

Users must verify identity using one of:

1. **2FA TOTP** (if enabled)
   - Google Authenticator
   - Authy
   - Microsoft Authenticator

2. **Email Verification Code**
   - 6-digit code sent to registered email
   - 10-minute expiration
   - Max 3 attempts

3. **SMS Code** (if configured)
   - Sent to registered mobile
   - Similar expiration and limits

4. **Backup Codes**
   - Previously generated codes
   - One-time use

### Step 2: Security Actions

Users can perform limited actions during recovery:

#### **Allowed Actions**:
- `VIEW_ACCOUNT`: View account information
- `CHANGE_PASSWORD`: Set new password (mandatory)
- `REVOKE_SESSIONS`: Terminate all active sessions
- `ENABLE_2FA`: Activate two-factor authentication
- `VIEW_SECURITY_LOG`: Review recent security events
- `DOWNLOAD_ACCOUNT_DATA`: Export account data

#### **Restrictions**:
- Read-only access by default
- No financial transactions
- No data modifications (except password)
- No sensitive data export (except account data)

### Step 3: Recovery Completion

Minimum requirements:
- Complete at least 2 security actions
- **Mandatory**: Change password
- **Recommended**: Enable 2FA, Revoke sessions

Upon completion:
- Account unlocked
- New secure session created
- Recovery session terminated
- User directed to dashboard

## Forensics System

### Session Replay

Records detailed session activity for post-incident analysis:

**Captured Data**:
- Request timestamps and endpoints
- HTTP methods and status codes
- Response times
- IP addresses and user agents
- Request/response headers (sanitized)
- Query parameters and body data (sanitized)

### Data Access Auditing

Tracks all data operations during suspicious sessions:

**Audit Information**:
- Resource accessed
- Action performed (READ, WRITE, DELETE)
- Record IDs involved
- Timestamp of access
- Sensitive data flag

### Timeline Reconstruction

Builds comprehensive timeline including:
- Session start/end events
- All HTTP requests
- Data access operations
- Security events
- Behavioral anomalies

### Forensic Reports

Generates detailed reports containing:

1. **Detection Summary**
   - Detection method
   - Risk score and confidence
   - Indicators identified

2. **Session Comparison**
   - Original vs. suspicious session details
   - IP addresses and locations
   - Device information

3. **Activity Analysis**
   - Request patterns
   - Activity bursts
   - Endpoint access frequency
   - Data operations performed

4. **Security Assessment**
   - Attack vector analysis
   - Impact assessment
   - Suspicious activities identified

5. **Recommendations**
   - Security improvements
   - Policy updates
   - User training needs

## Database Models

### SessionHijackingEvent

Stores hijacking detection events:

```javascript
{
  userId: ObjectId,
  sessionId: ObjectId,
  detectedAt: Date,
  detectionMethod: String,
  indicators: [{
    type: String,
    severity: String,
    riskScore: Number,
    details: Mixed
  }],
  riskScore: Number,
  confidenceLevel: Number,
  originalSession: { /* session data */ },
  suspiciousSession: { /* session data */ },
  containment: {
    executed: Boolean,
    actions: [/* containment actions */]
  },
  recovery: {
    initiated: Boolean,
    recoverySessionId: ObjectId,
    restored: Boolean
  },
  forensics: {
    sessionReplayAvailable: Boolean,
    requestLog: [/* requests */],
    dataAccessLog: [/* data access */]
  },
  status: String
}
```

### RecoverySession

Manages recovery sessions:

```javascript
{
  userId: ObjectId,
  recoveryToken: String (unique),
  hijackingEventId: ObjectId,
  stepUpAuthentication: {
    required: Boolean,
    method: String,
    completed: Boolean,
    attempts: Number,
    maxAttempts: Number
  },
  restrictions: {
    readOnly: Boolean,
    allowedActions: [String],
    deniedEndpoints: [String]
  },
  actionsPerformed: [{
    action: String,
    timestamp: Date,
    details: Mixed
  }],
  status: String,
  expiresAt: Date
}
```

### SessionBehaviorProfile

Tracks behavioral patterns:

```javascript
{
  sessionId: ObjectId,
  userId: ObjectId,
  requestPatterns: {
    totalRequests: Number,
    avgCadence: Number,
    cadenceStdDev: Number,
    endpointCounts: Map,
    topEndpoints: [{endpoint, count, percentage}],
    methodDistribution: {GET, POST, PUT, DELETE, PATCH}
  },
  activityProfile: {
    level: String,
    avgResponseTime: Number,
    hourlyActivity: [Number], // 24 buckets
    resourceTypes: Map,
    dataOperations: {reads, writes, deletes}
  },
  privilegeUsage: {
    actions: [/* privilege actions */],
    escalationAttempts: Number
  },
  baseline: {
    established: Boolean,
    requiredSamples: Number,
    currentSamples: Number
  },
  anomalies: [/* detected anomalies */]
}
```

## API Endpoints

### Recovery Endpoints

#### POST `/api/session-recovery/verify-step-up`
Verify step-up authentication code
- **Body**: `{recoveryToken, code, method}`
- **Response**: `{success, message, recoveryToken, allowedActions}`

#### POST `/api/session-recovery/resend-code`
Resend verification code
- **Body**: `{recoveryToken}`
- **Response**: `{success, message, expiresIn}`

#### GET `/api/session-recovery/status`
Get recovery session status
- **Headers**: `X-Recovery-Token`
- **Response**: `{recovery, hijacking}`

#### POST `/api/session-recovery/change-password`
Change password during recovery
- **Headers**: `X-Recovery-Token`
- **Body**: `{newPassword, confirmPassword}`
- **Response**: `{success, message}`

#### POST `/api/session-recovery/revoke-sessions`
Revoke all active sessions
- **Headers**: `X-Recovery-Token`
- **Response**: `{success, revokedCount}`

#### POST `/api/session-recovery/enable-2fa`
Enable two-factor authentication
- **Headers**: `X-Recovery-Token`
- **Response**: `{success, message, secret}`

#### GET `/api/session-recovery/security-log`
Get recent security events
- **Headers**: `X-Recovery-Token`
- **Response**: `{success, events}`

#### POST `/api/session-recovery/complete`
Complete recovery process
- **Headers**: `X-Recovery-Token`
- **Response**: `{success, message}`

#### GET `/api/session-recovery/hijacking-events`
Get user's hijacking history
- **Auth**: Required
- **Query**: `?limit=10`
- **Response**: `{success, events}`

#### GET `/api/session-recovery/forensics/:eventId`
Get forensic report
- **Auth**: Required
- **Response**: `{success, report}`

#### POST `/api/session-recovery/report-false-positive/:eventId`
Report false positive detection
- **Auth**: Required
- **Body**: `{feedback}`
- **Response**: `{success, message}`

## Integration

### 1. Server Integration

Add to `server.js`:

```javascript
const sessionRecoveryRoutes = require('./routes/sessionRecovery');
const sessionHijackingMiddleware = require('./middleware/sessionHijackingDetection');

// Apply hijacking detection to protected routes
sessionHijackingMiddleware.applyToRoutes(app, [
  '/api/expenses',
  '/api/budgets',
  '/api/transactions',
  '/api/reports',
  '/api/settings'
]);

// Register recovery routes
app.use('/api/session-recovery', sessionRecoveryRoutes);

// Serve recovery page
app.get('/auth/recovery', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'session-recovery.html'));
});
```

### 2. Route-Level Protection

Apply to specific routes:

```javascript
const router = express.Router();
const sessionHijackingMiddleware = require('../middleware/sessionHijackingDetection');

// Apply detection middleware
router.use(sessionHijackingMiddleware.detectAndContain);

// Apply data access auditing
router.get('/sensitive-data', 
  sessionHijackingMiddleware.auditDataAccess('sensitive-data', 'READ'),
  (req, res) => {
    // Handle request
  }
);
```

### 3. Manual Detection

For custom logic:

```javascript
const sessionHijackingDetectionService = require('./services/sessionHijackingDetectionService');

// In route handler
const detectionResult = await sessionHijackingDetectionService.detectHijacking(
  req,
  session,
  user
);

if (detectionResult.hijackingDetected) {
  // Handle hijacking
}
```

## Configuration

### Environment Variables

```bash
# Recovery settings
RECOVERY_SESSION_DURATION=3600000  # 1 hour
RECOVERY_CODE_EXPIRY=600000        # 10 minutes
MAX_RECOVERY_ATTEMPTS=3

# Detection thresholds
MAX_TRAVEL_SPEED=900               # km/h
IMPOSSIBLE_TRAVEL_THRESHOLD=60     # minutes
BEHAVIORAL_ANOMALY_THRESHOLD=0.6
AUTO_LOCK_THRESHOLD=90             # risk score

# Notification settings
APP_URL=https://expenseflow.com
ENABLE_EMAIL_NOTIFICATIONS=true
ENABLE_PUSH_NOTIFICATIONS=true
```

### Service Configuration

Modify in service files:

```javascript
// sessionHijackingDetectionService.js
static config = {
  riskThresholds: {
    low: 25,
    medium: 50,
    high: 75,
    critical: 90
  },
  maxTravelSpeed: 900,
  impossibleTravelThreshold: 60,
  behavioralAnomalyThreshold: 0.6,
  fingerprintMatchThreshold: 0.8,
  simultaneousSessionWindow: 300000,
  minDistanceForSimultaneousCheck: 100,
  privilegeEscalationWindow: 3600000
};

// sessionHijackingRecoveryService.js
static config = {
  recoverySessionDuration: 3600000,
  maxRecoveryAttempts: 3,
  autoLockThreshold: 90,
  recoveryCodeLength: 6,
  recoveryCodeExpiry: 600000
};
```

## Security Considerations

### Data Privacy

1. **Sensitive Data Sanitization**
   - Passwords, tokens, API keys redacted
   - PII minimized in logs
   - Forensic data encrypted at rest

2. **Access Control**
   - Forensic reports restricted to event owner and admins
   - Recovery tokens single-use and time-limited
   - Step-up authentication required

3. **Audit Trail**
   - All containment actions logged
   - Recovery actions tracked
   - Immutable audit log for compliance

### Rate Limiting

Implement rate limiting on recovery endpoints:

```javascript
const rateLimit = require('express-rate-limit');

const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many recovery attempts'
});

router.post('/verify-step-up', recoveryLimiter, ...);
```

### Token Security

- Recovery tokens: 32-byte cryptographically secure random
- Challenge codes: SHA-256 hashed before storage
- Short expiration times (10 minutes for codes, 1 hour for sessions)
- One-time use where applicable

## Monitoring and Alerts

### Metrics to Track

1. **Detection Metrics**
   - Hijacking events per day/week/month
   - Detection method distribution
   - Average risk scores
   - False positive rate

2. **Recovery Metrics**
   - Recovery success rate
   - Average recovery time
   - Step-up authentication success rate
   - Actions performed during recovery

3. **Performance Metrics**
   - Detection middleware latency
   - Baseline establishment time
   - Forensic report generation time

### Admin Dashboard

Consider adding admin views for:
- Real-time hijacking alerts
- User recovery status
- Forensic report access
- False positive review
- Detection threshold tuning

## Testing

### Unit Tests

Test individual components:

```javascript
describe('SessionHijackingDetectionService', () => {
  it('should detect impossible travel', async () => {
    // Test implementation
  });

  it('should detect behavioral divergence', async () => {
    // Test implementation
  });
});
```

### Integration Tests

Test full detection and recovery flow:

```javascript
describe('Hijacking Detection Flow', () => {
  it('should detect, contain, and create recovery session', async () => {
    // Simulate hijacking
    // Verify containment
    // Check recovery session created
    // Verify user notification
  });
});
```

### Load Testing

Test performance under load:
- Behavioral profile updates with high request volume
- Detection performance with many concurrent sessions
- Recovery endpoint capacity

## Best Practices

1. **Baseline Establishment**
   - Allow sufficient samples before aggressive detection
   - Consider user type (power users vs. occasional)
   - Adjust thresholds based on false positive rates

2. **User Communication**
   - Clear, non-technical language in notifications
   - Provide context about detected threats
   - Offer easy recovery path

3. **False Positive Handling**
   - Allow users to report false positives
   - Learn from reported cases
   - Adjust detection algorithms

4. **Continuous Improvement**
   - Monitor detection accuracy
   - Analyze attack patterns
   - Update threat indicators
   - Refine risk scoring

## Troubleshooting

### Common Issues

**High False Positive Rate**
- Adjust baseline requirements
- Increase risk thresholds
- Review behavioral anomaly sensitivity

**Recovery Session Expiration**
- Increase session duration
- Allow session extension
- Provide clear time warnings

**Geolocation Accuracy**
- Use premium IP geolocation service
- Account for VPN/proxy usage
- Increase distance thresholds

## Future Enhancements

1. **Machine Learning Integration**
   - Train ML models on historical hijacking data
   - Improve detection accuracy
   - Reduce false positives

2. **User Risk Profiles**
   - Per-user risk tolerance
   - Adaptive thresholds
   - Historical behavior weighting

3. **Biometric Authentication**
   - Fingerprint/Face ID during recovery
   - Continuous authentication
   - Behavioral biometrics

4. **Federation Support**
   - Cross-service session validation
   - Shared threat intelligence
   - Coordinated containment

## Support and Maintenance

- **Documentation**: This guide + inline code comments
- **Support**: See CONTRIBUTING.md for issue reporting
- **Updates**: Check for security patches regularly
- **Community**: Contribute improvements via pull requests

## License

Part of ExpenseFlow - See LICENSE file for details

---

**Implementation Date**: March 2, 2026
**Issue**: #881
**Status**: ✅ Complete
