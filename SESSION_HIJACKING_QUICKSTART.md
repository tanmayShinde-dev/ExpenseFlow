# Session Hijacking Prevention & Recovery - Quick Start Guide
## Issue #881

## Installation & Setup

### 1. Install Dependencies

```bash
npm install geolib@^3.3.4
```

Note: If you don't have `ioredis` already, install it:
```bash
npm install ioredis@^5.3.2
```

### 2. Environment Variables (Optional)

Add to your `.env` file:

```bash
# Session Hijacking Detection Settings
MAX_TRAVEL_SPEED=900
IMPOSSIBLE_TRAVEL_THRESHOLD=60
BEHAVIORAL_ANOMALY_THRESHOLD=0.6
AUTO_LOCK_THRESHOLD=90

# Recovery Session Settings
RECOVERY_SESSION_DURATION=3600000
RECOVERY_CODE_EXPIRY=600000
MAX_RECOVERY_ATTEMPTS=3

# Application URL (for recovery emails)
APP_URL=http://localhost:3000

# Geolocation API (optional - uses free ip-api.com by default)
# GEO_API_KEY=your_api_key_here
```

### 3. Database Setup

The system uses MongoDB and will automatically create the required collections:
- `sessionhijackingevents`
- `recoverysessions`
- `sessionbehaviorprofiles`
- `devicefingerprints` (enhanced)

**No migration required** - models will auto-create on first use.

### 4. Start the Server

```bash
npm start
# or for development
npm run dev
```

The following will be automatically initialized:
✓ Session hijacking detection service
✓ Behavior profiling system
✓ Recovery route handlers
✓ Detection middleware on protected routes

### 5. Verify Installation

Check server logs for:
```
✓ Session hijacking detection initialized
```

Test the system:
1. Log in to the application
2. Try accessing protected routes
3. Check that behavioral baseline is being established

## Usage

### For Developers

#### Apply Detection to New Routes

```javascript
const sessionHijackingMiddleware = require('./middleware/sessionHijackingDetection');

// Apply to specific route
router.get('/api/sensitive-data',
  auth,
  sessionHijackingMiddleware.detectAndContain,
  (req, res) => {
    // Your handler
  }
);

// Apply data access auditing
router.post('/api/financial-records',
  auth,
  sessionHijackingMiddleware.auditDataAccess('financial-records', 'WRITE'),
  (req, res) => {
    // Your handler
  }
);
```

#### Manual Detection

```javascript
const sessionHijackingDetectionService = require('./services/sessionHijackingDetectionService');

// In your route handler
const detectionResult = await sessionHijackingDetectionService.detectHijacking(
  req,
  session,
  user
);

if (detectionResult.hijackingDetected) {
  // Handle hijacking
  const event = await sessionHijackingDetectionService.createHijackingEvent(
    detectionResult,
    session,
    req
  );
  
  // Execute containment
  await sessionHijackingRecoveryService.executeContainment(event, session);
}
```

### For Users

#### Recovery Process

1. **Detection**: If suspicious activity is detected, your session will be terminated and you'll receive:
   - Email notification with recovery link
   - In-app alert (if still connected)
   - Push notification (if enabled)

2. **Access Recovery Page**:
   - Click link in email
   - Or navigate to: `https://yourapp.com/auth/recovery?token=<TOKEN>`

3. **Verify Identity**:
   - Enter 6-digit code sent to your email
   - Or use your 2FA authenticator app
   - Or use backup code

4. **Secure Your Account**:
   - Change your password (mandatory)
   - Revoke all active sessions (recommended)
   - Enable 2FA (strongly recommended)
   - Review security log

5. **Complete Recovery**:
   - Click "Complete Recovery"
   - You'll be redirected to dashboard
   - New secure session created

## Testing

### Test Detection Locally

#### Simulate Behavioral Anomaly

```javascript
// Make rapid requests from different endpoints
for (let i = 0; i < 60; i++) {
  await fetch('/api/random-endpoint-' + i);
  await delay(100); // Very rapid
}
```

#### Simulate Device Swap

```javascript
// Change device fingerprint mid-session
// Send request with different X-Device-Fingerprint header
fetch('/api/expenses', {
  headers: {
    'Authorization': 'Bearer <token>',
    'X-Device-Fingerprint': 'different-fingerprint-123'
  }
});
```

#### Test Recovery Flow

1. Manually create a hijacking event:
```javascript
const SessionHijackingEvent = require('./models/SessionHijackingEvent');
const event = await SessionHijackingEvent.createEvent({
  userId: user._id,
  sessionId: session._id,
  detectionMethod: 'TEST',
  riskScore: 85,
  indicators: [{
    type: 'TEST_INDICATOR',
    severity: 'high',
    riskScore: 85
  }]
});
```

2. Create recovery session:
```javascript
const sessionHijackingRecoveryService = require('./services/sessionHijackingRecoveryService');
await sessionHijackingRecoveryService.executeContainment(event, session);
```

3. Access recovery page with token from email

### Integration Tests

```javascript
describe('Session Hijacking Detection', () => {
  it('should detect behavioral divergence', async () => {
    // Establish baseline
    for (let i = 0; i < 50; i++) {
      await request(app)
        .get('/api/expenses')
        .set('Authorization', `Bearer ${token}`);
      await delay(1000); // Normal cadence
    }
    
    // Make anomalous requests
    for (let i = 0; i < 10; i++) {
      await request(app)
        .get('/api/admin/users') // Unusual endpoint
        .set('Authorization', `Bearer ${token}`)
        .expect(403); // Should be blocked
    }
  });
});
```

## Monitoring

### Check Detection Events

```javascript
// Get recent hijacking events
const events = await SessionHijackingEvent.find()
  .sort({ detectedAt: -1 })
  .limit(10);

console.log('Recent hijacking events:', events);
```

### View User's Recovery History

```javascript
const userEvents = await SessionHijackingEvent.getUserHistory(userId);
console.log('User hijacking history:', userEvents);
```

### Monitor Behavioral Profiles

```javascript
// Get session behavior profile
const profile = await SessionBehaviorProfile.findOne({ sessionId });
console.log('Baseline established:', profile.baseline.established);
console.log('Total requests:', profile.requestPatterns.totalRequests);
console.log('Activity level:', profile.activityProfile.level);
```

## Configuration

### Adjust Detection Sensitivity

Edit `services/sessionHijackingDetectionService.js`:

```javascript
static config = {
  // Increase for less sensitive detection
  riskThresholds: {
    low: 30,      // Was 25
    medium: 55,   // Was 50
    high: 80,     // Was 75
    critical: 95  // Was 90
  },
  
  // Increase for fewer travel alerts
  maxTravelSpeed: 1200, // Was 900
  
  // Increase for less sensitive behavioral detection
  behavioralAnomalyThreshold: 0.75 // Was 0.6
};
```

### Adjust Recovery Settings

Edit `services/sessionHijackingRecoveryService.js`:

```javascript
static config = {
  // Increase for longer recovery window
  recoverySessionDuration: 7200000, // 2 hours instead of 1
  
  // Increase for more verification attempts
  maxRecoveryAttempts: 5, // Was 3
  
  // Adjust auto-lock threshold
  autoLockThreshold: 95 // Was 90
};
```

## Troubleshooting

### Issue: High False Positive Rate

**Symptom**: Legitimate users getting locked out frequently

**Solutions**:
1. Increase risk thresholds
2. Adjust behavioral anomaly threshold
3. Increase baseline requirement (change `requiredSamples` in model)
4. Review geolocation accuracy (VPN users may trigger alerts)

### Issue: Detection Not Working

**Symptoms**: No events being created

**Checks**:
1. Verify middleware is applied: Check server logs for initialization message
2. Check if baseline is established: Requires 50 requests minimum
3. Verify session exists: Detection only works for authenticated sessions
4. Check MongoDB connection: Models must be properly initialized

### Issue: Recovery Emails Not Sending

**Symptoms**: Users not receiving recovery codes

**Checks**:
1. Verify email service is configured (`emailService`)
2. Check SMTP settings in `.env`
3. Review email logs in console
4. Test email service independently

### Issue: Geolocation Errors

**Symptoms**: Location detection failing

**Solutions**:
1. Check IP address format (IPv4 vs IPv6)
2. Verify external IP API is accessible
3. Use premium geolocation service for better accuracy
4. Configure fallback options

## Performance Tuning

### Database Indexes

Indexes are automatically created, but verify:

```javascript
// Check indexes
db.sessionhijackingevents.getIndexes()
db.sessionbehaviorprofiles.getIndexes()
db.recoverysessions.getIndexes()
```

### Caching

Consider caching:
- Geolocation results for IPs
- Behavioral profiles (already in-memory)
- Device fingerprints

### Rate Limiting

Apply rate limiting to recovery endpoints:

```javascript
const rateLimit = require('express-rate-limit');

const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

app.use('/api/session-recovery', recoveryLimiter);
```

## Security Best Practices

1. **Always use HTTPS in production**
2. **Enable 2FA for all users**
3. **Regularly review false positives**
4. **Monitor detection metrics**
5. **Keep dependencies updated**
6. **Review forensic reports periodically**
7. **Train users on security awareness**

## Next Steps

1. ✅ Install dependencies
2. ✅ Configure environment variables
3. ✅ Start server and verify initialization
4. ✅ Test detection in development
5. ✅ Test recovery flow
6. ✅ Monitor initial detection events
7. ✅ Tune thresholds based on data
8. ✅ Deploy to production
9. ✅ Set up monitoring and alerts
10. ✅ Train support team on recovery process

## Support

For issues or questions:
- Check full documentation: `SESSION_HIJACKING_PREVENTION_DOCUMENTATION.md`
- Review implementation summary: `ISSUE_881_IMPLEMENTATION_SUMMARY.md`
- Open GitHub issue with logs and details

## Additional Resources

- [OWASP Session Management](https://owasp.org/www-community/controls/Session_Management_Cheat_Sheet)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ExpenseFlow Security Documentation](SECURITY_IMPLEMENTATION.md)

---

**Quick Start Complete!** Your Session Hijacking Prevention & Recovery system is ready to protect your users.
