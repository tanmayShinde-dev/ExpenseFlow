# Cross-Session Threat Correlation - Integration Examples

## Example 1: Basic Integration in Existing Route

### Before (No Correlation)
```javascript
const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');

router.get('/expenses', auth, async (req, res) => {
  const expenses = await Expense.find({ userId: req.user._id });
  res.json({ expenses });
});

module.exports = router;
```

### After (With Correlation)
```javascript
const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { correlationCheck } = require('../middleware/crossSessionCorrelation');

router.get('/expenses', auth, correlationCheck, async (req, res) => {
  const expenses = await Expense.find({ userId: req.user._id });
  res.json({ expenses });
});

module.exports = router;
```

## Example 2: Protecting High-Value Operations

### Wire Transfer Endpoint
```javascript
const { protectHighValueOperation } = require('../middleware/crossSessionCorrelation');

router.post('/transfer', 
  auth, 
  protectHighValueOperation,  // Blocks if user in active containment
  async (req, res) => {
    const { toAccount, amount } = req.body;
    
    // Process transfer
    const transfer = await processWireTransfer(
      req.user._id,
      toAccount,
      amount
    );
    
    res.json({ success: true, transfer });
  }
);
```

### Admin Permission Change
```javascript
const { protectEndpoint } = require('../middleware/crossSessionCorrelation');

router.post('/users/:id/change-role',
  auth,
  requireAdmin,
  protectEndpoint({
    requireNoCorrelation: true,  // No active clusters allowed
    maxSeverity: 'MODERATE'      // No HIGH/CRITICAL clusters
  }),
  async (req, res) => {
    const { role } = req.body;
    
    await User.findByIdAndUpdate(req.params.id, { role });
    
    res.json({ success: true });
  }
);
```

## Example 3: Custom Correlation Analysis

### Manual Correlation Check
```javascript
const crossSessionThreatCorrelationService = require('../services/crossSessionThreatCorrelationService');

router.post('/sensitive-operation', auth, async (req, res) => {
  // Perform manual correlation analysis
  const result = await crossSessionThreatCorrelationService.analyzeSession(
    req.session._id,
    req.user._id
  );
  
  if (result.correlated && result.severity === 'CRITICAL') {
    // Block operation
    return res.status(403).json({
      error: 'OPERATION_BLOCKED',
      message: 'Security correlation detected',
      clusterId: result.clusterId
    });
  }
  
  // Continue with operation
  await performSensitiveOperation(req.body);
  
  res.json({ success: true });
});
```

## Example 4: Trusted Relationship Management UI

### Frontend: Request Relationship
```javascript
async function requestTrustedRelationship(targetUserEmail) {
  const response = await fetch('/api/correlation/relationships/request', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      targetUserEmail,
      relationshipType: 'FAMILY',
      description: 'Family member - shared household',
      expiresInDays: 365
    })
  });
  
  const data = await response.json();
  
  if (data.success) {
    alert('Relationship request sent! Waiting for approval.');
  } else {
    alert(`Error: ${data.error}`);
  }
}
```

### Frontend: Approve Pending Relationship
```javascript
async function loadPendingApprovals() {
  const response = await fetch('/api/correlation/relationships/pending', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const data = await response.json();
  
  // Display pending approvals
  data.pendingApprovals.forEach(rel => {
    console.log(`${rel.userId1.username} wants to add you as ${rel.relationshipType}`);
    
    // Show approve/reject buttons
  });
}

async function approveRelationship(relationshipId) {
  const response = await fetch(`/api/correlation/relationships/${relationshipId}/approve`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const data = await response.json();
  
  if (data.success) {
    alert('Relationship approved!');
  }
}
```

## Example 5: User Status Dashboard

### Backend: User Status Endpoint
```javascript
router.get('/my-security-status', auth, async (req, res) => {
  // Get correlation status
  const correlationStatus = await fetch('/api/correlation/my-status', {
    headers: { 'Authorization': req.headers.authorization }
  }).then(r => r.json());
  
  // Get active containments
  const containments = correlationStatus.containments || [];
  
  // Get trusted relationships
  const relationships = await fetch('/api/correlation/relationships/my', {
    headers: { 'Authorization': req.headers.authorization }
  }).then(r => r.json());
  
  res.json({
    riskLevel: correlationStatus.status.riskLevel,
    activeClusters: correlationStatus.status.activeClusters,
    activeContainments: containments.length,
    trustedUsers: relationships.relationships.length,
    canAppeal: containments.some(c => c.canAppeal)
  });
});
```

### Frontend: Display Status
```javascript
async function loadSecurityStatus() {
  const response = await fetch('/api/my-security-status', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  const status = await response.json();
  
  // Update UI
  document.getElementById('risk-level').textContent = status.riskLevel;
  document.getElementById('active-clusters').textContent = status.activeClusters;
  
  if (status.riskLevel === 'CRITICAL') {
    document.getElementById('warning-banner').style.display = 'block';
    document.getElementById('warning-message').textContent = 
      'Your account is under security review. Some operations may be restricted.';
  }
  
  if (status.canAppeal) {
    document.getElementById('appeal-button').style.display = 'block';
  }
}
```

## Example 6: Analyst Dashboard

### Backend: Analyst Endpoints
```javascript
// Get pending containment approvals
router.get('/analyst/pending-approvals', 
  auth, 
  requireAnalyst, 
  async (req, res) => {
    const containments = await ContainmentAction.getPendingApprovals();
    
    // Enrich with cluster data
    for (const containment of containments) {
      const cluster = await SessionCorrelationCluster
        .findById(containment.clusterId)
        .populate('userIds', 'username email');
      
      containment.cluster = cluster;
    }
    
    res.json({ containments });
  }
);

// Approve containment
router.post('/analyst/containments/:id/approve',
  auth,
  requireAnalyst,
  async (req, res) => {
    const { notes } = req.body;
    
    const action = await containmentActionSystem.approveAction(
      req.params.id,
      req.user._id,
      notes
    );
    
    res.json({ success: true, action });
  }
);
```

### Frontend: Analyst Dashboard
```javascript
async function loadAnalystDashboard() {
  // Get pending approvals
  const response = await fetch('/api/analyst/pending-approvals', {
    headers: { 'Authorization': `Bearer ${analystToken}` }
  });
  
  const data = await response.json();
  
  // Display each pending containment
  data.containments.forEach(containment => {
    const item = document.createElement('div');
    item.className = `containment-item severity-${containment.severity}`;
    item.innerHTML = `
      <h4>${containment.actionType}</h4>
      <p>Affects ${containment.affectedUsers.length} users</p>
      <p>Cluster: ${containment.cluster.correlationType}</p>
      <p>Severity: ${containment.severity}</p>
      <p>Reason: ${containment.reason}</p>
      
      <button onclick="approveContainment('${containment._id}')">
        Approve
      </button>
      <button onclick="rejectContainment('${containment._id}')">
        Reject
      </button>
    `;
    
    document.getElementById('pending-list').appendChild(item);
  });
}

async function approveContainment(containmentId) {
  const notes = prompt('Enter approval notes:');
  
  const response = await fetch(`/api/analyst/containments/${containmentId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${analystToken}`
    },
    body: JSON.stringify({ notes })
  });
  
  if (response.ok) {
    alert('Containment approved!');
    loadAnalystDashboard(); // Refresh
  }
}
```

## Example 7: Webhook Notifications

### Configure Webhook for Correlation Events
```javascript
const axios = require('axios');

// In crossSessionThreatCorrelationService.js
async function sendWebhookNotification(event) {
  const webhookUrl = process.env.CORRELATION_WEBHOOK_URL;
  
  if (!webhookUrl) return;
  
  try {
    await axios.post(webhookUrl, {
      type: 'CORRELATION_DETECTED',
      severity: event.severity,
      correlationType: event.correlationType,
      affectedUsers: event.affectedUsers.length,
      timestamp: new Date().toISOString(),
      clusterId: event.clusterId
    });
  } catch (error) {
    console.error('Webhook notification failed:', error);
  }
}

// After creating cluster
const cluster = await SessionCorrelationCluster.create({ ... });
await sendWebhookNotification({
  severity: cluster.severity,
  correlationType: cluster.correlationType,
  affectedUsers: cluster.userIds,
  clusterId: cluster._id
});
```

## Example 8: Custom Containment Actions

### Add Custom Action Type
```javascript
// In containmentActionSystem.js

// Add to action types enum in ContainmentAction model
// CUSTOM_WEBHOOK: Trigger external webhook

async function executeCustomWebhook(metadata) {
  const { webhookUrl, payload } = metadata;
  
  await axios.post(webhookUrl, {
    ...payload,
    timestamp: new Date().toISOString()
  });
  
  return {
    webhookTriggered: true,
    webhookUrl
  };
}

// In executeAction method
case 'CUSTOM_WEBHOOK':
  executionDetails = await this.executeCustomWebhook(action.metadata);
  break;
```

## Example 9: Rate Limiting Based on Correlation Status

### Adjust Rate Limits by Risk Level
```javascript
const { correlationBasedRateLimit } = require('../middleware/crossSessionCorrelation');

// Apply correlation-aware rate limiting
app.use('/api/data', 
  auth,
  addCorrelationContext,
  correlationBasedRateLimit(100),  // Base limit: 100 req/min
  dataRoutes
);

// Users with:
// - LOW risk: 100 req/min
// - MODERATE risk: 50 req/min
// - HIGH risk: 25 req/min
// - CRITICAL risk: 10 req/min
```

## Example 10: Batch Correlation Analysis

### Nightly Batch Processing
```javascript
// scripts/batch-correlation-analysis.js

const crossSessionThreatCorrelationService = require('./services/crossSessionThreatCorrelationService');
const Session = require('./models/Session');

async function batchAnalyzeAllSessions() {
  console.log('Starting batch correlation analysis...');
  
  // Get all active sessions from last 24 hours
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const sessions = await Session.find({
    createdAt: { $gte: cutoff },
    isActive: true
  });
  
  console.log(`Analyzing ${sessions.length} sessions...`);
  
  let correlationsFound = 0;
  
  for (const session of sessions) {
    try {
      const result = await crossSessionThreatCorrelationService.analyzeSession(
        session._id,
        session.userId
      );
      
      if (result.correlated) {
        correlationsFound++;
        console.log(`Correlation found: ${result.correlationType} (${result.severity})`);
      }
    } catch (error) {
      console.error(`Error analyzing session ${session._id}:`, error);
    }
  }
  
  console.log(`Batch analysis complete. Found ${correlationsFound} correlations.`);
}

// Run if called directly
if (require.main === module) {
  mongoose.connect(process.env.MONGODB_URI)
    .then(() => batchAnalyzeAllSessions())
    .then(() => process.exit(0))
    .catch(err => {
      console.error('Batch analysis failed:', err);
      process.exit(1);
    });
}

module.exports = { batchAnalyzeAllSessions };
```

### Schedule with Cron
```javascript
// In server.js or cronJobs.js

const cron = require('node-cron');
const { batchAnalyzeAllSessions } = require('./scripts/batch-correlation-analysis');

// Run every night at 2 AM
cron.schedule('0 2 * * *', async () => {
  console.log('Running scheduled correlation analysis...');
  await batchAnalyzeAllSessions();
});
```

## Example 11: Integration with Notification System

### Send Email When Correlation Detected
```javascript
const nodemailer = require('nodemailer');

async function notifyUserOfCorrelation(userId, cluster) {
  const user = await User.findById(userId);
  
  const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
  
  await transporter.sendMail({
    from: 'security@expenseflow.com',
    to: user.email,
    subject: 'Security Alert: Unusual Activity Detected',
    html: `
      <h2>Security Alert</h2>
      <p>We detected unusual activity on your account.</p>
      <p><strong>Type:</strong> ${cluster.correlationType}</p>
      <p><strong>Severity:</strong> ${cluster.severity}</p>
      <p><strong>Time:</strong> ${cluster.firstDetected}</p>
      
      <p>If this was you, no action is needed. Otherwise, please:</p>
      <ul>
        <li>Change your password immediately</li>
        <li>Review your account activity</li>
        <li>Contact support if you need assistance</li>
      </ul>
      
      <a href="${process.env.FRONTEND_URL}/security/appeal/${cluster._id}">
        Appeal This Alert
      </a>
    `
  });
}

// In crossSessionThreatCorrelationService.js, after creating cluster:
for (const userId of cluster.userIds) {
  await notifyUserOfCorrelation(userId, cluster);
}
```

## Example 12: Testing & Simulation

### Simulate Coordinated Attack
```javascript
// tests/simulate-coordinated-attack.js

const { createTestUsers, createTestSessions } = require('./test-helpers');

async function simulateIPBasedAttack() {
  // Create 5 test users
  const users = await createTestUsers(5);
  
  // Create sessions for all users from same IP
  const maliciousIP = '203.0.113.42';
  
  for (const user of users) {
    await Session.create({
      userId: user._id,
      ip: maliciousIP,
      deviceFingerprint: `device_${user._id}`,
      userAgent: 'Mozilla/5.0...',
      isActive: true
    });
  }
  
  // Trigger correlation analysis
  const result = await crossSessionThreatCorrelationService.analyzeSession(
    sessions[0]._id,
    users[0]._id
  );
  
  console.log('Simulation result:', result);
  console.log('Expected: IP-based correlation should be detected');
  
  // Verify cluster was created
  const cluster = await SessionCorrelationCluster.findOne({
    correlationType: 'IP_BASED',
    'indicators.ip': maliciousIP
  });
  
  expect(cluster).toBeDefined();
  expect(cluster.userIds).toHaveLength(5);
  expect(cluster.severity).toBe('HIGH');
}
```

---

## Additional Resources

- [Full Documentation](./ISSUE_879_IMPLEMENTATION_SUMMARY.md)
- [Quick Start Guide](./CROSS_SESSION_CORRELATION_QUICKSTART.md)
- [API Reference](./API_DOCUMENTATION.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)

**Last Updated**: 2024
**Version**: 1.0.0
