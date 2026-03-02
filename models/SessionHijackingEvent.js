const mongoose = require('mongoose');

/**
 * Session Hijacking Event Model
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Tracks detected session hijacking attempts with detailed forensics data
 */

const sessionHijackingEventSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  sessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session',
    required: true,
    index: true
  },
  // Detection metadata
  detectedAt: {
    type: Date,
    default: Date.now,
    required: true,
    index: true
  },
  detectionMethod: {
    type: String,
    enum: [
      'BEHAVIORAL_DIVERGENCE',
      'IMPOSSIBLE_LOCATION',
      'DEVICE_FINGERPRINT_SWAP',
      'PRIVILEGE_ESCALATION',
      'REQUEST_PATTERN_ANOMALY',
      'SIMULTANEOUS_SESSIONS',
      'VELOCITY_ANOMALY',
      'COMBINED_SIGNALS'
    ],
    required: true
  },
  // Hijacking indicators
  indicators: [{
    type: {
      type: String,
      enum: [
        'REQUEST_CADENCE_CHANGE',
        'ENDPOINT_PATTERN_CHANGE',
        'IMPOSSIBLE_TRAVEL',
        'DEVICE_SWAP',
        'IP_CHANGE',
        'USER_AGENT_CHANGE',
        'PRIVILEGE_ESCALATION',
        'SUSPICIOUS_ENDPOINT_ACCESS',
        'RAPID_ACTIONS',
        'GEOGRAPHIC_IMPOSSIBLE'
      ]
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    },
    riskScore: Number,
    details: mongoose.Schema.Types.Mixed,
    timestamp: Date
  }],
  // Risk assessment
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  confidenceLevel: {
    type: Number,
    min: 0,
    max: 1,
    default: 0
  },
  // Session data before hijacking
  originalSession: {
    ipAddress: String,
    userAgent: String,
    deviceFingerprint: String,
    location: {
      country: String,
      city: String,
      latitude: Number,
      longitude: Number
    },
    lastSeenAt: Date,
    requestPattern: {
      avgCadence: Number, // milliseconds between requests
      topEndpoints: [String],
      activityLevel: String
    }
  },
  // Suspicious session data
  suspiciousSession: {
    ipAddress: String,
    userAgent: String,
    deviceFingerprint: String,
    location: {
      country: String,
      city: String,
      latitude: Number,
      longitude: Number
    },
    firstSeenAt: Date,
    requestPattern: {
      cadence: Number,
      endpoints: [String],
      activityLevel: String
    },
    privilegeEscalation: {
      attempted: Boolean,
      endpoint: String,
      timestamp: Date
    }
  },
  // Behavioral divergence metrics
  behavioralMetrics: {
    requestCadenceDelta: Number, // % change
    endpointDivergenceScore: Number,
    activityLevelChange: Number,
    timeSinceLastSeen: Number, // milliseconds
    distanceTraveled: Number, // kilometers
    travelSpeed: Number // km/h
  },
  // Containment actions
  containment: {
    executed: {
      type: Boolean,
      default: false
    },
    executedAt: Date,
    actions: [{
      action: {
        type: String,
        enum: [
          'SESSION_KILLED',
          'USER_NOTIFIED',
          'ADMIN_ALERTED',
          'ACCOUNT_LOCKED',
          'RECOVERY_SESSION_CREATED',
          'TWO_FACTOR_ENFORCED',
          'PASSWORD_RESET_REQUIRED'
        ]
      },
      timestamp: Date,
      success: Boolean,
      details: mongoose.Schema.Types.Mixed
    }],
    containedBy: {
      type: String,
      enum: ['AUTOMATED', 'ADMIN', 'USER'],
      default: 'AUTOMATED'
    }
  },
  // Recovery process
  recovery: {
    initiated: {
      type: Boolean,
      default: false
    },
    initiatedAt: Date,
    recoverySessionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'RecoverySession'
    },
    stepUpChallengeCompleted: {
      type: Boolean,
      default: false
    },
    stepUpMethod: String, // '2FA', 'EMAIL_CODE', 'SMS_CODE'
    stepUpCompletedAt: Date,
    restored: {
      type: Boolean,
      default: false
    },
    restoredAt: Date,
    timeWindow: Number, // milliseconds until recovery expires
    expiresAt: Date
  },
  // User response
  userResponse: {
    acknowledged: {
      type: Boolean,
      default: false
    },
    acknowledgedAt: Date,
    actionTaken: {
      type: String,
      enum: ['RECOVERED', 'IGNORED', 'REPORTED_FALSE_POSITIVE', 'CHANGED_PASSWORD', 'CONTACTED_SUPPORT']
    },
    feedback: String
  },
  // Forensics
  forensics: {
    sessionReplayAvailable: {
      type: Boolean,
      default: false
    },
    requestLog: [{
      timestamp: Date,
      method: String,
      endpoint: String,
      statusCode: Number,
      responseTime: Number,
      ipAddress: String,
      userAgent: String
    }],
    dataAccessLog: [{
      timestamp: Date,
      resource: String,
      action: String,
      recordIds: [String],
      sensitive: Boolean
    }],
    forensicAnalysisCompleted: {
      type: Boolean,
      default: false
    },
    forensicReport: String
  },
  // Status
  status: {
    type: String,
    enum: [
      'DETECTED',
      'CONTAINED',
      'UNDER_INVESTIGATION',
      'RECOVERED',
      'FALSE_POSITIVE',
      'CONFIRMED_ATTACK',
      'CLOSED'
    ],
    default: 'DETECTED',
    index: true
  },
  // Resolution
  resolution: {
    resolvedAt: Date,
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    outcome: String,
    notes: String
  }
}, {
  timestamps: true
});

// Indexes for performance
sessionHijackingEventSchema.index({ userId: 1, detectedAt: -1 });
sessionHijackingEventSchema.index({ sessionId: 1, status: 1 });
sessionHijackingEventSchema.index({ riskScore: -1, detectedAt: -1 });
sessionHijackingEventSchema.index({ 'containment.executed': 1, status: 1 });

// Static method to create hijacking event
sessionHijackingEventSchema.statics.createEvent = async function(data) {
  const event = new this(data);
  await event.save();
  return event;
};

// Instance method to execute containment
sessionHijackingEventSchema.methods.executeContainment = async function(actions) {
  this.containment.executed = true;
  this.containment.executedAt = new Date();
  this.containment.actions = actions;
  this.status = 'CONTAINED';
  await this.save();
  return this;
};

// Instance method to initiate recovery
sessionHijackingEventSchema.methods.initiateRecovery = async function(recoverySessionId, timeWindow = 3600000) {
  this.recovery.initiated = true;
  this.recovery.initiatedAt = new Date();
  this.recovery.recoverySessionId = recoverySessionId;
  this.recovery.timeWindow = timeWindow;
  this.recovery.expiresAt = new Date(Date.now() + timeWindow);
  await this.save();
  return this;
};

// Instance method to complete recovery
sessionHijackingEventSchema.methods.completeRecovery = async function() {
  this.recovery.restored = true;
  this.recovery.restoredAt = new Date();
  this.status = 'RECOVERED';
  await this.save();
  return this;
};

// Static method to get user's hijacking history
sessionHijackingEventSchema.statics.getUserHistory = async function(userId, limit = 10) {
  return this.find({ userId })
    .sort({ detectedAt: -1 })
    .limit(limit)
    .populate('sessionId')
    .populate('recovery.recoverySessionId');
};

module.exports = mongoose.model('SessionHijackingEvent', sessionHijackingEventSchema);
