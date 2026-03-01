/**
 * SessionBehaviorSignal Model
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Records individual behavior and context signals for continuous trust evaluation.
 * Signals feed into the trust re-scoring engine.
 */

const mongoose = require('mongoose');

const SessionBehaviorSignalSchema = new mongoose.Schema({
  // Session & User
  sessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session',
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },

  // Signal Type
  signalType: {
    type: String,
    enum: [
      'ENDPOINT_ACCESS', // Sensitive endpoint accessed
      'REQUEST_CADENCE', // Request timing anomaly detected
      'GEO_DRIFT', // Geographic location changed significantly
      'USER_AGENT_CHANGE', // Browser/device mismatch
      'TOKEN_AGE', // Token age milestone
      'PRIVILEGE_ESCALATION', // User elevated privileges
      'PRIVILEGE_REVOCATION', // Privileges were revoked
      'FAILED_REAUTH', // Failed re-authentication attempt
      'SUCCESSFUL_REAUTH', // Successful re-authentication
      'IP_CHANGE', // IP address changed
      'KNOWN_THREAT', // Known threat indicator detected
      'ANOMALOUS_BEHAVIOR', // AI detected anomaly
      'DEVICE_MISMATCH', // Trusted device mismatch
      'VPN_DETECTION', // VPN/Proxy detected
      'BOT_DETECTION', // Bot-like behavior detected
    ],
    required: true,
    index: true
  },

  // Signal Severity
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    required: true,
  },

  // Trust Impact (-100 to +100)
  // Negative = decreases trust, Positive = increases trust
  trustImpact: {
    type: Number,
    min: -100,
    max: 100,
    required: true,
  },

  // Signal Details
  details: {
    // For ENDPOINT_ACCESS
    endpoint: String,
    method: String,
    sensitivity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    
    // For REQUEST_CADENCE
    requestsPerMinute: Number,
    previousAverageRequestsPerMinute: Number,
    deviationPercentage: Number, // How much deviation from baseline
    
    // For GEO_DRIFT
    previousLocation: {
      latitude: Number,
      longitude: Number,
      country: String,
      city: String,
    },
    currentLocation: {
      latitude: Number,
      longitude: Number,
      country: String,
      city: String,
    },
    distanceKm: Number,
    timeDifferenceSeconds: Number,
    maxPossibleDistanceKm: Number, // For impossible travel check
    
    // For USER_AGENT_CHANGE
    previousUserAgent: String,
    currentUserAgent: String,
    previousBrowser: String,
    currentBrowser: String,
    previousOS: String,
    currentOS: String,
    
    // For PRIVILEGE_ESCALATION
    previousRole: String,
    currentRole: String,
    escalationLevel: Number,
    
    // For TOKEN_AGE
    tokenAgeSeconds: Number,
    sessionStartedAt: Date,
    
    // For REAUTH_ATTEMPT
    attemptType: { type: String, enum: ['OTP', 'PASSWORD', 'BIOMETRIC', 'DEVICE'] },
    success: Boolean,
    delayMs: Number, // Time to complete challenge
    
    // For IP_CHANGE
    previousIP: String,
    currentIP: String,
    geoLocation: String,
    
    // For KNOWN_THREAT
    threatType: String, // 'IP_BLACKLIST', 'MALWARE', 'BOTNET', etc
    threatSource: String,
    threatConfidence: { type: Number, min: 0, max: 100 },
    
    // Generic context
    context: mongoose.Schema.Types.Mixed, // Flexible additional data
  },

  // Signal Confidence (0-100)
  // Higher = we're more certain about this signal
  confidence: {
    type: Number,
    min: 0,
    max: 100,
    default: 80,
  },

  // Impact Summary
  affectedComponents: [{
    // Which trust score components does this signal affect?
    component: {
      type: String,
      enum: [
        'endpointSensitivity',
        'requestCadence',
        'geoContext',
        'userAgentConsistency',
        'tokenAge',
        'privilegeTransition',
        'reAuth',
        'threatIndicator',
      ]
    },
    scoreAdjustment: { type: Number, min: -100, max: 100 },
  }],

  // Decision on this signal
  actionTaken: {
    type: String,
    enum: [
      'LOGGED_ONLY', // Just tracked, no action
      'INCREASED_MONITORING', // Raised monitoring level
      'CHALLENGE_ISSUED', // Challenge issued
      'SESSION_FLAGGED', // Session marked as anomalous
      'SESSION_TERMINATED', // Session killed
    ],
    default: 'LOGGED_ONLY',
  },

  // Was this a false positive?
  falsePositive: {
    type: Boolean,
    default: false,
    index: true,
  },
  falsePositiveConfirmedAt: Date,

  // Anomaly Score
  // Based on how unusual this signal is for this user
  anomalyScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 50,
    // 0-20: Normal, 20-40: Unusual, 40-70: Very Unusual, 70+: Highly Anomalous
  },

  // User Baseline Comparison
  deviationFromBaseline: {
    type: Number,
    min: 0,
    max: 200,
    // 100 = exactly baseline, 150 = significant deviation
  },

  // Timestamps
  detectedAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  processedAt: Date,
}, {
  timestamps: true,
  collection: 'session_behavior_signals',
});

// Indexes for querying and analysis
SessionBehaviorSignalSchema.index({ userId: 1, createdAt: -1 });
SessionBehaviorSignalSchema.index({ sessionId: 1, detectedAt: -1 });
SessionBehaviorSignalSchema.index({ signalType: 1, userId: 1 });
SessionBehaviorSignalSchema.index({ severity: 1, createdAt: -1 });
SessionBehaviorSignalSchema.index({ anomalyScore: 1, userId: 1 });
SessionBehaviorSignalSchema.index({ falsePositive: 1 });
SessionBehaviorSignalSchema.index({ actionTaken: 1, createdAt: -1 });

// Methods

/**
 * Check if this signal is anomalous for the user
 */
SessionBehaviorSignalSchema.methods.isAnomalous = function() {
  return this.anomalyScore >= 40;
};

/**
 * Check if this is a critical signal requiring immediate action
 */
SessionBehaviorSignalSchema.methods.isCritical = function() {
  return this.severity === 'CRITICAL' && this.confidence > 70;
};

/**
 * Mark as false positive
 */
SessionBehaviorSignalSchema.methods.markAsFalsePositive = function() {
  this.falsePositive = true;
  this.falsePositiveConfirmedAt = new Date();
  return this;
};

/**
 * Get signal explanation for UI/logging
 */
SessionBehaviorSignalSchema.methods.getExplanation = function() {
  const explanations = {
    ENDPOINT_ACCESS: `Accessed sensitive endpoint: ${this.details.endpoint}`,
    REQUEST_CADENCE: `Unusual request rate: ${this.details.requestsPerMinute} req/min (baseline: ${this.details.previousAverageRequestsPerMinute})`,
    GEO_DRIFT: `Location changed from ${this.details.previousLocation.city} to ${this.details.currentLocation.city} (${this.details.distanceKm}km in ${this.details.timeDifferenceSeconds}s)`,
    USER_AGENT_CHANGE: `Browser/device changed from ${this.details.previousBrowser} to ${this.details.currentBrowser}`,
    TOKEN_AGE: `Session token aged ${Math.round(this.details.tokenAgeSeconds / 3600)} hours`,
    PRIVILEGE_ESCALATION: `Privilege escalated from ${this.details.previousRole} to ${this.details.currentRole}`,
    PRIVILEGE_REVOCATION: `Privileges revoked: ${this.details.previousRole}`,
    FAILED_REAUTH: `Failed re-authentication attempt`,
    SUCCESSFUL_REAUTH: `Successful re-authentication via ${this.details.attemptType}`,
    IP_CHANGE: `IP address changed to ${this.details.currentIP}`,
    KNOWN_THREAT: `Known threat detected: ${this.details.threatType}`,
    ANOMALOUS_BEHAVIOR: `Anomalous behavior detected (score: ${this.anomalyScore})`,
    DEVICE_MISMATCH: `Device does not match trusted devices`,
    VPN_DETECTION: `VPN/Proxy usage detected`,
    BOT_DETECTION: `Bot-like behavior detected`,
  };

  return explanations[this.signalType] || 'Security signal detected';
};

/**
 * Recalculate anomaly score (for AI/ML updates)
 */
SessionBehaviorSignalSchema.methods.updateAnomalyScore = function(newScore) {
  const oldScore = this.anomalyScore;
  this.anomalyScore = Math.max(0, Math.min(100, newScore));
  this.processedAt = new Date();
  return this;
};

module.exports = mongoose.model('SessionBehaviorSignal', SessionBehaviorSignalSchema);
