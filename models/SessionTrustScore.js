/**
 * SessionTrustScore Model
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Tracks continuous trust evaluation throughout session lifecycle.
 * Maintains current trust score and historical scoring data.
 */

const mongoose = require('mongoose');

const SessionTrustScoreSchema = new mongoose.Schema({
  // Session Reference
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

  // Current Trust State
  currentTrustScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 100,
    required: true,
    // 90-100: NORMAL (green)
    // 70-89: MONITORED (yellow)  
    // 40-69: CHALLENGED (orange)
    // <40: TERMINATED (red)
  },
  currentEnforcementTier: {
    type: String,
    enum: ['NORMAL', 'MONITORED', 'CHALLENGED', 'TERMINATED'],
    default: 'NORMAL',
    required: true,
    index: true
  },

  // Trust Score Components (weighted)
  components: {
    endpointSensitivityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Risk based on endpoint access patterns
    },
    requestCadenceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Anomaly based on request timing deviation
    },
    geoContextScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Risk based on geographic anomalies
    },
    userAgentConsistencyScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Browser/device consistency check
    },
    tokenAgeScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Age of session token (newer = higher trust)
    },
    privilegeTransitionScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Risk based on privilege escalation patterns
    },
    reAuthScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Failed attempts and successful re-auth
    },
    threatIndicatorScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
      // Known threat indicators (IP blacklist, etc.)
    },
  },

  // Component Weights (sum = 100)
  weights: {
    endpointSensitivity: { type: Number, default: 15 },
    requestCadence: { type: Number, default: 12 },
    geoContext: { type: Number, default: 18 },
    userAgentConsistency: { type: Number, default: 10 },
    tokenAge: { type: Number, default: 15 },
    privilegeTransition: { type: Number, default: 12 },
    reAuth: { type: Number, default: 10 },
    threatIndicator: { type: Number, default: 8 },
  },

  // Confidence Level in the Score
  confidenceLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH'],
    default: 'MEDIUM',
    // LOW: <3 data points, HIGH: >10 data points
  },
  dataPointCount: {
    type: Number,
    default: 0,
    // Number of signals used in current score
  },

  // Fraud/Anomaly Indicators
  flaggedAsAnomalous: {
    type: Boolean,
    default: false,
    index: true
  },
  anomalyReasons: [{
    reason: String, // e.g., "impossible_travel", "unusual_privilege_access"
    severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    detectedAt: { type: Date, default: Date.now },
  }],

  // Re-Authentication History
  reAuthAttempts: {
    failed: { type: Number, default: 0 },
    successful: { type: Number, default: 0 },
    lastAttemptAt: Date,
    lastFailureAt: Date,
  },

  // Tier Transition History
  tierTransitions: [{
    fromTier: { type: String, enum: ['NORMAL', 'MONITORED', 'CHALLENGED', 'TERMINATED'] },
    toTier: { type: String, enum: ['NORMAL', 'MONITORED', 'CHALLENGED', 'TERMINATED'] },
    reason: String, // Why transition happened
    trustScoreAtTransition: Number,
    transitionAt: { type: Date, default: Date.now },
  }],

  // Challenge Status
  activeChallengeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SessionChallenge',
  },
  lastChallengeAt: Date,
  challengeCount: { type: Number, default: 0 },
  lastChallengeResponse: {
    success: Boolean,
    respondedAt: Date,
    delayMs: Number, // Time to respond
  },

  // Monitoring & Signals
  isUnderMonitoring: {
    type: Boolean,
    default: false,
  },
  monitoringStartedAt: Date,
  signalCollectionInterval: {
    type: Number,
    default: 30000, // 30 seconds (milliseconds)
  },

  // Baseline Comparison (user-specific adaptation)
  userBaselineDeviation: {
    type: Number,
    min: 0,
    max: 200,
    // 100 = normal baseline, >100 = deviation from baseline
  },

  // Lifecycle
  sessionInitiatedAt: Date,
  lastScoringAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  nextScoringScheduledAt: Date,
  terminatedAt: {
    type: Date,
    sparse: true,
  },
  terminationReason: {
    type: String,
    enum: [
      'TRUST_SCORE_BELOW_THRESHOLD',
      'MANUAL_TERMINATION',
      'UNRECOVERABLE_COMPROMISE',
      'SESSION_EXPIRED',
      'USER_LOGOUT',
    ],
  },

  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  collection: 'session_trust_scores',
});

// Indexes for performance
SessionTrustScoreSchema.index({ userId: 1, createdAt: -1 });
SessionTrustScoreSchema.index({ currentEnforcementTier: 1, userId: 1 });
SessionTrustScoreSchema.index({ flaggedAsAnomalous: 1, createdAt: -1 });
SessionTrustScoreSchema.index({ lastScoringAt: 1 }); // For scheduling
SessionTrustScoreSchema.index({ nextScoringScheduledAt: 1 }); // For background tasks
SessionTrustScoreSchema.index({ sessionId: 1, currentEnforcementTier: 1 });

// Methods

/**
 * Calculate composite trust score from components
 */
SessionTrustScoreSchema.methods.calculateCompositeScore = function() {
  const components = this.components;
  const weights = this.weights;

  let score = 0;
  score += components.endpointSensitivityScore * (weights.endpointSensitivity / 100);
  score += components.requestCadenceScore * (weights.requestCadence / 100);
  score += components.geoContextScore * (weights.geoContext / 100);
  score += components.userAgentConsistencyScore * (weights.userAgentConsistency / 100);
  score += components.tokenAgeScore * (weights.tokenAge / 100);
  score += components.privilegeTransitionScore * (weights.privilegeTransition / 100);
  score += components.reAuthScore * (weights.reAuth / 100);
  score += components.threatIndicatorScore * (weights.threatIndicator / 100);

  return Math.round(score);
};

/**
 * Get enforcement tier based on trust score
 */
SessionTrustScoreSchema.methods.getEnforcementTier = function(trustScore) {
  if (trustScore >= 90) return 'NORMAL';
  if (trustScore >= 70) return 'MONITORED';
  if (trustScore >= 40) return 'CHALLENGED';
  return 'TERMINATED';
};

/**
 * Update trust score and enforcement tier
 */
SessionTrustScoreSchema.methods.updateScore = function(newComponents, newAnomalies = []) {
  // Update components
  Object.assign(this.components, newComponents);

  // Recalculate composite score
  this.currentTrustScore = this.calculateCompositeScore();

  // Get new enforcement tier
  const newTier = this.getEnforcementTier(this.currentTrustScore);

  // Record transition if tier changed
  if (newTier !== this.currentEnforcementTier) {
    this.tierTransitions.push({
      fromTier: this.currentEnforcementTier,
      toTier: newTier,
      reason: `Score dropped to ${this.currentTrustScore}`,
      trustScoreAtTransition: this.currentTrustScore,
      transitionAt: new Date(),
    });
  }

  this.currentEnforcementTier = newTier;

  // Update anomalies
  if (newAnomalies.length > 0) {
    this.flaggedAsAnomalous = true;
    this.anomalyReasons.push(...newAnomalies.map(reason => ({
      reason,
      severity: 'HIGH',
      detectedAt: new Date(),
    })));
  }

  this.lastScoringAt = new Date();
  this.updatedAt = new Date();

  return this;
};

/**
 * Check if session should be terminated
 */
SessionTrustScoreSchema.methods.shouldTerminate = function() {
  return this.currentTrustScore < 40 || this.currentEnforcementTier === 'TERMINATED';
};

/**
 * Record failed re-authentication attempt
 */
SessionTrustScoreSchema.methods.recordFailedReAuth = function() {
  this.reAuthAttempts.failed++;
  this.reAuthAttempts.lastFailureAt = new Date();
  
  // Penalize re-auth score
  this.components.reAuthScore = Math.max(0, this.components.reAuthScore - 15);
  
  return this;
};

/**
 * Record successful re-authentication
 */
SessionTrustScoreSchema.methods.recordSuccessfulReAuth = function() {
  this.reAuthAttempts.successful++;
  this.reAuthAttempts.lastAttemptAt = new Date();
  
  // Restore some re-auth score
  this.components.reAuthScore = Math.min(100, this.components.reAuthScore + 10);
  
  return this;
};

/**
 * Check if challenge response was fast (anti-friction)
 */
SessionTrustScoreSchema.methods.wasChallengeResponseFast = function(delayMs = 0) {
  // Response within 2 seconds is considered normal
  return delayMs < 2000;
};

/**
 * Get trust explanation for UI
 */
SessionTrustScoreSchema.methods.getTrustExplanation = function() {
  const tier = this.currentEnforcementTier;
  const score = this.currentTrustScore;

  let explanation = '';
  switch (tier) {
    case 'NORMAL':
      explanation = 'Your session is trusted. Continue as normal.';
      break;
    case 'MONITORED':
      explanation = 'Your session is being monitored for security.';
      break;
    case 'CHALLENGED':
      explanation = 'Additional verification required.';
      break;
    case 'TERMINATED':
      explanation = 'Session terminated due to security concerns.';
      break;
  }

  return {
    tier,
    score,
    explanation,
    next_action: tier === 'CHALLENGED' ? 'CHALLENGE_REQUIRED' : 'CONTINUE',
  };
};

module.exports = mongoose.model('SessionTrustScore', SessionTrustScoreSchema);
