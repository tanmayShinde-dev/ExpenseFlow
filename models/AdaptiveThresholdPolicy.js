/**
 * AdaptiveThresholdPolicy Model
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Manages user-specific adaptive thresholds to reduce false positives.
 * Learns baseline behavior and adjusts enforcement sensitivity accordingly.
 */

const mongoose = require('mongoose');

const AdaptiveThresholdPolicySchema = new mongoose.Schema({
  // User Reference
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },

  // Baseline Behavior Profile
  baselineProfile: {
    // Geographic baseline
    primaryCountries: [String], // Most common access locations
    primaryCities: [String],
    usualTimezoneOffset: Number,
    timezoneVariance: { type: Number, default: 2 }, // Hours deviation acceptable

    // Temporal baseline
    usualActiveHours: {
      start: Number, // 0-23 (UTC)
      end: Number,
    },
    usualDaysOfWeek: [Number], // 0-6 (Sunday-Saturday)
    weekdayActiveHours: { start: Number, end: Number },
    weekendActiveHours: { start: Number, end: Number },

    // Device baseline
    trustedDevices: [String], // Device fingerprints
    usualBrowsers: [String],
    usualOS: [String],
    usualUserAgents: [String],

    // Request pattern baseline
    averageRequestsPerMinute: {
      type: Number,
      default: 5,
    },
    averageRequestsPerHour: {
      type: Number,
      default: 300,
    },
    requestCadenceDeviation: {
      type: Number,
      default: 0.3, // 30% deviation acceptable
    },

    // Privilege baseline
    usualRoles: [String], // Typical roles for this user
    maxPrivilegeLevel: String, // Highest privilege ever accessed
    privilegeEscalationFrequency: Number, // Escalations per month

    // Network baseline
    usualIPs: [String], // Most common IPs
    usualISPs: [String],
    vpnUsageNormal: { type: Boolean, default: false },

    // Behavioral baseline
    usualEndpoints: [String], // Most accessed endpoints
    endpointAccessPattern: mongoose.Schema.Types.Mixed, // Frequency of each endpoint

    // Data
    baselineCalculatedAt: Date,
    dataPointsCollected: { type: Number, default: 0 },
    learningPeriodDays: { type: Number, default: 30 },
  },

  // Sensitivity Levels (per component)
  componentThresholds: {
    endpointSensitivity: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      criticalEndpointPenalty: { type: Number, default: 25 }, // -25 score on critical access
      unknownEndpointPenalty: { type: Number, default: 15 },
      minScoreBeforeChallenge: { type: Number, default: 70 },
    },
    requestCadence: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      deviationThreshold: { type: Number, default: 0.5 }, // 50% deviation triggers
      penaltyPercentDeviation: { type: Number, default: 0.5 }, // -0.5 per % deviation
      minScoreBeforeChallenge: { type: Number, default: 70 },
    },
    geoContext: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      impossibleTravelThreshold: { type: Number, default: 900 }, // km/h
      newCountryPenalty: { type: Number, default: 30 },
      newCityPenalty: { type: Number, default: 15 },
      sameCountrySameTimezoneBonusRecovery: { type: Boolean, default: true },
      minScoreBeforeChallenge: { type: Number, default: 60 },
    },
    userAgentConsistency: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      browserChangePenalty: { type: Number, default: 20 },
      osChangePenalty: { type: Number, default: 25 },
      minorVersionChangeTolerance: { type: Boolean, default: true },
      minScoreBeforeChallenge: { type: Number, default: 75 },
    },
    tokenAge: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      warningThresholdHours: { type: Number, default: 12 },
      maxAgeHours: { type: Number, default: 24 },
      ageGracePeriodMinutes: { type: Number, default: 5 },
      minScoreBeforeChallenge: { type: Number, default: 50 },
    },
    privilegeTransition: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      escalationRiskFactor: { type: Number, default: 2.0 }, // 2x penalty for escalations
      unusualEscalationPenalty: { type: Number, default: 40 },
      revocationTrustBoost: { type: Number, default: 5 }, // Restores trust slightly
      minScoreBeforeChallenge: { type: Number, default: 60 },
    },
    reAuth: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'NORMAL' },
      failedAttemptPenalty: { type: Number, default: 15 },
      successfulAttemptBoost: { type: Number, default: 10 },
      failureThresholdBeforeLock: { type: Number, default: 3 },
      minScoreBeforeChallenge: { type: Number, default: 65 },
    },
    threatIndicator: {
      toleranceLevel: { type: String, enum: ['STRICT', 'NORMAL', 'RELAXED'], default: 'STRICT' },
      ipBlacklistPenalty: { type: Number, default: 50 },
      malwarePenalty: { type: Number, default: 60 },
      botnetPenalty: { type: Number, default: 55 },
      knownAttackerPenalty: { type: Number, default: 70 },
      minScoreBeforeChallenge: { type: Number, default: 30 }, // Very strict
    },
  },

  // Global Thresholds
  globalThresholds: {
    normalToMonitoredThreshold: { type: Number, default: 89 }, // <90 = MONITORED
    monitoredToChallengedThreshold: { type: Number, default: 69 }, // <70 = CHALLENGED
    challengedToTerminatedThreshold: { type: Number, default: 39 }, // <40 = TERMINATED
  },

  // Challenge Selection Strategy (anti-friction)
  challengeStrategy: {
    preferWeakChallenges: { type: Boolean, default: true },
    // Weak challenges: Device check, Email verification
    // Strong challenges: OTP, Biometric
    // Strongest: Password + 2FA

    challengePreferenceOrder: [{
      challengeType: { type: String, enum: ['DEVICE_CHECK', 'EMAIL_VERIFY', 'OTP', 'BIOMETRIC', 'PASSWORD_2FA'] },
      frequency: Number, // How often used (1=first choice)
      effectiveness: Number, // Success rate in preventing fraud (0-100)
    }],

    // Reduce challenges if confidence is high
    confidenceThreshold: { type: Number, default: 85 },

    // Don't challenge too frequently
    challengeCooldownMinutes: { type: Number, default: 30 },
    maxChallengesPerHour: { type: Number, default: 3 },

    // Fast response = less suspicious
    fastResponseTimeMs: { type: Number, default: 2000 }, // Response <2s = normal
  },

  // False Positive Impact
  falsePositiveTracking: {
    count: { type: Number, default: 0 },
    lastOccurredAt: Date,
    trend: { type: String, enum: ['INCREASING', 'DECREASING', 'STABLE'], default: 'STABLE' },
    averagePerWeek: { type: Number, default: 0 },
  },

  // Auto-Adjustment Settings
  autoAdjustment: {
    enabled: { type: Boolean, default: true },
    // Automatically relax thresholds if false positive rate high
    falsePositiveThreshold: { type: Number, default: 0.1 }, // 10% false positive rate
    relaxationFactor: { type: Number, default: 0.85 }, // Reduce sensitivity by 15%
    
    // Tighten if attacks detected
    threatThreshold: { type: Number, default: 2 }, // 2 real attacks
    tighteningFactor: { type: Number, default: 1.2 }, // Increase sensitivity by 20%

    adjustmentCheckFrequency: { type: String, default: 'WEEKLY' },
    lastAdjustmentAt: Date,
  },

  // Allow Exceptions
  exceptions: [{
    exceptionType: { type: String, enum: ['TEMPORARY_RELAXATION', 'KNOWN_VPN', 'TRAVELING', 'DEVICE_CHANGE'] },
    description: String,
    component: String, // Which component to exclude
    relaxationFactor: { type: Number, default: 0.8 }, // 80% of normal sensitivity
    validFrom: Date,
    validUntil: Date,
    requiresApproval: { type: Boolean, default: false },
    approvedBy: String,
  }],

  // Policy Status
  enabled: { type: Boolean, default: true },
  lastUpdatedAt: Date,
  lastReviewedAt: Date,

  // Metadata
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
  collection: 'adaptive_threshold_policies',
});

// Indexes
AdaptiveThresholdPolicySchema.index({ userId: 1 });
AdaptiveThresholdPolicySchema.index({ enabled: 1, userId: 1 });
AdaptiveThresholdPolicySchema.index({ 'falsePositiveTracking.count': 1 });

// Methods

/**
 * Get effective threshold for a component
 */
AdaptiveThresholdPolicySchema.methods.getComponentThreshold = function(component) {
  return this.componentThresholds[component] || this.componentThresholds.requestCadence;
};

/**
 * Get currently active exceptions
 */
AdaptiveThresholdPolicySchema.methods.getActiveExceptions = function() {
  const now = new Date();
  return this.exceptions.filter(ex => 
    ex.validFrom <= now && ex.validUntil >= now
  );
};

/**
 * Check if exception applies to component
 */
AdaptiveThresholdPolicySchema.methods.hasExceptionForComponent = function(component) {
  return this.getActiveExceptions().some(ex => ex.component === component);
};

/**
 * Get relaxation factor for component (1.0 = normal, <1.0 = relaxed, >1.0 = strict)
 */
AdaptiveThresholdPolicySchema.methods.getRelaxationFactor = function(component) {
  const activeExceptions = this.getActiveExceptions();
  
  for (const ex of activeExceptions) {
    if (!ex.component || ex.component === component) {
      return ex.relaxationFactor;
    }
  }

  return 1.0; // No relaxation
};

/**
 * Get next challenge recommendation
 */
AdaptiveThresholdPolicySchema.methods.getNextChallenge = function() {
  const strategy = this.challengeStrategy;
  
  if (!strategy.challengePreferenceOrder || strategy.challengePreferenceOrder.length === 0) {
    return 'OTP'; // Default
  }

  return strategy.challengePreferenceOrder[0].challengeType;
};

/**
 * Record false positive
 */
AdaptiveThresholdPolicySchema.methods.recordFalsePositive = function() {
  this.falsePositiveTracking.count++;
  this.falsePositiveTracking.lastOccurredAt = new Date();
  return this;
};

/**
 * Check if should trigger auto-adjustment (high false positive rate)
 */
AdaptiveThresholdPolicySchema.methods.shouldAutoAdjust = function() {
  const { autoAdjustment, falsePositiveTracking } = this;

  if (!autoAdjustment.enabled) return false;

  // Check if false positive rate exceeds threshold
  const fpRate = falsePositiveTracking.count / Math.max(1, falsePositiveTracking.count + 100);
  
  return fpRate > autoAdjustment.falsePositiveThreshold;
};

/**
 * Get user risk profile
 */
AdaptiveThresholdPolicySchema.methods.getRiskProfile = function() {
  const fpRate = this.falsePositiveTracking.count / Math.max(1, this.falsePositiveTracking.count + 100);

  let risk = 'NORMAL';
  if (fpRate > 0.15) risk = 'HIGH_FP_RATE';
  if (this.baselineProfile.dataPointsCollected < 10) risk = 'INSUFFICIENT_DATA';

  return {
    risk,
    falsePositiveRate: fpRate,
    dataPoints: this.baselineProfile.dataPointsCollected,
    policyEnabled: this.enabled,
  };
};

module.exports = mongoose.model('AdaptiveThresholdPolicy', AdaptiveThresholdPolicySchema);
