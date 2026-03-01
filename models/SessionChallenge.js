/**
 * SessionChallenge Model
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Tracks challenges issued during session re-scoring.
 * Implements anti-friction controls for minimal user disruption.
 */

const mongoose = require('mongoose');

const SessionChallengeSchema = new mongoose.Schema({
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

  // Challenge Metadata
  challengeType: {
    type: String,
    enum: [
      'DEVICE_CHECK', // Verify trusted device
      'EMAIL_VERIFY', // Click link in email
      'OTP', // One-time password
      'BIOMETRIC', // Fingerprint/Face
      'PASSWORD_2FA', // Password + 2FA
      'SECURITY_QUESTIONS', // Knowledge-based
    ],
    required: true,
  },

  // Challenge Strength (anti-friction metric)
  strength: {
    type: String,
    enum: ['WEAK', 'MEDIUM', 'STRONG'],
    default: 'MEDIUM',
    // WEAK: Device check, Email verify
    // MEDIUM: OTP, Security questions
    // STRONG: Biometric + OTP, Password + 2FA
  },

  // Trigger Context
  triggerReason: {
    type: String,
    required: true,
    // e.g., "trust_score_below_threshold", "anomalous_behavior", "privilege_escalation"
  },
  triggerSignalId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SessionBehaviorSignal',
  },
  trustScoreAtTrigger: Number,
  confidenceLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH'],
    // Higher confidence = stronger challenge
  },

  // Challenge Status
  status: {
    type: String,
    enum: [
      'PENDING', // Waiting for user response
      'COMPLETED', // User responded
      'EXPIRED', // Timed out
      'CANCELLED', // Cancelled by security
      'FAILED', // User failed the challenge
    ],
    default: 'PENDING',
    index: true,
  },

  // Challenge Configuration
  config: {
    expirationMinutes: { type: Number, default: 15 },
    maxAttempts: { type: Number, default: 3 },
    allowSkip: { type: Boolean, default: false },
    // For OTP
    otpCodeLength: { type: Number, default: 6 },
    otpDeliveryMethod: { type: String, enum: ['EMAIL', 'SMS', 'PUSH'] },
    // For device check
    deviceFingerprint: String,
    // For security questions
    questionCount: { type: Number, default: 2 },
  },

  // User Response
  userResponse: {
    attemptCount: { type: Number, default: 0 },
    attempts: [{
      attemptNumber: Number,
      response: String, // SHA256 hashed response
      correct: Boolean,
      completedAt: Date,
    }],
    finalResponseAt: Date,
    responseTimeMs: Number, // Total time to respond
    responseWasFast: Boolean, // <2 seconds = fast
  },

  // Challenge Result
  result: {
    success: Boolean,
    reason: String, // Why challenge passed/failed
    completedAt: Date,
    scoreAdjustment: Number, // How much to adjust trust score
  },

  // Anti-Friction Tracking
  frictionMetrics: {
    userInitiatedRetry: { type: Boolean, default: false },
    abandonmentReason: String, // If user abandoned challenge
    estimatedUserFriction: { type: String, enum: ['MINIMAL', 'LOW', 'MODERATE', 'HIGH'] },
    // Based on: challenge type, attempts needed, time to complete
  },

  // Lifecycle Timestamps
  issuedAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  expiresAt: {
    type: Date,
    index: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  completedAt: Date,

  // Multi-channel Support
  channels: [{
    channel: { type: String, enum: ['EMAIL', 'SMS', 'PUSH', 'IN_APP'] },
    sentAt: Date,
    deliveredAt: Date,
    deliveryStatus: { type: String, enum: ['PENDING', 'DELIVERED', 'FAILED'] },
  }],

  // Metadata
  ipAddress: String,
  userAgent: String,
  deviceInfo: mongoose.Schema.Types.Mixed,

  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  collection: 'session_challenges',
});

// Indexes
SessionChallengeSchema.index({ userId: 1, status: 1 });
SessionChallengeSchema.index({ sessionId: 1, status: 1 });
SessionChallengeSchema.index({ expiresAt: 1 }); // For cleanup
SessionChallengeSchema.index({ issuedAt: 1 });
SessionChallengeSchema.index({ 'result.success': 1, userId: 1 });

// Methods

/**
 * Check if challenge is expired
 */
SessionChallengeSchema.methods.isExpired = function() {
  return this.status === 'EXPIRED' || (new Date() > this.expiresAt);
};

/**
 * Check if challenge is still pending
 */
SessionChallengeSchema.methods.isPending = function() {
  return this.status === 'PENDING' && !this.isExpired();
};

/**
 * Record user response
 */
SessionChallengeSchema.methods.recordAttempt = function(response, isCorrect) {
  this.userResponse.attemptCount++;
  this.userResponse.attempts.push({
    attemptNumber: this.userResponse.attemptCount,
    response: response, // Should be hashed
    correct: isCorrect,
    completedAt: new Date(),
  });

  if (isCorrect) {
    this.status = 'COMPLETED';
    this.userResponse.finalResponseAt = new Date();
    this.result = {
      success: true,
      reason: 'User successfully completed challenge',
      completedAt: new Date(),
    };
  } else if (this.userResponse.attemptCount >= this.config.maxAttempts) {
    this.status = 'FAILED';
    this.result = {
      success: false,
      reason: 'Maximum attempts exceeded',
      completedAt: new Date(),
    };
  }

  return this;
};

/**
 * Calculate response time
 */
SessionChallengeSchema.methods.calculateResponseTime = function() {
  if (this.userResponse.finalResponseAt && this.issuedAt) {
    this.userResponse.responseTimeMs = 
      this.userResponse.finalResponseAt.getTime() - this.issuedAt.getTime();
    
    // Fast response <2 seconds
    this.userResponse.responseWasFast = this.userResponse.responseTimeMs < 2000;
  }

  return this;
};

/**
 * Calculate friction metrics
 */
SessionChallengeSchema.methods.calculateFrictionMetrics = function() {
  const metrics = this.frictionMetrics;
  const attempts = this.userResponse.attemptCount;
  const timeMs = this.userResponse.responseTimeMs;

  // Determine friction level based on challenge type, attempts, and time
  if (this.challengeType === 'DEVICE_CHECK') {
    // Device check is very low friction
    metrics.estimatedUserFriction = 'MINIMAL';
  } else if (this.challengeType === 'EMAIL_VERIFY') {
    // Email verify is low friction
    metrics.estimatedUserFriction = attempts > 2 ? 'LOW' : 'MINIMAL';
  } else if (this.challengeType === 'OTP') {
    // OTP is moderate friction
    if (attempts <= 1 && timeMs < 10000) {
      metrics.estimatedUserFriction = 'LOW';
    } else {
      metrics.estimatedUserFriction = 'MODERATE';
    }
  } else if (this.challengeType === 'BIOMETRIC') {
    // Biometric varies
    metrics.estimatedUserFriction = attempts > 2 ? 'HIGH' : 'LOW';
  } else {
    // Password + 2FA is high friction
    metrics.estimatedUserFriction = 'HIGH';
  }

  return this;
};

/**
 * Mark as expired
 */
SessionChallengeSchema.methods.markExpired = function() {
  this.status = 'EXPIRED';
  this.result = {
    success: false,
    reason: 'Challenge expired',
    completedAt: new Date(),
  };
  return this;
};

/**
 * Cancel challenge
 */
SessionChallengeSchema.methods.cancel = function(reason = 'Cancelled by security') {
  this.status = 'CANCELLED';
  this.result = {
    success: false,
    reason,
    completedAt: new Date(),
  };
  return this;
};

/**
 * Get challenge explanation for UI
 */
SessionChallengeSchema.methods.getExplanation = function() {
  const explanations = {
    DEVICE_CHECK: 'Please verify this is a recognized device',
    EMAIL_VERIFY: 'Verify by clicking the link sent to your email',
    OTP: 'Enter the code sent to your phone',
    BIOMETRIC: 'Use your fingerprint or face to verify',
    PASSWORD_2FA: 'Enter your password and security code',
    SECURITY_QUESTIONS: 'Answer security questions to continue',
  };

  return explanations[this.challengeType] || 'Additional verification required';
};

/**
 * Get challenge strength explanation
 */
SessionChallengeSchema.methods.getStrengthExplanation = function() {
  switch (this.strength) {
    case 'WEAK':
      return 'Quick verification (minimal friction)';
    case 'MEDIUM':
      return 'Standard verification';
    case 'STRONG':
      return 'Enhanced verification (for sensitive actions)';
    default:
      return 'Verification required';
  }
};

module.exports = mongoose.model('SessionChallenge', SessionChallengeSchema);
