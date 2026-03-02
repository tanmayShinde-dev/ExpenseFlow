const mongoose = require('mongoose');
const crypto = require('crypto');

/**
 * Recovery Session Model
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Temporary authenticated session for account recovery after hijacking
 */

const recoverySessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Recovery token (secure, one-time use)
  recoveryToken: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  // Associated hijacking event
  hijackingEventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SessionHijackingEvent',
    required: true
  },
  // Original compromised session
  compromisedSessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session'
  },
  // Step-up authentication
  stepUpAuthentication: {
    required: {
      type: Boolean,
      default: true
    },
    method: {
      type: String,
      enum: ['2FA_TOTP', 'EMAIL_CODE', 'SMS_CODE', 'BACKUP_CODE', 'BIOMETRIC'],
      required: true
    },
    completed: {
      type: Boolean,
      default: false
    },
    completedAt: Date,
    attempts: {
      type: Number,
      default: 0
    },
    maxAttempts: {
      type: Number,
      default: 3
    },
    challengeCode: String, // Hashed challenge code for email/SMS
    challengeCodeExpiresAt: Date
  },
  // Recovery session metadata
  status: {
    type: String,
    enum: ['PENDING', 'AUTHENTICATED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'COMPLETED'],
    default: 'PENDING',
    index: true
  },
  // Access restrictions during recovery
  restrictions: {
    readOnly: {
      type: Boolean,
      default: true // Default to read-only during recovery
    },
    allowedActions: [{
      type: String,
      enum: [
        'VIEW_ACCOUNT',
        'CHANGE_PASSWORD',
        'REVOKE_SESSIONS',
        'ENABLE_2FA',
        'VIEW_SECURITY_LOG',
        'DOWNLOAD_ACCOUNT_DATA',
        'DELETE_ACCOUNT'
      ]
    }],
    deniedEndpoints: [String],
    requireReauth: [String] // Endpoints requiring re-authentication
  },
  // Session details
  device: {
    ipAddress: String,
    userAgent: String,
    deviceFingerprint: String,
    location: {
      country: String,
      city: String,
      latitude: Number,
      longitude: Number
    }
  },
  // Recovery actions taken
  actionsPerformed: [{
    action: {
      type: String,
      enum: [
        'PASSWORD_CHANGED',
        'SESSIONS_REVOKED',
        '2FA_ENABLED',
        'BACKUP_CODES_REGENERATED',
        'TRUSTED_DEVICES_CLEARED',
        'ACCOUNT_REVIEWED',
        'DATA_DOWNLOADED',
        'SUPPORT_CONTACTED'
      ]
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    details: mongoose.Schema.Types.Mixed
  }],
  // Expiration and usage
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  lastAccessedAt: Date,
  accessCount: {
    type: Number,
    default: 0
  },
  // Completion
  completedAt: Date,
  outcome: {
    type: String,
    enum: ['ACCOUNT_SECURED', 'EXPIRED', 'USER_CANCELLED', 'ADMIN_INTERVENED']
  },
  notes: String
}, {
  timestamps: true
});

// TTL index for automatic cleanup
recoverySessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Pre-save: Generate recovery token if not provided
recoverySessionSchema.pre('save', function(next) {
  if (!this.recoveryToken) {
    this.recoveryToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Static method to create recovery session
recoverySessionSchema.statics.createRecoverySession = async function(userId, hijackingEventId, options = {}) {
  const expiresIn = options.expiresIn || 3600000; // 1 hour default
  const expiresAt = new Date(Date.now() + expiresIn);

  const recoverySession = new this({
    userId,
    hijackingEventId,
    compromisedSessionId: options.compromisedSessionId,
    recoveryToken: crypto.randomBytes(32).toString('hex'),
    stepUpAuthentication: {
      method: options.stepUpMethod || '2FA_TOTP',
      challengeCode: options.challengeCode,
      challengeCodeExpiresAt: options.challengeCodeExpiresAt
    },
    restrictions: {
      readOnly: options.readOnly !== undefined ? options.readOnly : true,
      allowedActions: options.allowedActions || [
        'VIEW_ACCOUNT',
        'CHANGE_PASSWORD',
        'REVOKE_SESSIONS',
        'ENABLE_2FA',
        'VIEW_SECURITY_LOG'
      ]
    },
    device: options.device || {},
    expiresAt
  });

  await recoverySession.save();
  return recoverySession;
};

// Instance method to verify step-up challenge
recoverySessionSchema.methods.verifyStepUpChallenge = async function(userInput) {
  if (this.stepUpAuthentication.attempts >= this.stepUpAuthentication.maxAttempts) {
    this.status = 'REVOKED';
    await this.save();
    throw new Error('Maximum authentication attempts exceeded');
  }

  this.stepUpAuthentication.attempts += 1;

  // Check expiration for email/SMS codes
  if (this.stepUpAuthentication.challengeCodeExpiresAt && 
      new Date() > this.stepUpAuthentication.challengeCodeExpiresAt) {
    await this.save();
    throw new Error('Challenge code expired');
  }

  // For email/SMS codes, compare hashed values
  if (['EMAIL_CODE', 'SMS_CODE'].includes(this.stepUpAuthentication.method)) {
    const hashedInput = crypto.createHash('sha256').update(userInput).digest('hex');
    if (hashedInput !== this.stepUpAuthentication.challengeCode) {
      await this.save();
      return false;
    }
  }

  // Mark as completed
  this.stepUpAuthentication.completed = true;
  this.stepUpAuthentication.completedAt = new Date();
  this.status = 'AUTHENTICATED';
  await this.save();
  
  return true;
};

// Instance method to record action
recoverySessionSchema.methods.recordAction = async function(action, details = {}) {
  this.actionsPerformed.push({
    action,
    timestamp: new Date(),
    details
  });
  this.lastAccessedAt = new Date();
  this.accessCount += 1;
  await this.save();
  return this;
};

// Instance method to complete recovery
recoverySessionSchema.methods.complete = async function(outcome, notes = '') {
  this.status = 'COMPLETED';
  this.completedAt = new Date();
  this.outcome = outcome;
  this.notes = notes;
  await this.save();
  return this;
};

// Instance method to check if action is allowed
recoverySessionSchema.methods.isActionAllowed = function(action) {
  return this.restrictions.allowedActions.includes(action);
};

// Instance method to check if expired
recoverySessionSchema.methods.isExpired = function() {
  return new Date() > this.expiresAt;
};

module.exports = mongoose.model('RecoverySession', recoverySessionSchema);
