/**
 * Containment Action Model
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Tracks reversible containment actions taken in response to correlated threats
 */

const mongoose = require('mongoose');

const containmentActionSchema = new mongoose.Schema({
  clusterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SessionCorrelationCluster',
    required: true,
    index: true
  },
  
  correlationType: {
    type: String,
    required: true,
    enum: [
      'IP_BASED',
      'DEVICE_REUSE',
      'COORDINATED_PRIVILEGE_ESCALATION',
      'ANOMALY_CLUSTER',
      'ATTACK_VECTOR',
      'MULTI_ACCOUNT_CAMPAIGN'
    ]
  },
  
  actionType: {
    type: String,
    required: true,
    enum: [
      'LOCK_ACCOUNTS',
      'REVOKE_SESSIONS',
      'REQUIRE_2FA',
      'RESTRICT_PERMISSIONS',
      'IP_BLOCK',
      'DEVICE_BLOCK',
      'MONITOR_ONLY'
    ],
    index: true
  },
  
  affectedUsers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  
  severity: {
    type: String,
    enum: ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'],
    required: true
  },
  
  status: {
    type: String,
    enum: ['PENDING', 'APPROVED', 'EXECUTED', 'REVERSED', 'FAILED', 'CANCELLED'],
    default: 'PENDING',
    index: true
  },
  
  // Approval workflow
  requiresAnalystApproval: {
    type: Boolean,
    default: true
  },
  
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  approvedAt: Date,
  
  approvalNotes: String,
  
  // Execution
  executedAt: Date,
  
  autoExecuteAt: {
    type: Date,
    index: true
  },
  
  executionDetails: {
    accountsLocked: Number,
    sessionsRevoked: Number,
    permissionsChanged: Number,
    ipsBlocked: [String],
    devicesBlocked: [String]
  },
  
  // Reversal
  isReversible: {
    type: Boolean,
    default: true
  },
  
  reversedAt: Date,
  
  reversedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  reverseReason: String,
  
  reverseDetails: {
    accountsUnlocked: Number,
    permissionsRestored: Number,
    blocksRemoved: Number
  },
  
  // Context
  reason: {
    type: String,
    required: true
  },
  
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  
  // Error handling
  error: String,
  
  retryCount: {
    type: Number,
    default: 0
  },
  
  lastRetryAt: Date
  
}, {
  timestamps: true
});

// Indexes
containmentActionSchema.index({ status: 1, createdAt: -1 });
containmentActionSchema.index({ affectedUsers: 1, status: 1 });
containmentActionSchema.index({ autoExecuteAt: 1, status: 1 });
containmentActionSchema.index({ clusterId: 1, status: 1 });

// Methods
containmentActionSchema.methods.approve = function(analystId, notes) {
  this.status = 'APPROVED';
  this.approvedBy = analystId;
  this.approvedAt = new Date();
  this.approvalNotes = notes;
  return this.save();
};

containmentActionSchema.methods.execute = function(executionDetails) {
  this.status = 'EXECUTED';
  this.executedAt = new Date();
  this.executionDetails = executionDetails;
  return this.save();
};

containmentActionSchema.methods.reverse = function(analystId, reason, reverseDetails) {
  if (!this.isReversible) {
    throw new Error('This containment action is not reversible');
  }
  
  this.status = 'REVERSED';
  this.reversedAt = new Date();
  this.reversedBy = analystId;
  this.reverseReason = reason;
  this.reverseDetails = reverseDetails;
  return this.save();
};

containmentActionSchema.methods.markFailed = function(errorMsg) {
  this.status = 'FAILED';
  this.error = errorMsg;
  this.retryCount += 1;
  this.lastRetryAt = new Date();
  return this.save();
};

containmentActionSchema.methods.cancel = function(analystId, reason) {
  this.status = 'CANCELLED';
  this.reversedBy = analystId;
  this.reverseReason = reason;
  return this.save();
};

containmentActionSchema.methods.canAutoExecute = function() {
  return (
    this.status === 'PENDING' &&
    !this.requiresAnalystApproval &&
    this.autoExecuteAt &&
    this.autoExecuteAt <= new Date()
  );
};

// Statics
containmentActionSchema.statics.getPendingApprovals = function() {
  return this.find({
    status: 'PENDING',
    requiresAnalystApproval: true
  })
  .populate('affectedUsers', 'username email')
  .populate('clusterId')
  .sort({ createdAt: -1 });
};

containmentActionSchema.statics.getAutoExecuteReady = function() {
  return this.find({
    status: 'PENDING',
    requiresAnalystApproval: false,
    autoExecuteAt: { $lte: new Date() }
  });
};

containmentActionSchema.statics.getUserContainments = function(userId) {
  return this.find({
    affectedUsers: userId,
    status: { $in: ['EXECUTED', 'PENDING', 'APPROVED'] }
  })
  .populate('clusterId')
  .sort({ createdAt: -1 });
};

containmentActionSchema.statics.getActiveContainments = function() {
  return this.find({
    status: 'EXECUTED',
    isReversible: true
  })
  .populate('affectedUsers', 'username email')
  .populate('clusterId')
  .sort({ executedAt: -1 });
};

containmentActionSchema.statics.getContainmentStatistics = function(days = 7) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  
  return this.aggregate([
    {
      $match: { createdAt: { $gte: cutoff } }
    },
    {
      $group: {
        _id: {
          actionType: '$actionType',
          status: '$status'
        },
        count: { $sum: 1 },
        affectedUsersTotal: { $sum: { $size: '$affectedUsers' } }
      }
    },
    {
      $group: {
        _id: '$_id.actionType',
        statusCounts: {
          $push: {
            status: '$_id.status',
            count: '$count',
            affectedUsers: '$affectedUsersTotal'
          }
        },
        totalCount: { $sum: '$count' },
        totalAffectedUsers: { $sum: '$affectedUsersTotal' }
      }
    }
  ]);
};

const ContainmentAction = mongoose.model('ContainmentAction', containmentActionSchema);

module.exports = ContainmentAction;
