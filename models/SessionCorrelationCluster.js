/**
 * Session Correlation Cluster Model
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Represents a cluster of correlated sessions/users showing coordinated attack patterns
 */

const mongoose = require('mongoose');

const sessionCorrelationClusterSchema = new mongoose.Schema({
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
    ],
    index: true
  },
  
  correlationKey: {
    type: String,
    required: true,
    index: true
  },
  
  userIds: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  
  sessionIds: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session'
  }],
  
  severity: {
    type: String,
    enum: ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'],
    default: 'MODERATE',
    index: true
  },
  
  status: {
    type: String,
    enum: ['ACTIVE', 'RESOLVED', 'FALSE_POSITIVE', 'EXPIRED'],
    default: 'ACTIVE',
    index: true
  },
  
  indicators: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  
  firstDetected: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  
  resolvedAt: Date,
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  resolution: {
    action: String,
    notes: String,
    outcome: String
  },
  
  // Attack campaign tracking
  campaignId: {
    type: String,
    index: true
  },
  
  // Related clusters
  relatedClusters: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SessionCorrelationCluster'
  }]
  
}, {
  timestamps: true
});

// Indexes
sessionCorrelationClusterSchema.index({ correlationType: 1, status: 1, firstDetected: -1 });
sessionCorrelationClusterSchema.index({ severity: 1, status: 1 });
sessionCorrelationClusterSchema.index({ userIds: 1, status: 1 });

// Methods
sessionCorrelationClusterSchema.methods.addUsers = function(userIds) {
  this.userIds = [...new Set([...this.userIds, ...userIds])];
  this.lastUpdated = new Date();
  return this.save();
};

sessionCorrelationClusterSchema.methods.resolve = function(userId, resolution) {
  this.status = 'RESOLVED';
  this.resolvedAt = new Date();
  this.resolvedBy = userId;
  this.resolution = resolution;
  return this.save();
};

sessionCorrelationClusterSchema.methods.markFalsePositive = function(userId, notes) {
  this.status = 'FALSE_POSITIVE';
  this.resolvedAt = new Date();
  this.resolvedBy = userId;
  this.resolution = { action: 'FALSE_POSITIVE', notes };
  return this.save();
};

// Statics
sessionCorrelationClusterSchema.statics.getActiveClusters = function(severity = null) {
  const query = { status: 'ACTIVE' };
  if (severity) query.severity = severity;
  return this.find(query).sort({ firstDetected: -1 });
};

sessionCorrelationClusterSchema.statics.getUserClusters = function(userId) {
  return this.find({
    userIds: userId,
    status: 'ACTIVE'
  }).sort({ firstDetected: -1 });
};

sessionCorrelationClusterSchema.statics.getClusterStatistics = function() {
  return this.aggregate([
    {
      $match: { status: 'ACTIVE' }
    },
    {
      $group: {
        _id: '$correlationType',
        count: { $sum: 1 },
        avgUserCount: { $avg: { $size: '$userIds' } },
        criticalCount: {
          $sum: { $cond: [{ $eq: ['$severity', 'CRITICAL'] }, 1, 0] }
        }
      }
    }
  ]);
};

const SessionCorrelationCluster = mongoose.model('SessionCorrelationCluster', sessionCorrelationClusterSchema);

module.exports = SessionCorrelationCluster;
