/**
 * Threat Correlation Event Model
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Logs individual correlation detection events
 */

const mongoose = require('mongoose');

const threatCorrelationEventSchema = new mongoose.Schema({
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
    required: true,
    index: true
  },
  
  description: {
    type: String,
    required: true
  },
  
  indicators: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  // Detection details
  detectionMethod: {
    type: String,
    default: 'CROSS_SESSION_CORRELATION'
  },
  
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.8
  },
  
  // Context
  sourceEventIds: [{
    type: mongoose.Schema.Types.ObjectId
  }],
  
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
  
}, {
  timestamps: true
});

// Indexes
threatCorrelationEventSchema.index({ timestamp: -1, severity: 1 });
threatCorrelationEventSchema.index({ affectedUsers: 1, timestamp: -1 });
threatCorrelationEventSchema.index({ clusterId: 1, timestamp: -1 });

// Statics
threatCorrelationEventSchema.statics.getRecentEvents = function(hours = 24) {
  const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
  return this.find({ timestamp: { $gte: cutoff } })
    .sort({ timestamp: -1 })
    .populate('affectedUsers', 'username email');
};

threatCorrelationEventSchema.statics.getUserEvents = function(userId, days = 7) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return this.find({
    affectedUsers: userId,
    timestamp: { $gte: cutoff }
  }).sort({ timestamp: -1 });
};

threatCorrelationEventSchema.statics.getEventStatistics = function(timeRange = 24) {
  const cutoff = new Date(Date.now() - timeRange * 60 * 60 * 1000);
  
  return this.aggregate([
    {
      $match: { timestamp: { $gte: cutoff } }
    },
    {
      $group: {
        _id: {
          correlationType: '$correlationType',
          severity: '$severity'
        },
        count: { $sum: 1 },
        uniqueUsers: { $addToSet: '$affectedUsers' }
      }
    },
    {
      $project: {
        correlationType: '$_id.correlationType',
        severity: '$_id.severity',
        count: 1,
        affectedUserCount: { $size: '$uniqueUsers' }
      }
    }
  ]);
};

const ThreatCorrelationEvent = mongoose.model('ThreatCorrelationEvent', threatCorrelationEventSchema);

module.exports = ThreatCorrelationEvent;
