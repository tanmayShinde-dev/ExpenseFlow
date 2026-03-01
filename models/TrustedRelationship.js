/**
 * Trusted Relationship Model
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Defines trusted relationships between users to avoid false positive
 * correlation alerts (e.g., family members, team members)
 */

const mongoose = require('mongoose');

const trustedRelationshipSchema = new mongoose.Schema({
  userId1: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  userId2: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  relationshipType: {
    type: String,
    required: true,
    enum: [
      'FAMILY',
      'HOUSEHOLD',
      'TEAM_MEMBER',
      'BUSINESS_PARTNER',
      'SHARED_DEVICE',
      'OTHER'
    ],
    default: 'OTHER'
  },
  
  status: {
    type: String,
    enum: ['ACTIVE', 'PENDING', 'REVOKED', 'EXPIRED'],
    default: 'PENDING',
    index: true
  },
  
  // Approval workflow
  requestedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  approvedAt: Date,
  
  revokedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  revokedAt: Date,
  
  revokeReason: String,
  
  // Expiration
  expiresAt: {
    type: Date,
    index: true
  },
  
  // Metadata
  description: String,
  
  metadata: {
    sharedIP: Boolean,
    sharedDevice: Boolean,
    sharedLocation: Boolean,
    verificationMethod: String,
    verificationData: mongoose.Schema.Types.Mixed
  },
  
  // Audit
  lastVerified: Date,
  
  verificationHistory: [{
    verifiedAt: Date,
    verifiedBy: mongoose.Schema.Types.ObjectId,
    method: String,
    result: Boolean
  }]
  
}, {
  timestamps: true
});

// Compound indexes
trustedRelationshipSchema.index({ userId1: 1, userId2: 1 }, { unique: true });
trustedRelationshipSchema.index({ userId1: 1, status: 1 });
trustedRelationshipSchema.index({ userId2: 1, status: 1 });
trustedRelationshipSchema.index({ status: 1, expiresAt: 1 });

// Methods
trustedRelationshipSchema.methods.approve = function(approvingUserId) {
  this.status = 'ACTIVE';
  this.approvedBy = approvingUserId;
  this.approvedAt = new Date();
  return this.save();
};

trustedRelationshipSchema.methods.revoke = function(revokingUserId, reason) {
  this.status = 'REVOKED';
  this.revokedBy = revokingUserId;
  this.revokedAt = new Date();
  this.revokeReason = reason;
  return this.save();
};

trustedRelationshipSchema.methods.verify = function(verifyingUserId, method, result) {
  this.lastVerified = new Date();
  this.verificationHistory.push({
    verifiedAt: new Date(),
    verifiedBy: verifyingUserId,
    method,
    result
  });
  return this.save();
};

trustedRelationshipSchema.methods.isExpired = function() {
  return this.expiresAt && this.expiresAt < new Date();
};

// Statics
trustedRelationshipSchema.statics.findRelationship = function(userId1, userId2) {
  return this.findOne({
    $or: [
      { userId1, userId2 },
      { userId1: userId2, userId2: userId1 }
    ],
    status: 'ACTIVE'
  });
};

trustedRelationshipSchema.statics.getUserRelationships = function(userId) {
  return this.find({
    $or: [{ userId1: userId }, { userId2: userId }],
    status: 'ACTIVE'
  })
  .populate('userId1 userId2', 'username email')
  .sort({ createdAt: -1 });
};

trustedRelationshipSchema.statics.getPendingApprovals = function(userId) {
  return this.find({
    userId2: userId,
    status: 'PENDING'
  })
  .populate('userId1 requestedBy', 'username email')
  .sort({ createdAt: -1 });
};

trustedRelationshipSchema.statics.expireOldRelationships = async function() {
  const result = await this.updateMany(
    {
      status: 'ACTIVE',
      expiresAt: { $lt: new Date() }
    },
    {
      $set: { status: 'EXPIRED' }
    }
  );
  
  return result.modifiedCount;
};

trustedRelationshipSchema.statics.getRelationshipStatistics = function() {
  return this.aggregate([
    {
      $group: {
        _id: {
          relationshipType: '$relationshipType',
          status: '$status'
        },
        count: { $sum: 1 }
      }
    },
    {
      $group: {
        _id: '$_id.relationshipType',
        statusCounts: {
          $push: {
            status: '$_id.status',
            count: '$count'
          }
        },
        totalCount: { $sum: '$count' }
      }
    }
  ]);
};

const TrustedRelationship = mongoose.model('TrustedRelationship', trustedRelationshipSchema);

module.exports = TrustedRelationship;
