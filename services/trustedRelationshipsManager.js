/**
 * Trusted Relationships Manager
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Manages trusted relationships between users to prevent false positives
 */

const TrustedRelationship = require('../models/TrustedRelationship');
const User = require('../models/User');
const Session = require('../models/Session');
const SecurityEvent = require('../models/SecurityEvent');

class TrustedRelationshipsManager {
  constructor() {
    this.expirationCheckInterval = null;
  }
  
  /**
   * Initialize the relationships manager
   */
  async initialize() {
    console.log('[TrustedRelationshipsManager] Initializing trusted relationships manager');
    
    // Start expiration checker
    this.startExpirationChecker();
    
    // Expire old relationships
    await this.expireOldRelationships();
    
    console.log('[TrustedRelationshipsManager] Trusted relationships manager initialized');
  }
  
  /**
   * Start expiration checker
   */
  startExpirationChecker() {
    if (this.expirationCheckInterval) {
      clearInterval(this.expirationCheckInterval);
    }
    
    // Check every hour for expired relationships
    this.expirationCheckInterval = setInterval(async () => {
      await this.expireOldRelationships();
    }, 60 * 60 * 1000);
  }
  
  /**
   * Stop expiration checker
   */
  stopExpirationChecker() {
    if (this.expirationCheckInterval) {
      clearInterval(this.expirationCheckInterval);
      this.expirationCheckInterval = null;
    }
  }
  
  /**
   * Request a trusted relationship
   */
  async requestRelationship(options) {
    const {
      requestingUserId,
      targetUserId,
      relationshipType,
      description,
      expiresInDays = 365,
      metadata = {}
    } = options;
    
    // Validate users exist
    const requestingUser = await User.findById(requestingUserId);
    const targetUser = await User.findById(targetUserId);
    
    if (!requestingUser || !targetUser) {
      throw new Error('One or both users not found');
    }
    
    if (requestingUserId.toString() === targetUserId.toString()) {
      throw new Error('Cannot create relationship with yourself');
    }
    
    // Check if relationship already exists
    const existing = await TrustedRelationship.findRelationship(requestingUserId, targetUserId);
    if (existing) {
      throw new Error('Trusted relationship already exists between these users');
    }
    
    // Create relationship
    const relationship = new TrustedRelationship({
      userId1: requestingUserId,
      userId2: targetUserId,
      relationshipType,
      description,
      requestedBy: requestingUserId,
      status: 'PENDING',
      expiresAt: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000),
      metadata
    });
    
    await relationship.save();
    
    console.log(`[TrustedRelationshipsManager] Relationship requested: ${requestingUserId} -> ${targetUserId}`);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'TRUSTED_RELATIONSHIP_REQUESTED',
      severity: 'LOW',
      userId: requestingUserId,
      description: `User requested trusted relationship with ${targetUser.username}`,
      metadata: {
        relationshipId: relationship._id,
        relationshipType,
        targetUserId
      }
    });
    
    // Send notification to target user (implement notification system separately)
    // await notificationService.send(targetUserId, 'RELATIONSHIP_REQUEST', { ... });
    
    return relationship;
  }
  
  /**
   * Approve a trusted relationship
   */
  async approveRelationship(relationshipId, approvingUserId) {
    const relationship = await TrustedRelationship.findById(relationshipId)
      .populate('userId1 userId2');
    
    if (!relationship) {
      throw new Error('Relationship not found');
    }
    
    if (relationship.status !== 'PENDING') {
      throw new Error(`Cannot approve relationship with status ${relationship.status}`);
    }
    
    // Verify the approving user is the target user
    if (relationship.userId2._id.toString() !== approvingUserId.toString()) {
      throw new Error('Only the target user can approve this relationship');
    }
    
    await relationship.approve(approvingUserId);
    
    console.log(`[TrustedRelationshipsManager] Relationship approved: ${relationshipId}`);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'TRUSTED_RELATIONSHIP_APPROVED',
      severity: 'LOW',
      userId: approvingUserId,
      description: `User approved trusted relationship with ${relationship.userId1.username}`,
      metadata: {
        relationshipId: relationship._id,
        relationshipType: relationship.relationshipType
      }
    });
    
    return relationship;
  }
  
  /**
   * Revoke a trusted relationship
   */
  async revokeRelationship(relationshipId, revokingUserId, reason) {
    const relationship = await TrustedRelationship.findById(relationshipId)
      .populate('userId1 userId2');
    
    if (!relationship) {
      throw new Error('Relationship not found');
    }
    
    // Verify the revoking user is one of the users in the relationship
    const isUser1 = relationship.userId1._id.toString() === revokingUserId.toString();
    const isUser2 = relationship.userId2._id.toString() === revokingUserId.toString();
    
    if (!isUser1 && !isUser2) {
      throw new Error('Only users in the relationship can revoke it');
    }
    
    await relationship.revoke(revokingUserId, reason);
    
    console.log(`[TrustedRelationshipsManager] Relationship revoked: ${relationshipId}`);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'TRUSTED_RELATIONSHIP_REVOKED',
      severity: 'LOW',
      userId: revokingUserId,
      description: `User revoked trusted relationship`,
      metadata: {
        relationshipId: relationship._id,
        reason
      }
    });
    
    return relationship;
  }
  
  /**
   * Check if two users have a trusted relationship
   */
  async isTrusted(userId1, userId2) {
    if (userId1.toString() === userId2.toString()) {
      return false; // Same user
    }
    
    const relationship = await TrustedRelationship.findRelationship(userId1, userId2);
    
    if (!relationship) {
      return false;
    }
    
    // Check if expired
    if (relationship.isExpired()) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Get user's trusted relationships
   */
  async getUserRelationships(userId) {
    return await TrustedRelationship.getUserRelationships(userId);
  }
  
  /**
   * Get pending relationship approvals for user
   */
  async getPendingApprovals(userId) {
    return await TrustedRelationship.getPendingApprovals(userId);
  }
  
  /**
   * Get trusted users for a given user
   */
  async getTrustedUsers(userId) {
    const relationships = await TrustedRelationship.getUserRelationships(userId);
    
    const trustedUserIds = relationships.map(rel => {
      if (rel.userId1._id.toString() === userId.toString()) {
        return rel.userId2._id;
      } else {
        return rel.userId1._id;
      }
    });
    
    return trustedUserIds;
  }
  
  /**
   * Auto-suggest relationships based on behavioral patterns
   */
  async suggestRelationships(userId, options = {}) {
    const {
      minSharedSessions = 5,
      maxSuggestions = 10,
      timePeriodDays = 30
    } = options;
    
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    
    const cutoff = new Date(Date.now() - timePeriodDays * 24 * 60 * 60 * 1000);
    
    // Find sessions for this user
    const userSessions = await Session.find({
      userId,
      createdAt: { $gte: cutoff }
    });
    
    // Extract IPs and device fingerprints
    const userIPs = [...new Set(userSessions.map(s => s.ip).filter(Boolean))];
    const userDevices = [...new Set(userSessions.map(s => s.deviceFingerprint).filter(Boolean))];
    
    // Find other users with overlapping IPs or devices
    const potentialMatches = await Session.aggregate([
      {
        $match: {
          userId: { $ne: userId },
          createdAt: { $gte: cutoff },
          $or: [
            { ip: { $in: userIPs } },
            { deviceFingerprint: { $in: userDevices } }
          ]
        }
      },
      {
        $group: {
          _id: '$userId',
          sharedSessions: { $sum: 1 },
          sharedIPs: { $addToSet: '$ip' },
          sharedDevices: { $addToSet: '$deviceFingerprint' }
        }
      },
      {
        $match: {
          sharedSessions: { $gte: minSharedSessions }
        }
      },
      {
        $sort: { sharedSessions: -1 }
      },
      {
        $limit: maxSuggestions
      }
    ]);
    
    // Filter out existing relationships
    const existingRelationships = await TrustedRelationship.getUserRelationships(userId);
    const existingUserIds = existingRelationships.map(rel => {
      if (rel.userId1._id.toString() === userId.toString()) {
        return rel.userId2._id.toString();
      } else {
        return rel.userId1._id.toString();
      }
    });
    
    const suggestions = potentialMatches
      .filter(match => !existingUserIds.includes(match._id.toString()))
      .map(match => ({
        userId: match._id,
        confidence: Math.min(match.sharedSessions / 10, 1), // Normalize to [0, 1]
        sharedSessions: match.sharedSessions,
        reason: this.getSuggestionReason(match)
      }));
    
    // Populate user details
    for (const suggestion of suggestions) {
      const suggestedUser = await User.findById(suggestion.userId).select('username email');
      suggestion.user = suggestedUser;
    }
    
    return suggestions;
  }
  
  /**
   * Get reason for relationship suggestion
   */
  getSuggestionReason(match) {
    const reasons = [];
    
    if (match.sharedIPs && match.sharedIPs.length > 0) {
      reasons.push(`Shared ${match.sharedIPs.length} IP address(es)`);
    }
    
    if (match.sharedDevices && match.sharedDevices.length > 0) {
      reasons.push(`Shared ${match.sharedDevices.length} device(s)`);
    }
    
    reasons.push(`${match.sharedSessions} overlapping sessions`);
    
    return reasons.join(', ');
  }
  
  /**
   * Verify a relationship using additional data
   */
  async verifyRelationship(relationshipId, verifyingUserId, verificationMethod, verificationData) {
    const relationship = await TrustedRelationship.findById(relationshipId);
    
    if (!relationship) {
      throw new Error('Relationship not found');
    }
    
    // Verify the verifying user is one of the users in the relationship
    const isUser = 
      relationship.userId1.toString() === verifyingUserId.toString() ||
      relationship.userId2.toString() === verifyingUserId.toString();
    
    if (!isUser) {
      throw new Error('Only users in the relationship can verify it');
    }
    
    // Perform verification based on method
    let result = false;
    
    switch (verificationMethod) {
      case 'SHARED_SECRET':
        result = this.verifySharedSecret(verificationData);
        break;
      
      case 'EMAIL_CONFIRMATION':
        result = this.verifyEmailConfirmation(verificationData);
        break;
      
      case 'PHONE_VERIFICATION':
        result = this.verifyPhoneNumber(verificationData);
        break;
      
      default:
        throw new Error(`Unknown verification method: ${verificationMethod}`);
    }
    
    // Update relationship
    await relationship.verify(verifyingUserId, verificationMethod, result);
    
    console.log(`[TrustedRelationshipsManager] Relationship verified: ${relationshipId} - ${result}`);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'TRUSTED_RELATIONSHIP_VERIFIED',
      severity: 'LOW',
      userId: verifyingUserId,
      description: `Relationship verification ${result ? 'succeeded' : 'failed'}`,
      metadata: {
        relationshipId,
        verificationMethod,
        result
      }
    });
    
    return { verified: result, relationship };
  }
  
  /**
   * Verify shared secret
   */
  verifySharedSecret(verificationData) {
    // Placeholder - implement actual verification logic
    return verificationData && verificationData.secret === 'correct_secret';
  }
  
  /**
   * Verify email confirmation
   */
  verifyEmailConfirmation(verificationData) {
    // Placeholder - implement actual email verification
    return verificationData && verificationData.emailConfirmed === true;
  }
  
  /**
   * Verify phone number
   */
  verifyPhoneNumber(verificationData) {
    // Placeholder - implement actual phone verification
    return verificationData && verificationData.phoneVerified === true;
  }
  
  /**
   * Expire old relationships
   */
  async expireOldRelationships() {
    try {
      const count = await TrustedRelationship.expireOldRelationships();
      
      if (count > 0) {
        console.log(`[TrustedRelationshipsManager] Expired ${count} old relationships`);
        
        await this.logSecurityEvent({
          eventType: 'TRUSTED_RELATIONSHIPS_EXPIRED',
          severity: 'LOW',
          description: `${count} trusted relationships expired`,
          metadata: { count }
        });
      }
    } catch (error) {
      console.error('[TrustedRelationshipsManager] Error expiring relationships:', error);
    }
  }
  
  /**
   * Get relationship statistics
   */
  async getStatistics() {
    const stats = await TrustedRelationship.getRelationshipStatistics();
    
    const activeCount = await TrustedRelationship.countDocuments({ status: 'ACTIVE' });
    const pendingCount = await TrustedRelationship.countDocuments({ status: 'PENDING' });
    const revokedCount = await TrustedRelationship.countDocuments({ status: 'REVOKED' });
    const expiredCount = await TrustedRelationship.countDocuments({ status: 'EXPIRED' });
    
    return {
      total: {
        active: activeCount,
        pending: pendingCount,
        revoked: revokedCount,
        expired: expiredCount
      },
      byType: stats
    };
  }
  
  /**
   * Bulk import relationships (for admin/migration)
   */
  async bulkImportRelationships(relationships, importedBy) {
    const results = {
      success: 0,
      failed: 0,
      errors: []
    };
    
    for (const rel of relationships) {
      try {
        await this.requestRelationship({
          requestingUserId: rel.userId1,
          targetUserId: rel.userId2,
          relationshipType: rel.type || 'OTHER',
          description: rel.description || 'Bulk imported',
          expiresInDays: rel.expiresInDays || 365,
          metadata: { bulkImported: true, importedBy }
        });
        
        // Auto-approve if specified
        if (rel.autoApprove) {
          const relationship = await TrustedRelationship.findOne({
            userId1: rel.userId1,
            userId2: rel.userId2
          });
          
          if (relationship) {
            await relationship.approve(rel.userId2);
          }
        }
        
        results.success++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          relationship: rel,
          error: error.message
        });
      }
    }
    
    console.log(`[TrustedRelationshipsManager] Bulk import completed: ${results.success} success, ${results.failed} failed`);
    
    return results;
  }
  
  /**
   * Log security event
   */
  async logSecurityEvent(event) {
    try {
      await SecurityEvent.create({
        ...event,
        timestamp: new Date()
      });
    } catch (error) {
      console.error('[TrustedRelationshipsManager] Error logging security event:', error);
    }
  }
  
  /**
   * Shutdown the relationships manager
   */
  async shutdown() {
    console.log('[TrustedRelationshipsManager] Shutting down trusted relationships manager');
    this.stopExpirationChecker();
  }
}

// Export singleton instance
const trustedRelationshipsManager = new TrustedRelationshipsManager();

module.exports = trustedRelationshipsManager;
