/**
 * Containment Action System
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Manages execution and reversal of security containment actions
 */

const ContainmentAction = require('../models/ContainmentAction');
const User = require('../models/User');
const Session = require('../models/Session');
const SecurityEvent = require('../models/SecurityEvent');

class ContainmentActionSystem {
  constructor() {
    this.executionQueue = [];
    this.isProcessing = false;
    this.autoExecuteInterval = null;
  }
  
  /**
   * Initialize the containment system
   */
  async initialize() {
    console.log('[ContainmentActionSystem] Initializing containment action system');
    
    // Start auto-execution processor
    this.startAutoExecutor();
    
    // Recover any in-progress actions
    await this.recoverPendingActions();
    
    console.log('[ContainmentActionSystem] Containment action system initialized');
  }
  
  /**
   * Start auto-executor for scheduled containment actions
   */
  startAutoExecutor() {
    if (this.autoExecuteInterval) {
      clearInterval(this.autoExecuteInterval);
    }
    
    // Check every 30 seconds for actions ready to auto-execute
    this.autoExecuteInterval = setInterval(async () => {
      await this.processAutoExecuteQueue();
    }, 30000);
  }
  
  /**
   * Stop auto-executor
   */
  stopAutoExecutor() {
    if (this.autoExecuteInterval) {
      clearInterval(this.autoExecuteInterval);
      this.autoExecuteInterval = null;
    }
  }
  
  /**
   * Process actions ready for auto-execution
   */
  async processAutoExecuteQueue() {
    try {
      const readyActions = await ContainmentAction.getAutoExecuteReady();
      
      for (const action of readyActions) {
        console.log(`[ContainmentActionSystem] Auto-executing containment action ${action._id}`);
        await this.executeAction(action._id);
      }
    } catch (error) {
      console.error('[ContainmentActionSystem] Error processing auto-execute queue:', error);
    }
  }
  
  /**
   * Recover pending actions after restart
   */
  async recoverPendingActions() {
    try {
      const pendingActions = await ContainmentAction.find({
        status: { $in: ['PENDING', 'APPROVED'] },
        autoExecuteAt: { $lte: new Date() }
      });
      
      console.log(`[ContainmentActionSystem] Recovering ${pendingActions.length} pending actions`);
      
      for (const action of pendingActions) {
        if (action.status === 'APPROVED' || !action.requiresAnalystApproval) {
          await this.executeAction(action._id);
        }
      }
    } catch (error) {
      console.error('[ContainmentActionSystem] Error recovering pending actions:', error);
    }
  }
  
  /**
   * Create a new containment action
   */
  async createAction(options) {
    const {
      clusterId,
      correlationType,
      actionType,
      affectedUsers,
      severity,
      reason,
      requiresAnalystApproval = true,
      autoExecuteDelayMinutes = 15,
      metadata = {}
    } = options;
    
    // Validate inputs
    if (!clusterId || !affectedUsers || affectedUsers.length === 0) {
      throw new Error('clusterId and affectedUsers are required');
    }
    
    // Create containment action
    const action = new ContainmentAction({
      clusterId,
      correlationType,
      actionType,
      affectedUsers,
      severity,
      reason,
      requiresAnalystApproval,
      autoExecuteAt: new Date(Date.now() + autoExecuteDelayMinutes * 60 * 1000),
      metadata
    });
    
    await action.save();
    
    console.log(`[ContainmentActionSystem] Created containment action ${action._id} for ${affectedUsers.length} users`);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'CONTAINMENT_ACTION_CREATED',
      severity,
      description: `Containment action ${actionType} created for ${affectedUsers.length} users`,
      metadata: {
        actionId: action._id,
        actionType,
        requiresApproval: requiresAnalystApproval
      }
    });
    
    return action;
  }
  
  /**
   * Execute a containment action
   */
  async executeAction(actionId) {
    try {
      const action = await ContainmentAction.findById(actionId)
        .populate('affectedUsers');
      
      if (!action) {
        throw new Error('Containment action not found');
      }
      
      if (action.status !== 'PENDING' && action.status !== 'APPROVED') {
        throw new Error(`Cannot execute action with status ${action.status}`);
      }
      
      if (action.requiresAnalystApproval && action.status !== 'APPROVED') {
        throw new Error('Action requires analyst approval before execution');
      }
      
      console.log(`[ContainmentActionSystem] Executing ${action.actionType} for ${action.affectedUsers.length} users`);
      
      // Execute based on action type
      let executionDetails = {};
      
      switch (action.actionType) {
        case 'LOCK_ACCOUNTS':
          executionDetails = await this.lockAccounts(action.affectedUsers);
          break;
        
        case 'REVOKE_SESSIONS':
          executionDetails = await this.revokeSessions(action.affectedUsers);
          break;
        
        case 'REQUIRE_2FA':
          executionDetails = await this.require2FA(action.affectedUsers);
          break;
        
        case 'RESTRICT_PERMISSIONS':
          executionDetails = await this.restrictPermissions(action.affectedUsers);
          break;
        
        case 'IP_BLOCK':
          executionDetails = await this.blockIPs(action.metadata.ips || []);
          break;
        
        case 'DEVICE_BLOCK':
          executionDetails = await this.blockDevices(action.metadata.devices || []);
          break;
        
        case 'MONITOR_ONLY':
          executionDetails = await this.enableMonitoring(action.affectedUsers);
          break;
        
        default:
          throw new Error(`Unknown action type: ${action.actionType}`);
      }
      
      // Mark action as executed
      await action.execute(executionDetails);
      
      // Log security event
      await this.logSecurityEvent({
        eventType: 'CONTAINMENT_ACTION_EXECUTED',
        severity: action.severity,
        description: `Containment action ${action.actionType} executed for ${action.affectedUsers.length} users`,
        metadata: {
          actionId: action._id,
          actionType: action.actionType,
          executionDetails
        }
      });
      
      console.log(`[ContainmentActionSystem] Successfully executed containment action ${action._id}`);
      
      return { success: true, action, executionDetails };
      
    } catch (error) {
      console.error(`[ContainmentActionSystem] Error executing action ${actionId}:`, error);
      
      // Mark action as failed
      const action = await ContainmentAction.findById(actionId);
      if (action) {
        await action.markFailed(error.message);
      }
      
      throw error;
    }
  }
  
  /**
   * Lock user accounts
   */
  async lockAccounts(users) {
    let lockedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        accountLocked: true,
        lockReason: 'SECURITY_THREAT_CORRELATION',
        lockedAt: new Date()
      });
      
      lockedCount++;
    }
    
    return { accountsLocked: lockedCount };
  }
  
  /**
   * Revoke all active sessions
   */
  async revokeSessions(users) {
    const userIds = users.map(u => u._id);
    
    const result = await Session.updateMany(
      {
        userId: { $in: userIds },
        isActive: true
      },
      {
        $set: {
          isActive: false,
          invalidated: true,
          invalidatedAt: new Date(),
          invalidationReason: 'SECURITY_THREAT_CORRELATION'
        }
      }
    );
    
    return { sessionsRevoked: result.modifiedCount };
  }
  
  /**
   * Require 2FA for users
   */
  async require2FA(users) {
    let updatedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        'security.require2FA': true,
        'security.require2FAReason': 'SECURITY_THREAT_CORRELATION',
        'security.require2FAAt': new Date()
      });
      
      updatedCount++;
    }
    
    return { usersRequired2FA: updatedCount };
  }
  
  /**
   * Restrict user permissions
   */
  async restrictPermissions(users) {
    let updatedCount = 0;
    
    for (const user of users) {
      // Store original permissions
      const originalPermissions = user.permissions || [];
      
      // Restrict to read-only
      await User.findByIdAndUpdate(user._id, {
        permissions: ['READ_ONLY'],
        'security.originalPermissions': originalPermissions,
        'security.permissionsRestricted': true,
        'security.permissionsRestrictedAt': new Date()
      });
      
      updatedCount++;
    }
    
    return { permissionsChanged: updatedCount };
  }
  
  /**
   * Block IP addresses
   */
  async blockIPs(ips) {
    // In production, this would integrate with firewall/WAF
    // For now, store in database
    
    const blockedIPs = [];
    for (const ip of ips) {
      await Session.updateMany(
        { ip },
        {
          $set: {
            ipBlocked: true,
            blockedAt: new Date(),
            blockReason: 'SECURITY_THREAT_CORRELATION'
          }
        }
      );
      
      blockedIPs.push(ip);
    }
    
    return { ipsBlocked: blockedIPs };
  }
  
  /**
   * Block device fingerprints
   */
  async blockDevices(devices) {
    const blockedDevices = [];
    
    for (const device of devices) {
      await Session.updateMany(
        { deviceFingerprint: device },
        {
          $set: {
            deviceBlocked: true,
            blockedAt: new Date(),
            blockReason: 'SECURITY_THREAT_CORRELATION'
          }
        }
      );
      
      blockedDevices.push(device);
    }
    
    return { devicesBlocked: blockedDevices };
  }
  
  /**
   * Enable enhanced monitoring
   */
  async enableMonitoring(users) {
    let updatedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        'security.enhancedMonitoring': true,
        'security.monitoringEnabledAt': new Date(),
        'security.monitoringReason': 'SECURITY_THREAT_CORRELATION'
      });
      
      updatedCount++;
    }
    
    return { usersMonitored: updatedCount };
  }
  
  /**
   * Reverse a containment action
   */
  async reverseAction(actionId, analystId, reason) {
    try {
      const action = await ContainmentAction.findById(actionId)
        .populate('affectedUsers');
      
      if (!action) {
        throw new Error('Containment action not found');
      }
      
      if (action.status !== 'EXECUTED') {
        throw new Error(`Cannot reverse action with status ${action.status}`);
      }
      
      if (!action.isReversible) {
        throw new Error('This containment action is not reversible');
      }
      
      console.log(`[ContainmentActionSystem] Reversing ${action.actionType} for ${action.affectedUsers.length} users`);
      
      // Reverse based on action type
      let reverseDetails = {};
      
      switch (action.actionType) {
        case 'LOCK_ACCOUNTS':
          reverseDetails = await this.unlockAccounts(action.affectedUsers);
          break;
        
        case 'REQUIRE_2FA':
          reverseDetails = await this.unrequire2FA(action.affectedUsers);
          break;
        
        case 'RESTRICT_PERMISSIONS':
          reverseDetails = await this.restorePermissions(action.affectedUsers);
          break;
        
        case 'IP_BLOCK':
          reverseDetails = await this.unblockIPs(action.executionDetails.ipsBlocked || []);
          break;
        
        case 'DEVICE_BLOCK':
          reverseDetails = await this.unblockDevices(action.executionDetails.devicesBlocked || []);
          break;
        
        case 'MONITOR_ONLY':
          reverseDetails = await this.disableMonitoring(action.affectedUsers);
          break;
        
        case 'REVOKE_SESSIONS':
          // Sessions cannot be un-revoked
          reverseDetails = { note: 'Sessions cannot be restored after revocation' };
          break;
        
        default:
          throw new Error(`Unknown action type: ${action.actionType}`);
      }
      
      // Mark action as reversed
      await action.reverse(analystId, reason, reverseDetails);
      
      // Log security event
      await this.logSecurityEvent({
        eventType: 'CONTAINMENT_ACTION_REVERSED',
        severity: action.severity,
        description: `Containment action ${action.actionType} reversed for ${action.affectedUsers.length} users`,
        metadata: {
          actionId: action._id,
          actionType: action.actionType,
          reason,
          reverseDetails
        }
      });
      
      console.log(`[ContainmentActionSystem] Successfully reversed containment action ${action._id}`);
      
      return { success: true, action, reverseDetails };
      
    } catch (error) {
      console.error(`[ContainmentActionSystem] Error reversing action ${actionId}:`, error);
      throw error;
    }
  }
  
  /**
   * Unlock user accounts
   */
  async unlockAccounts(users) {
    let unlockedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        accountLocked: false,
        lockReason: null,
        lockedAt: null,
        unlockedAt: new Date()
      });
      
      unlockedCount++;
    }
    
    return { accountsUnlocked: unlockedCount };
  }
  
  /**
   * Remove 2FA requirement
   */
  async unrequire2FA(users) {
    let updatedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        'security.require2FA': false,
        'security.require2FAReason': null,
        'security.require2FAAt': null
      });
      
      updatedCount++;
    }
    
    return { users2FAUnrequired: updatedCount };
  }
  
  /**
   * Restore original permissions
   */
  async restorePermissions(users) {
    let restoredCount = 0;
    
    for (const user of users) {
      const userData = await User.findById(user._id);
      const originalPermissions = userData.security?.originalPermissions || [];
      
      await User.findByIdAndUpdate(user._id, {
        permissions: originalPermissions,
        'security.originalPermissions': null,
        'security.permissionsRestricted': false,
        'security.permissionsRestrictedAt': null
      });
      
      restoredCount++;
    }
    
    return { permissionsRestored: restoredCount };
  }
  
  /**
   * Unblock IP addresses
   */
  async unblockIPs(ips) {
    for (const ip of ips) {
      await Session.updateMany(
        { ip },
        {
          $set: {
            ipBlocked: false,
            blockedAt: null,
            blockReason: null,
            unblockedAt: new Date()
          }
        }
      );
    }
    
    return { ipsUnblocked: ips.length };
  }
  
  /**
   * Unblock devices
   */
  async unblockDevices(devices) {
    for (const device of devices) {
      await Session.updateMany(
        { deviceFingerprint: device },
        {
          $set: {
            deviceBlocked: false,
            blockedAt: null,
            blockReason: null,
            unblockedAt: new Date()
          }
        }
      );
    }
    
    return { devicesUnblocked: devices.length };
  }
  
  /**
   * Disable enhanced monitoring
   */
  async disableMonitoring(users) {
    let updatedCount = 0;
    
    for (const user of users) {
      await User.findByIdAndUpdate(user._id, {
        'security.enhancedMonitoring': false,
        'security.monitoringEnabledAt': null,
        'security.monitoringReason': null
      });
      
      updatedCount++;
    }
    
    return { usersMonitoringDisabled: updatedCount };
  }
  
  /**
   * Approve a containment action
   */
  async approveAction(actionId, analystId, notes) {
    const action = await ContainmentAction.findById(actionId);
    
    if (!action) {
      throw new Error('Containment action not found');
    }
    
    if (action.status !== 'PENDING') {
      throw new Error(`Cannot approve action with status ${action.status}`);
    }
    
    await action.approve(analystId, notes);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'CONTAINMENT_ACTION_APPROVED',
      severity: action.severity,
      description: `Containment action ${action.actionType} approved by analyst`,
      metadata: {
        actionId: action._id,
        analystId,
        notes
      }
    });
    
    // Execute immediately if auto-execute time has passed
    if (action.autoExecuteAt <= new Date()) {
      await this.executeAction(actionId);
    }
    
    return action;
  }
  
  /**
   * Cancel a containment action
   */
  async cancelAction(actionId, analystId, reason) {
    const action = await ContainmentAction.findById(actionId);
    
    if (!action) {
      throw new Error('Containment action not found');
    }
    
    if (action.status !== 'PENDING' && action.status !== 'APPROVED') {
      throw new Error(`Cannot cancel action with status ${action.status}`);
    }
    
    await action.cancel(analystId, reason);
    
    // Log security event
    await this.logSecurityEvent({
      eventType: 'CONTAINMENT_ACTION_CANCELLED',
      severity: action.severity,
      description: `Containment action ${action.actionType} cancelled`,
      metadata: {
        actionId: action._id,
        analystId,
        reason
      }
    });
    
    return action;
  }
  
  /**
   * Get containment action statistics
   */
  async getStatistics(days = 7) {
    const stats = await ContainmentAction.getContainmentStatistics(days);
    const pendingCount = await ContainmentAction.countDocuments({ status: 'PENDING' });
    const activeCount = await ContainmentAction.countDocuments({ status: 'EXECUTED', isReversible: true });
    
    return {
      pendingApprovals: pendingCount,
      activeContainments: activeCount,
      statistics: stats
    };
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
      console.error('[ContainmentActionSystem] Error logging security event:', error);
    }
  }
  
  /**
   * Shutdown the containment system
   */
  async shutdown() {
    console.log('[ContainmentActionSystem] Shutting down containment action system');
    this.stopAutoExecutor();
  }
}

// Export singleton instance
const containmentActionSystem = new ContainmentActionSystem();

module.exports = containmentActionSystem;
