/**
 * Cross-Session Threat Correlation API Routes
 * Issue #879: Cross-Session Threat Correlation
 * 
 * API endpoints for managing correlation, containment, and trusted relationships
 */

const express = require('express');
const router = express.Router();
const crossSessionThreatCorrelationService = require('../services/crossSessionThreatCorrelationService');
const containmentActionSystem = require('../services/containmentActionSystem');
const trustedRelationshipsManager = require('../services/trustedRelationshipsManager');
const SessionCorrelationCluster = require('../models/SessionCorrelationCluster');
const ThreatCorrelationEvent = require('../models/ThreatCorrelationEvent');
const ContainmentAction = require('../models/ContainmentAction');
const TrustedRelationship = require('../models/TrustedRelationship');
const { auth, requireAdmin, requireAnalyst } = require('../middleware/auth');

// ============================================================================
// CORRELATION CLUSTER ROUTES
// ============================================================================

/**
 * GET /api/correlation/clusters
 * Get all active correlation clusters (Admin/Analyst)
 */
router.get('/clusters', auth, requireAnalyst, async (req, res) => {
  try {
    const { severity, status, limit = 50 } = req.query;
    
    const query = {};
    if (severity) query.severity = severity;
    if (status) query.status = status;
    
    const clusters = await SessionCorrelationCluster
      .find(query)
      .populate('userIds', 'username email')
      .sort({ firstDetected: -1 })
      .limit(parseInt(limit));
    
    res.json({
      success: true,
      clusters,
      count: clusters.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching clusters:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch correlation clusters',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/clusters/:id
 * Get specific cluster details
 */
router.get('/clusters/:id', auth, requireAnalyst, async (req, res) => {
  try {
    const cluster = await SessionCorrelationCluster
      .findById(req.params.id)
      .populate('userIds', 'username email accountLocked')
      .populate('resolvedBy', 'username email');
    
    if (!cluster) {
      return res.status(404).json({
        success: false,
        error: 'Cluster not found'
      });
    }
    
    // Get related events
    const events = await ThreatCorrelationEvent
      .find({ clusterId: cluster._id })
      .sort({ timestamp: -1 })
      .limit(20);
    
    // Get containment actions
    const containments = await ContainmentAction
      .find({ clusterId: cluster._id })
      .populate('approvedBy reversedBy', 'username email')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      cluster,
      events,
      containments
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching cluster:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch cluster details',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/clusters/:id/resolve
 * Resolve a correlation cluster
 */
router.post('/clusters/:id/resolve', auth, requireAnalyst, async (req, res) => {
  try {
    const { action, notes, outcome } = req.body;
    
    const cluster = await SessionCorrelationCluster.findById(req.params.id);
    if (!cluster) {
      return res.status(404).json({
        success: false,
        error: 'Cluster not found'
      });
    }
    
    await cluster.resolve(req.user._id, { action, notes, outcome });
    
    res.json({
      success: true,
      message: 'Cluster resolved successfully',
      cluster
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error resolving cluster:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to resolve cluster',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/clusters/:id/false-positive
 * Mark cluster as false positive
 */
router.post('/clusters/:id/false-positive', auth, requireAnalyst, async (req, res) => {
  try {
    const { notes } = req.body;
    
    const cluster = await SessionCorrelationCluster.findById(req.params.id);
    if (!cluster) {
      return res.status(404).json({
        success: false,
        error: 'Cluster not found'
      });
    }
    
    await cluster.markFalsePositive(req.user._id, notes);
    
    res.json({
      success: true,
      message: 'Cluster marked as false positive',
      cluster
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error marking false positive:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark as false positive',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/events
 * Get recent correlation events
 */
router.get('/events', auth, requireAnalyst, async (req, res) => {
  try {
    const { hours = 24, severity, limit = 100 } = req.query;
    
    const events = await ThreatCorrelationEvent.getRecentEvents(parseInt(hours));
    
    let filtered = events;
    if (severity) {
      filtered = events.filter(e => e.severity === severity);
    }
    
    res.json({
      success: true,
      events: filtered.slice(0, parseInt(limit)),
      count: filtered.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching events:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch correlation events',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/statistics
 * Get correlation statistics
 */
router.get('/statistics', auth, requireAnalyst, async (req, res) => {
  try {
    const clusterStats = await SessionCorrelationCluster.getClusterStatistics();
    const eventStats = await ThreatCorrelationEvent.getEventStatistics(24);
    
    const activeClusters = await SessionCorrelationCluster.countDocuments({ status: 'ACTIVE' });
    const criticalClusters = await SessionCorrelationCluster.countDocuments({ 
      status: 'ACTIVE',
      severity: 'CRITICAL'
    });
    
    res.json({
      success: true,
      statistics: {
        clusters: {
          active: activeClusters,
          critical: criticalClusters,
          byType: clusterStats
        },
        events: eventStats
      }
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics',
      message: error.message
    });
  }
});

// ============================================================================
// CONTAINMENT ACTION ROUTES
// ============================================================================

/**
 * GET /api/correlation/containments
 * Get containment actions
 */
router.get('/containments', auth, requireAnalyst, async (req, res) => {
  try {
    const { status } = req.query;
    
    let containments;
    if (status === 'pending') {
      containments = await ContainmentAction.getPendingApprovals();
    } else if (status === 'active') {
      containments = await ContainmentAction.getActiveContainments();
    } else {
      containments = await ContainmentAction
        .find({})
        .populate('affectedUsers', 'username email')
        .populate('approvedBy reversedBy', 'username email')
        .sort({ createdAt: -1 })
        .limit(50);
    }
    
    res.json({
      success: true,
      containments,
      count: containments.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching containments:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch containment actions',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/containments/:id/approve
 * Approve a containment action
 */
router.post('/containments/:id/approve', auth, requireAnalyst, async (req, res) => {
  try {
    const { notes } = req.body;
    
    const action = await containmentActionSystem.approveAction(
      req.params.id,
      req.user._id,
      notes
    );
    
    res.json({
      success: true,
      message: 'Containment action approved',
      action
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error approving containment:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to approve containment action',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/containments/:id/reverse
 * Reverse a containment action
 */
router.post('/containments/:id/reverse', auth, requireAnalyst, async (req, res) => {
  try {
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({
        success: false,
        error: 'Reason is required for reversal'
      });
    }
    
    const result = await containmentActionSystem.reverseAction(
      req.params.id,
      req.user._id,
      reason
    );
    
    res.json({
      success: true,
      message: 'Containment action reversed',
      ...result
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error reversing containment:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reverse containment action',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/containments/:id/cancel
 * Cancel a pending containment action
 */
router.post('/containments/:id/cancel', auth, requireAnalyst, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const action = await containmentActionSystem.cancelAction(
      req.params.id,
      req.user._id,
      reason
    );
    
    res.json({
      success: true,
      message: 'Containment action cancelled',
      action
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error cancelling containment:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to cancel containment action',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/containments/statistics
 * Get containment statistics
 */
router.get('/containments/statistics', auth, requireAnalyst, async (req, res) => {
  try {
    const { days = 7 } = req.query;
    
    const stats = await containmentActionSystem.getStatistics(parseInt(days));
    
    res.json({
      success: true,
      statistics: stats
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching containment stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch containment statistics',
      message: error.message
    });
  }
});

// ============================================================================
// TRUSTED RELATIONSHIP ROUTES
// ============================================================================

/**
 * GET /api/correlation/relationships/my
 * Get current user's trusted relationships
 */
router.get('/relationships/my', auth, async (req, res) => {
  try {
    const relationships = await trustedRelationshipsManager.getUserRelationships(req.user._id);
    
    res.json({
      success: true,
      relationships,
      count: relationships.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching relationships:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch relationships',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/relationships/pending
 * Get pending relationship approvals
 */
router.get('/relationships/pending', auth, async (req, res) => {
  try {
    const pending = await trustedRelationshipsManager.getPendingApprovals(req.user._id);
    
    res.json({
      success: true,
      pendingApprovals: pending,
      count: pending.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching pending approvals:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch pending approvals',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/relationships/request
 * Request a new trusted relationship
 */
router.post('/relationships/request', auth, async (req, res) => {
  try {
    const {
      targetUserEmail,
      targetUserId,
      relationshipType,
      description,
      expiresInDays = 365
    } = req.body;
    
    // Find target user
    let targetUser;
    if (targetUserId) {
      targetUser = await require('../models/User').findById(targetUserId);
    } else if (targetUserEmail) {
      targetUser = await require('../models/User').findOne({ email: targetUserEmail });
    } else {
      return res.status(400).json({
        success: false,
        error: 'targetUserId or targetUserEmail required'
      });
    }
    
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'Target user not found'
      });
    }
    
    const relationship = await trustedRelationshipsManager.requestRelationship({
      requestingUserId: req.user._id,
      targetUserId: targetUser._id,
      relationshipType,
      description,
      expiresInDays
    });
    
    res.json({
      success: true,
      message: 'Relationship request sent',
      relationship
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error requesting relationship:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to request relationship',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/relationships/:id/approve
 * Approve a relationship request
 */
router.post('/relationships/:id/approve', auth, async (req, res) => {
  try {
    const relationship = await trustedRelationshipsManager.approveRelationship(
      req.params.id,
      req.user._id
    );
    
    res.json({
      success: true,
      message: 'Relationship approved',
      relationship
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error approving relationship:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to approve relationship',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/relationships/:id/revoke
 * Revoke a trusted relationship
 */
router.post('/relationships/:id/revoke', auth, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const relationship = await trustedRelationshipsManager.revokeRelationship(
      req.params.id,
      req.user._id,
      reason
    );
    
    res.json({
      success: true,
      message: 'Relationship revoked',
      relationship
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error revoking relationship:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke relationship',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/relationships/suggestions
 * Get suggested relationships based on behavior patterns
 */
router.get('/relationships/suggestions', auth, async (req, res) => {
  try {
    const { minSharedSessions = 5, maxSuggestions = 10 } = req.query;
    
    const suggestions = await trustedRelationshipsManager.suggestRelationships(
      req.user._id,
      {
        minSharedSessions: parseInt(minSharedSessions),
        maxSuggestions: parseInt(maxSuggestions)
      }
    );
    
    res.json({
      success: true,
      suggestions,
      count: suggestions.length
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching suggestions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch relationship suggestions',
      message: error.message
    });
  }
});

/**
 * GET /api/correlation/relationships/statistics
 * Get relationship statistics (Admin only)
 */
router.get('/relationships/statistics', auth, requireAdmin, async (req, res) => {
  try {
    const stats = await trustedRelationshipsManager.getStatistics();
    
    res.json({
      success: true,
      statistics: stats
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching relationship stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch relationship statistics',
      message: error.message
    });
  }
});

// ============================================================================
// USER-FACING ROUTES
// ============================================================================

/**
 * GET /api/correlation/my-status
 * Get current user's correlation status
 */
router.get('/my-status', auth, async (req, res) => {
  try {
    // Get active clusters
    const clusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
    
    // Get active containments
    const containments = await ContainmentAction.getUserContainments(req.user._id);
    
    // Get recent events
    const events = await ThreatCorrelationEvent.getUserEvents(req.user._id, 7);
    
    // Calculate risk level
    let riskLevel = 'LOW';
    if (containments.some(c => c.status === 'EXECUTED')) {
      riskLevel = 'CRITICAL';
    } else if (clusters.some(c => c.severity === 'CRITICAL')) {
      riskLevel = 'CRITICAL';
    } else if (clusters.some(c => c.severity === 'HIGH')) {
      riskLevel = 'HIGH';
    } else if (clusters.length > 0) {
      riskLevel = 'MODERATE';
    }
    
    res.json({
      success: true,
      status: {
        riskLevel,
        activeClusters: clusters.length,
        activeContainments: containments.filter(c => c.status === 'EXECUTED').length,
        recentEvents: events.length
      },
      clusters,
      containments: containments.filter(c => c.status === 'EXECUTED'),
      events: events.slice(0, 10)
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error fetching user status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch status',
      message: error.message
    });
  }
});

/**
 * POST /api/correlation/appeal-containment/:id
 * Appeal a containment action
 */
router.post('/appeal-containment/:id', auth, async (req, res) => {
  try {
    const { reason, evidence } = req.body;
    
    const containment = await ContainmentAction.findById(req.params.id);
    if (!containment) {
      return res.status(404).json({
        success: false,
        error: 'Containment action not found'
      });
    }
    
    // Verify user is affected
    if (!containment.affectedUsers.includes(req.user._id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not affected by this containment action'
      });
    }
    
    // Create appeal (implementation would depend on your appeal system)
    // For now, just log it
    await require('../models/SecurityEvent').create({
      eventType: 'CONTAINMENT_APPEAL',
      severity: 'MODERATE',
      userId: req.user._id,
      description: 'User appealed containment action',
      metadata: {
        containmentId: containment._id,
        reason,
        evidence
      }
    });
    
    res.json({
      success: true,
      message: 'Appeal submitted successfully',
      appealId: containment._id
    });
    
  } catch (error) {
    console.error('[CorrelationRoutes] Error submitting appeal:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to submit appeal',
      message: error.message
    });
  }
});

module.exports = router;
