const express = require('express');
const router = express.Router();
const AttackGraphEntity = require('../models/AttackGraphEntity');
const AttackGraphRelationship = require('../models/AttackGraphRelationship');
const SecurityIncident = require('../models/SecurityIncident');
const SecurityEvent = require('../models/SecurityEvent');
const Session = require('../models/Session');
const attackGraphDetectionService = require('../services/attackGraphDetectionService');
const authMiddleware = require('../middleware/auth');
const rbacMiddleware = require('../middleware/rbac');

/**
 * Attack Graph Analyst Tooling Routes
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Provides analyst interfaces for:
 * - Incident management and investigation
 * - Graph traversal and visualization
 * - "Why clustered" reasoning
 * - Mass session revocation
 * - Infrastructure blocking
 */

// Authentication and RBAC - only security analysts
router.use(authMiddleware);
router.use(rbacMiddleware.checkPermission('security:analyst'));

/**
 * GET /api/attack-graph/incidents
 * List all incidents with filtering and sorting
 */
router.get('/incidents', async (req, res) => {
  try {
    const {
      status,
      severity,
      incidentType,
      minConfidence,
      limit = 50,
      skip = 0,
      sortBy = 'detectedAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {};
    
    if (status) {
      query.status = Array.isArray(status) ? { $in: status } : status;
    }
    
    if (severity) {
      query.severity = Array.isArray(severity) ? { $in: severity } : severity;
    }
    
    if (incidentType) {
      query.incidentType = Array.isArray(incidentType) ? { $in: incidentType } : incidentType;
    }
    
    if (minConfidence) {
      query.confidenceScore = { $gte: parseInt(minConfidence) };
    }
    
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    
    const incidents = await SecurityIncident.find(query)
      .sort(sortOptions)
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .populate('assignedTo.userId', 'username email')
      .lean();
    
    const total = await SecurityIncident.countDocuments(query);
    
    res.json({
      success: true,
      incidents,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: skip + limit < total
      }
    });
  } catch (error) {
    console.error('Error fetching incidents:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch incidents'
    });
  }
});

/**
 * GET /api/attack-graph/incidents/:incidentId
 * Get detailed incident information
 */
router.get('/incidents/:incidentId', async (req, res) => {
  try {
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    })
      .populate('evidence.securityEvents')
      .populate('evidence.entities')
      .populate('evidence.relationships')
      .populate('assignedTo.userId', 'username email')
      .populate('analystNotes.analyst', 'username email')
      .populate('responseActions.performedBy', 'username email');
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    // Get evidence summary
    const evidenceSummary = incident.getEvidenceSummary();
    
    res.json({
      success: true,
      incident,
      evidenceSummary
    });
  } catch (error) {
    console.error('Error fetching incident:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch incident details'
    });
  }
});

/**
 * GET /api/attack-graph/incidents/:incidentId/graph
 * Get graph visualization data for an incident
 */
router.get('/incidents/:incidentId/graph', async (req, res) => {
  try {
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    // Get entities
    const entities = await AttackGraphEntity.find({
      _id: { $in: incident.evidence.entities }
    });
    
    // Get relationships
    const relationships = await AttackGraphRelationship.find({
      _id: { $in: incident.evidence.relationships }
    })
      .populate('sourceEntity targetEntity');
    
    // Format for graph visualization (nodes and edges)
    const nodes = entities.map(entity => ({
      id: entity._id.toString(),
      label: entity.entityValue,
      type: entity.entityType,
      riskScore: entity.riskScore,
      classification: entity.classification,
      stats: entity.stats,
      metadata: entity.metadata
    }));
    
    const edges = relationships.map(rel => ({
      id: rel._id.toString(),
      source: rel.sourceEntity._id.toString(),
      target: rel.targetEntity._id.toString(),
      type: rel.relationshipType,
      weight: rel.weight,
      riskContribution: rel.riskContribution,
      evidence: rel.evidence.length,
      pattern: rel.pattern
    }));
    
    res.json({
      success: true,
      graph: {
        nodes,
        edges
      },
      graphAnalysis: incident.graphAnalysis,
      clusteringReasoning: incident.clusteringReasoning
    });
  } catch (error) {
    console.error('Error fetching incident graph:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch incident graph'
    });
  }
});

/**
 * GET /api/attack-graph/entities/:entityId
 * Get entity details and relationships
 */
router.get('/entities/:entityId', async (req, res) => {
  try {
    const entity = await AttackGraphEntity.findById(req.params.entityId);
    
    if (!entity) {
      return res.status(404).json({
        success: false,
        error: 'Entity not found'
      });
    }
    
    // Get relationships
    const relationships = await AttackGraphRelationship.getEntityRelationships(
      entity._id,
      'both'
    );
    
    // Get associated incidents
    const incidents = await SecurityIncident.find({
      _id: { $in: entity.incidents }
    }).select('incidentId title incidentType severity status confidenceScore detectedAt');
    
    // Get related security events
    const query = {};
    
    if (entity.entityType === 'IP') {
      query.ipAddress = entity.entityValue;
    } else if (entity.entityType === 'DEVICE_FINGERPRINT') {
      query.deviceFingerprint = entity.entityValue;
    } else if (entity.entityType === 'USER') {
      query.userId = entity.metadata.userId;
    }
    
    const recentEvents = await SecurityEvent.find(query)
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({
      success: true,
      entity,
      relationships,
      incidents,
      recentEvents
    });
  } catch (error) {
    console.error('Error fetching entity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch entity details'
    });
  }
});

/**
 * POST /api/attack-graph/entities/:entityId/traverse
 * Traverse the graph from an entity
 */
router.post('/entities/:entityId/traverse', async (req, res) => {
  try {
    const { maxDepth = 3, direction = 'both' } = req.body;
    
    const entity = await AttackGraphEntity.findById(req.params.entityId);
    
    if (!entity) {
      return res.status(404).json({
        success: false,
        error: 'Entity not found'
      });
    }
    
    // Find connected component
    const connectedEntityIds = await AttackGraphRelationship.findConnectedComponent(
      entity._id,
      maxDepth
    );
    
    // Load full entities
    const connectedEntities = await AttackGraphEntity.find({
      _id: { $in: connectedEntityIds }
    });
    
    // Get all relationships in this component
    const relationships = await AttackGraphRelationship.find({
      $or: [
        { sourceEntity: { $in: connectedEntityIds } },
        { targetEntity: { $in: connectedEntityIds } }
      ]
    });
    
    // Format for visualization
    const nodes = connectedEntities.map(e => ({
      id: e._id.toString(),
      label: e.entityValue,
      type: e.entityType,
      riskScore: e.riskScore,
      classification: e.classification
    }));
    
    const edges = relationships.map(r => ({
      source: r.sourceEntity.toString(),
      target: r.targetEntity.toString(),
      type: r.relationshipType,
      weight: r.weight
    }));
    
    res.json({
      success: true,
      traversal: {
        startEntity: entity._id,
        depth: maxDepth,
        nodesFound: nodes.length,
        edgesFound: edges.length,
        nodes,
        edges
      }
    });
  } catch (error) {
    console.error('Error traversing graph:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to traverse graph'
    });
  }
});

/**
 * GET /api/attack-graph/entities/high-risk
 * Get high-risk entities for investigation
 */
router.get('/entities/high-risk', async (req, res) => {
  try {
    const { 
      entityType, 
      minRiskScore = 70, 
      limit = 100 
    } = req.query;
    
    const query = {
      riskScore: { $gte: parseInt(minRiskScore) },
      classification: { $in: ['SUSPICIOUS', 'MALICIOUS', 'COMPROMISED'] }
    };
    
    if (entityType) {
      query.entityType = entityType;
    }
    
    const entities = await AttackGraphEntity.find(query)
      .sort({ riskScore: -1, lastSeen: -1 })
      .limit(parseInt(limit));
    
    res.json({
      success: true,
      entities,
      count: entities.length
    });
  } catch (error) {
    console.error('Error fetching high-risk entities:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch high-risk entities'
    });
  }
});

/**
 * POST /api/attack-graph/entities/:entityId/blocklist
 * Blocklist an entity (IP, device, etc.)
 */
router.post('/entities/:entityId/blocklist', async (req, res) => {
  try {
    const { reason, expiresInHours } = req.body;
    
    if (!reason) {
      return res.status(400).json({
        success: false,
        error: 'Reason is required'
      });
    }
    
    const entity = await AttackGraphEntity.findById(req.params.entityId);
    
    if (!entity) {
      return res.status(404).json({
        success: false,
        error: 'Entity not found'
      });
    }
    
    const expiresInMs = expiresInHours ? expiresInHours * 60 * 60 * 1000 : null;
    await entity.blocklist(reason, expiresInMs);
    
    // Record action in associated incidents
    if (entity.incidents.length > 0) {
      await Promise.all(entity.incidents.map(incidentId => 
        SecurityIncident.findByIdAndUpdate(incidentId, {
          $push: {
            responseActions: {
              actionType: 'BLOCKED_' + entity.entityType,
              targetEntityId: entity._id,
              targetEntityType: entity.entityType,
              performedBy: req.user._id,
              reason,
              details: { expiresInHours }
            }
          }
        })
      ));
    }
    
    res.json({
      success: true,
      message: 'Entity blocklisted successfully',
      entity
    });
  } catch (error) {
    console.error('Error blocklisting entity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to blocklist entity'
    });
  }
});

/**
 * POST /api/attack-graph/incidents/:incidentId/revoke-sessions
 * Mass-revoke sessions associated with an incident
 */
router.post('/incidents/:incidentId/revoke-sessions', async (req, res) => {
  try {
    const { reason = 'Security incident - mass revocation' } = req.body;
    
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    // Get all entities in the incident
    const entities = await AttackGraphEntity.find({
      _id: { $in: incident.evidence.entities }
    });
    
    // Extract user IDs and IP addresses from entities
    const userIds = entities
      .filter(e => e.entityType === 'USER')
      .map(e => e.metadata.userId);
    
    const ipAddresses = entities
      .filter(e => e.entityType === 'IP')
      .map(e => e.entityValue);
    
    // Find and revoke matching sessions
    const sessionsToRevoke = await Session.find({
      $or: [
        { userId: { $in: userIds } },
        { 'location.ipAddress': { $in: ipAddresses } }
      ],
      status: 'active'
    });
    
    // Revoke all sessions
    const revokedCount = sessionsToRevoke.length;
    await Session.updateMany(
      { _id: { $in: sessionsToRevoke.map(s => s._id) } },
      { 
        $set: { 
          status: 'revoked',
          'revocation.revokedAt': new Date(),
          'revocation.revokedBy': req.user._id,
          'revocation.reason': 'security_concern',
          'revocation.note': reason
        }
      }
    );
    
    // Record action in incident
    await incident.recordAction(
      'MASS_REVOKED_SESSIONS',
      req.user._id,
      incident._id,
      'INCIDENT',
      reason,
      {
        sessionsRevoked: revokedCount,
        userIds: userIds.length,
        ipAddresses: ipAddresses.length,
        deviceFingerprints: deviceFingerprints.length
      }
    );
    
    res.json({
      success: true,
      message: `Successfully revoked ${revokedCount} sessions`,
      details: {
        sessionsRevoked: revokedCount,
        affectedUsers: userIds.length,
        affectedIPs: ipAddresses.length
      }
    });
  } catch (error) {
    console.error('Error revoking sessions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke sessions'
    });
  }
});

/**
 * POST /api/attack-graph/incidents/:incidentId/assign
 * Assign incident to an analyst
 */
router.post('/incidents/:incidentId/assign', async (req, res) => {
  try {
    const { analystId } = req.body;
    
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    await incident.assignTo(analystId || req.user._id);
    
    res.json({
      success: true,
      message: 'Incident assigned successfully',
      incident
    });
  } catch (error) {
    console.error('Error assigning incident:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assign incident'
    });
  }
});

/**
 * POST /api/attack-graph/incidents/:incidentId/notes
 * Add analyst note to incident
 */
router.post('/incidents/:incidentId/notes', async (req, res) => {
  try {
    const { note, noteType = 'OBSERVATION' } = req.body;
    
    if (!note) {
      return res.status(400).json({
        success: false,
        error: 'Note is required'
      });
    }
    
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    await incident.addAnalystNote(req.user._id, note, noteType);
    
    res.json({
      success: true,
      message: 'Note added successfully',
      incident
    });
  } catch (error) {
    console.error('Error adding note:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add note'
    });
  }
});

/**
 * PUT /api/attack-graph/incidents/:incidentId/status
 * Update incident status
 */
router.put('/incidents/:incidentId/status', async (req, res) => {
  try {
    const { status, notes = '' } = req.body;
    
    if (!status) {
      return res.status(400).json({
        success: false,
        error: 'Status is required'
      });
    }
    
    const validStatuses = ['NEW', 'INVESTIGATING', 'CONFIRMED', 'MITIGATED', 'RESOLVED', 'FALSE_POSITIVE'];
    
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }
    
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    await incident.updateStatus(status, req.user._id, notes);
    
    res.json({
      success: true,
      message: 'Status updated successfully',
      incident
    });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update status'
    });
  }
});

/**
 * POST /api/attack-graph/incidents/:incidentId/validate
 * Validate incident for precision/recall tracking
 */
router.post('/incidents/:incidentId/validate', async (req, res) => {
  try {
    const { isTruePositive, notes = '' } = req.body;
    
    if (typeof isTruePositive !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: 'isTruePositive (boolean) is required'
      });
    }
    
    const incident = await SecurityIncident.findOne({
      incidentId: req.params.incidentId
    });
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        error: 'Incident not found'
      });
    }
    
    await incident.validate(req.user._id, isTruePositive, notes);
    
    res.json({
      success: true,
      message: 'Incident validated successfully',
      incident
    });
  } catch (error) {
    console.error('Error validating incident:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to validate incident'
    });
  }
});

/**
 * GET /api/attack-graph/metrics
 * Get detection metrics (precision, recall, etc.)
 */
router.get('/metrics', async (req, res) => {
  try {
    // Get precision/recall metrics
    const precisionRecall = await SecurityIncident.calculatePrecisionRecall();
    
    // Get incident statistics
    const totalIncidents = await SecurityIncident.countDocuments();
    const activeIncidents = await SecurityIncident.countDocuments({
      status: { $in: ['NEW', 'INVESTIGATING', 'CONFIRMED'] }
    });
    
    const incidentsByType = await SecurityIncident.aggregate([
      {
        $group: {
          _id: '$incidentType',
          count: { $sum: 1 },
          avgConfidence: { $avg: '$confidenceScore' }
        }
      }
    ]);
    
    const incidentsBySeverity = await SecurityIncident.aggregate([
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Entity statistics
    const totalEntities = await AttackGraphEntity.countDocuments();
    const highRiskEntities = await AttackGraphEntity.countDocuments({
      riskScore: { $gte: 70 }
    });
    const blocklistedEntities = await AttackGraphEntity.countDocuments({
      isBlocklisted: true
    });
    
    // Relationship statistics
    const totalRelationships = await AttackGraphRelationship.countDocuments();
    
    res.json({
      success: true,
      metrics: {
        precisionRecall,
        incidents: {
          total: totalIncidents,
          active: activeIncidents,
          byType: incidentsByType,
          bySeverity: incidentsBySeverity
        },
        entities: {
          total: totalEntities,
          highRisk: highRiskEntities,
          blocklisted: blocklistedEntities
        },
        relationships: {
          total: totalRelationships
        }
      }
    });
  } catch (error) {
    console.error('Error fetching metrics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch metrics'
    });
  }
});

/**
 * POST /api/attack-graph/analyze
 * Trigger manual graph analysis
 */
router.post('/analyze', rbacMiddleware.checkPermission('security:admin'), async (req, res) => {
  try {
    // Run full graph analysis in background
    attackGraphDetectionService.runFullGraphAnalysis()
      .then(result => {
        console.log('Graph analysis completed:', result);
      })
      .catch(error => {
        console.error('Graph analysis error:', error);
      });
    
    res.json({
      success: true,
      message: 'Graph analysis started in background'
    });
  } catch (error) {
    console.error('Error starting analysis:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to start analysis'
    });
  }
});

/**
 * GET /api/attack-graph/dashboard
 * Get analyst dashboard data
 */
router.get('/dashboard', async (req, res) => {
  try {
    // Get recent high-confidence incidents
    const recentIncidents = await SecurityIncident.find({
      status: { $in: ['NEW', 'INVESTIGATING', 'CONFIRMED'] }
    })
      .sort({ confidenceScore: -1, detectedAt: -1 })
      .limit(10)
      .select('incidentId title incidentType severity status confidenceScore detectedAt campaignMetrics');
    
    // Get high-risk entities
    const highRiskEntities = await AttackGraphEntity.find({
      riskScore: { $gte: 70 }
    })
      .sort({ riskScore: -1 })
      .limit(20)
      .select('entityType entityValue riskScore classification lastSeen');
    
    // Get recent activity timeline
    const recentActivity = await SecurityEvent.find({
      eventType: {
        $in: ['SUSPICIOUS_LOGIN', 'BRUTE_FORCE_ATTEMPT', 'SESSION_ANOMALY_DETECTED']
      },
      createdAt: {
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
      }
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .select('eventType userId ipAddress createdAt riskScore severity');
    
    // Activity by hour (last 24 hours)
    const activityByHour = await SecurityEvent.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
          }
        }
      },
      {
        $group: {
          _id: {
            $hour: '$createdAt'
          },
          count: { $sum: 1 },
          avgRiskScore: { $avg: '$riskScore' }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);
    
    res.json({
      success: true,
      dashboard: {
        recentIncidents,
        highRiskEntities,
        recentActivity,
        activityByHour
      }
    });
  } catch (error) {
    console.error('Error fetching dashboard:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch dashboard data'
    });
  }
});

module.exports = router;
