/**
 * Cross-Session Threat Correlation Service
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Detects coordinated attacks across multiple user sessions by correlating
 * threat signals, identifying multi-account campaigns, and enabling
 * reversible containment actions.
 */

const SessionCorrelationCluster = require('../models/SessionCorrelationCluster');
const ThreatCorrelationEvent = require('../models/ThreatCorrelationEvent');
const TrustedRelationship = require('../models/TrustedRelationship');
const ContainmentAction = require('../models/ContainmentAction');
const Session = require('../models/Session');
const User = require('../models/User');
const SecurityEvent = require('../models/SecurityEvent');
const MLPrediction = require('../models/MLPrediction');
const AttackGraphEntity = require('../models/AttackGraphEntity');
const SessionBehaviorSignal = require('../models/SessionBehaviorSignal');

class CrossSessionThreatCorrelationService {
  constructor() {
    this.correlationWindow = 60 * 60 * 1000; // 1 hour correlation window
    this.thresholds = {
      ipBasedCorrelation: 3,        // 3+ users from same IP
      deviceFingerprintReuse: 2,    // 2+ users same device
      privilegeEscalation: 2,       // 2+ users escalating in window
      anomalyCluster: 4,            // 4+ users with ML anomalies
      attackVectorMatch: 3,         // 3+ users same attack vector
      rapidAccountCompromise: 5     // 5+ accounts in 1 hour
    };
    this.isMonitoring = false;
  }

  /**
   * Initialize correlation monitoring
   */
  async initialize() {
    try {
      console.log('[CrossSession] Initializing cross-session threat correlation...');
      
      // Start background correlation analysis
      this.startCorrelationMonitoring();
      
      // Clean up old clusters
      await this.cleanupOldClusters();
      
      console.log('[CrossSession] Correlation service initialized');
      return true;
    } catch (error) {
      console.error('[CrossSession] Initialization error:', error);
      throw error;
    }
  }

  /**
   * Analyze session for cross-session threats
   */
  async analyzeSession(sessionId, userId, eventContext = {}) {
    try {
      const session = await Session.findById(sessionId).populate('userId');
      if (!session) {
        return { correlation: false, clusters: [] };
      }

      // Extract correlation indicators
      const indicators = {
        ipAddress: session.ipAddress,
        deviceFingerprint: session.deviceFingerprint,
        userAgent: session.userAgent,
        location: session.location,
        userId: session.userId._id
      };

      // Check for correlations across multiple dimensions
      const correlations = await Promise.all([
        this.detectIPBasedCorrelation(indicators, eventContext),
        this.detectDeviceFingerprintReuse(indicators, eventContext),
        this.detectCoordinatedPrivilegeEscalation(indicators, eventContext),
        this.detectAnomalyCluster(indicators, eventContext),
        this.detectAttackVectorCorrelation(indicators, eventContext)
      ]);

      // Aggregate correlation results
      const identifiedClusters = correlations
        .filter(c => c.isCorrelated)
        .map(c => c.cluster);

      // Check if escalation threshold reached
      const shouldEscalate = identifiedClusters.some(
        cluster => cluster.severity === 'CRITICAL' && cluster.userCount >= this.thresholds.ipBasedCorrelation
      );

      if (shouldEscalate) {
        await this.escalateCorrelatedThreat(identifiedClusters);
      }

      return {
        correlation: identifiedClusters.length > 0,
        clusters: identifiedClusters,
        shouldEscalate,
        indicators
      };
    } catch (error) {
      console.error('[CrossSession] Session analysis error:', error);
      return { correlation: false, clusters: [], error: error.message };
    }
  }

  /**
   * Detect IP-based correlation (same IP attacking multiple users)
   */
  async detectIPBasedCorrelation(indicators, eventContext) {
    try {
      const { ipAddress, userId } = indicators;
      const windowStart = new Date(Date.now() - this.correlationWindow);

      // Find recent sessions from same IP with different users
      const sessionsFromSameIP = await Session.find({
        ipAddress,
        userId: { $ne: userId },
        createdAt: { $gte: windowStart },
        isActive: true
      }).populate('userId');

      // Check for trusted relationships
      const trustedUsers = await this.getTrustedUsers(userId);
      const suspiciousSessions = sessionsFromSameIP.filter(
        s => !trustedUsers.includes(s.userId._id.toString())
      );

      if (suspiciousSessions.length < this.thresholds.ipBasedCorrelation - 1) {
        return { isCorrelated: false };
      }

      // Create or update correlation cluster
      const userIds = [userId, ...suspiciousSessions.map(s => s.userId._id)];
      const cluster = await this.createOrUpdateCluster({
        correlationType: 'IP_BASED',
        correlationKey: ipAddress,
        userIds,
        sessionIds: [indicators.sessionId, ...suspiciousSessions.map(s => s._id)],
        severity: userIds.length >= 5 ? 'CRITICAL' : 'HIGH',
        indicators: {
          ipAddress,
          affectedUserCount: userIds.length,
          timeWindow: this.correlationWindow
        },
        metadata: {
          suspiciousSessions: suspiciousSessions.map(s => ({
            userId: s.userId._id,
            username: s.userId.username,
            sessionId: s._id,
            createdAt: s.createdAt
          }))
        }
      });

      // Log correlation event
      await this.logCorrelationEvent({
        clusterId: cluster._id,
        correlationType: 'IP_BASED',
        affectedUsers: userIds,
        severity: cluster.severity,
        description: `Multiple users (${userIds.length}) detected from same IP: ${ipAddress}`,
        indicators
      });

      return {
        isCorrelated: true,
        cluster: {
          id: cluster._id,
          type: 'IP_BASED',
          userCount: userIds.length,
          severity: cluster.severity,
          ipAddress
        }
      };
    } catch (error) {
      console.error('[CrossSession] IP correlation error:', error);
      return { isCorrelated: false };
    }
  }

  /**
   * Detect device fingerprint reuse across accounts
   */
  async detectDeviceFingerprintReuse(indicators, eventContext) {
    try {
      const { deviceFingerprint, userId } = indicators;
      
      if (!deviceFingerprint || deviceFingerprint === 'unknown') {
        return { isCorrelated: false };
      }

      const windowStart = new Date(Date.now() - this.correlationWindow);

      // Find sessions with same device fingerprint, different users
      const sessionsWithSameDevice = await Session.find({
        deviceFingerprint,
        userId: { $ne: userId },
        createdAt: { $gte: windowStart }
      }).populate('userId');

      // Filter out trusted relationships
      const trustedUsers = await this.getTrustedUsers(userId);
      const suspiciousSessions = sessionsWithSameDevice.filter(
        s => !trustedUsers.includes(s.userId._id.toString())
      );

      if (suspiciousSessions.length < this.thresholds.deviceFingerprintReuse - 1) {
        return { isCorrelated: false };
      }

      const userIds = [userId, ...suspiciousSessions.map(s => s.userId._id)];
      const cluster = await this.createOrUpdateCluster({
        correlationType: 'DEVICE_REUSE',
        correlationKey: deviceFingerprint,
        userIds,
        sessionIds: [indicators.sessionId, ...suspiciousSessions.map(s => s._id)],
        severity: 'CRITICAL',
        indicators: {
          deviceFingerprint,
          affectedUserCount: userIds.length
        },
        metadata: {
          deviceInfo: indicators.userAgent,
          affectedAccounts: suspiciousSessions.map(s => ({
            userId: s.userId._id,
            username: s.userId.username
          }))
        }
      });

      await this.logCorrelationEvent({
        clusterId: cluster._id,
        correlationType: 'DEVICE_REUSE',
        affectedUsers: userIds,
        severity: 'CRITICAL',
        description: `Device fingerprint reused across ${userIds.length} accounts`,
        indicators
      });

      return {
        isCorrelated: true,
        cluster: {
          id: cluster._id,
          type: 'DEVICE_REUSE',
          userCount: userIds.length,
          severity: 'CRITICAL',
          deviceFingerprint
        }
      };
    } catch (error) {
      console.error('[CrossSession] Device reuse detection error:', error);
      return { isCorrelated: false };
    }
  }

  /**
   * Detect coordinated privilege escalations
   */
  async detectCoordinatedPrivilegeEscalation(indicators, eventContext) {
    try {
      const windowStart = new Date(Date.now() - this.correlationWindow);

      // Find privilege escalation events in window
      const escalationEvents = await SecurityEvent.find({
        eventType: { $in: ['PRIVILEGE_ESCALATION', 'ROLE_CHANGE', 'PERMISSION_ELEVATION'] },
        timestamp: { $gte: windowStart }
      }).populate('userId');

      if (escalationEvents.length < this.thresholds.privilegeEscalation) {
        return { isCorrelated: false };
      }

      // Group by correlation indicators
      const correlationGroups = this.groupByCorrelation(escalationEvents, [
        'ipAddress',
        'metadata.deviceFingerprint',
        'metadata.userAgent'
      ]);

      // Find groups exceeding threshold
      const suspiciousGroups = correlationGroups.filter(
        g => g.events.length >= this.thresholds.privilegeEscalation
      );

      if (suspiciousGroups.length === 0) {
        return { isCorrelated: false };
      }

      // Create clusters for each suspicious group
      const clusters = await Promise.all(
        suspiciousGroups.map(async group => {
          const userIds = group.events.map(e => e.userId._id);
          
          return await this.createOrUpdateCluster({
            correlationType: 'COORDINATED_PRIVILEGE_ESCALATION',
            correlationKey: group.key,
            userIds,
            sessionIds: group.events.map(e => e.sessionId).filter(Boolean),
            severity: 'CRITICAL',
            indicators: {
              correlationKey: group.key,
              affectedUserCount: userIds.length,
              escalationType: 'PRIVILEGE_ESCALATION'
            },
            metadata: {
              escalations: group.events.map(e => ({
                userId: e.userId._id,
                username: e.userId.username,
                timestamp: e.timestamp,
                fromRole: e.metadata?.fromRole,
                toRole: e.metadata?.toRole
              }))
            }
          });
        })
      );

      // Log correlation events
      await Promise.all(
        clusters.map(cluster =>
          this.logCorrelationEvent({
            clusterId: cluster._id,
            correlationType: 'COORDINATED_PRIVILEGE_ESCALATION',
            affectedUsers: cluster.userIds,
            severity: 'CRITICAL',
            description: `Coordinated privilege escalation detected across ${cluster.userIds.length} users`,
            indicators
          })
        )
      );

      return {
        isCorrelated: true,
        cluster: {
          id: clusters[0]._id,
          type: 'COORDINATED_PRIVILEGE_ESCALATION',
          userCount: clusters[0].userIds.length,
          severity: 'CRITICAL'
        }
      };
    } catch (error) {
      console.error('[CrossSession] Privilege escalation detection error:', error);
      return { isCorrelated: false };
    }
  }

  /**
   * Detect anomaly clusters (multiple ML anomalies in same timeframe)
   */
  async detectAnomalyCluster(indicators, eventContext) {
    try {
      const windowStart = new Date(Date.now() - this.correlationWindow);

      // Find recent ML anomalies
      const recentAnomalies = await MLPrediction.find({
        timestamp: { $gte: windowStart },
        isAnomaly: true,
        compositeScore: { $gte: 0.7 }
      }).populate('userId');

      if (recentAnomalies.length < this.thresholds.anomalyCluster) {
        return { isCorrelated: false };
      }

      // Group by similarity (IP, device, similar features)
      const clusters = this.clusterAnomaliesBySimilarity(recentAnomalies);

      const largeClusters = clusters.filter(
        c => c.anomalies.length >= this.thresholds.anomalyCluster
      );

      if (largeClusters.length === 0) {
        return { isCorrelated: false };
      }

      // Create correlation clusters
      const correlationClusters = await Promise.all(
        largeClusters.map(async cluster => {
          const userIds = cluster.anomalies.map(a => a.userId._id);
          
          return await this.createOrUpdateCluster({
            correlationType: 'ANOMALY_CLUSTER',
            correlationKey: cluster.key,
            userIds,
            sessionIds: cluster.anomalies.map(a => a.sessionId),
            severity: 'HIGH',
            indicators: {
              averageAnomalyScore: cluster.avgScore,
              affectedUserCount: userIds.length,
              clusterKey: cluster.key
            },
            metadata: {
              anomalies: cluster.anomalies.map(a => ({
                userId: a.userId._id,
                score: a.compositeScore,
                timestamp: a.timestamp
              }))
            }
          });
        })
      );

      await this.logCorrelationEvent({
        clusterId: correlationClusters[0]._id,
        correlationType: 'ANOMALY_CLUSTER',
        affectedUsers: correlationClusters[0].userIds,
        severity: 'HIGH',
        description: `ML anomaly cluster detected: ${correlationClusters[0].userIds.length} users`,
        indicators
      });

      return {
        isCorrelated: true,
        cluster: {
          id: correlationClusters[0]._id,
          type: 'ANOMALY_CLUSTER',
          userCount: correlationClusters[0].userIds.length,
          severity: 'HIGH'
        }
      };
    } catch (error) {
      console.error('[CrossSession] Anomaly cluster detection error:', error);
      return { isCorrelated: false };
    }
  }

  /**
   * Detect attack vector correlation
   */
  async detectAttackVectorCorrelation(indicators, eventContext) {
    try {
      const windowStart = new Date(Date.now() - this.correlationWindow);

      // Find attack graph entities with similar attack patterns
      const attackEntities = await AttackGraphEntity.find({
        lastSeen: { $gte: windowStart },
        riskScore: { $gte: 60 }
      });

      if (attackEntities.length < this.thresholds.attackVectorMatch) {
        return { isCorrelated: false };
      }

      // Group by attack vector similarity
      const vectorGroups = this.groupByAttackVector(attackEntities);
      
      const suspiciousVectors = vectorGroups.filter(
        g => g.entities.length >= this.thresholds.attackVectorMatch
      );

      if (suspiciousVectors.length === 0) {
        return { isCorrelated: false };
      }

      // Create clusters
      const clusters = await Promise.all(
        suspiciousVectors.map(async group => {
          const userIds = group.entities
            .map(e => e.entityId)
            .filter(id => id.toString() !== indicators.userId.toString());

          return await this.createOrUpdateCluster({
            correlationType: 'ATTACK_VECTOR',
            correlationKey: group.vector,
            userIds: [indicators.userId, ...userIds],
            sessionIds: [],
            severity: 'HIGH',
            indicators: {
              attackVector: group.vector,
              affectedUserCount: userIds.length + 1,
              avgRiskScore: group.avgRiskScore
            },
            metadata: {
              attackPattern: group.pattern,
              entities: group.entities.map(e => ({
                entityId: e.entityId,
                entityType: e.entityType,
                riskScore: e.riskScore
              }))
            }
          });
        })
      );

      await this.logCorrelationEvent({
        clusterId: clusters[0]._id,
        correlationType: 'ATTACK_VECTOR',
        affectedUsers: clusters[0].userIds,
        severity: 'HIGH',
        description: `Attack vector correlation detected: ${clusters[0].userIds.length} affected`,
        indicators
      });

      return {
        isCorrelated: true,
        cluster: {
          id: clusters[0]._id,
          type: 'ATTACK_VECTOR',
          userCount: clusters[0].userIds.length,
          severity: 'HIGH'
        }
      };
    } catch (error) {
      console.error('[CrossSession] Attack vector detection error:', error);
      return { isCorrelated: false };
    }
  }

  /**
   * Escalate correlated threat and trigger containment
   */
  async escalateCorrelatedThreat(clusters) {
    try {
      console.log(`[CrossSession] Escalating ${clusters.length} correlated threat clusters`);

      for (const cluster of clusters) {
        // Check if containment already active
        const existingContainment = await ContainmentAction.findOne({
          clusterId: cluster.id,
          status: { $in: ['ACTIVE', 'PENDING'] }
        });

        if (existingContainment) {
          console.log(`[CrossSession] Containment already active for cluster ${cluster.id}`);
          continue;
        }

        // Determine containment action based on severity and type
        const action = this.determineContainmentAction(cluster);

        // Create containment action
        const containment = await ContainmentAction.create({
          clusterId: cluster.id,
          correlationType: cluster.type,
          actionType: action.type,
          affectedUsers: cluster.userIds || [],
          severity: cluster.severity,
          status: 'PENDING',
          requiresAnalystApproval: action.requiresApproval,
          autoExecuteAt: action.autoExecute ? new Date(Date.now() + 5 * 60 * 1000) : null,
          reason: `Correlated threat detected: ${cluster.type}`,
          metadata: {
            cluster,
            detectedAt: new Date(),
            threshold: this.thresholds[this.getThresholdKey(cluster.type)]
          }
        });

        // Auto-execute if configured
        if (action.autoExecute && !action.requiresApproval) {
          await this.executeContainment(containment._id);
        }

        // Notify security team
        await this.notifySecurityTeam(containment);
      }

      return true;
    } catch (error) {
      console.error('[CrossSession] Escalation error:', error);
      throw error;
    }
  }

  /**
   * Execute containment action
   */
  async executeContainment(containmentId) {
    try {
      const containment = await ContainmentAction.findById(containmentId);
      
      if (!containment || containment.status === 'EXECUTED') {
        return false;
      }

      console.log(`[CrossSession] Executing containment ${containmentId}`);

      switch (containment.actionType) {
        case 'LOCK_ACCOUNTS':
          await this.lockAccounts(containment.affectedUsers);
          break;
        
        case 'REVOKE_SESSIONS':
          await this.revokeSessions(containment.affectedUsers);
          break;
        
        case 'REQUIRE_2FA':
          await this.enforce2FA(containment.affectedUsers);
          break;
        
        case 'RESTRICT_PERMISSIONS':
          await this.restrictPermissions(containment.affectedUsers);
          break;
        
        case 'MONITOR_ONLY':
          // Enhanced monitoring - no direct action
          break;
        
        default:
          console.warn(`[CrossSession] Unknown action type: ${containment.actionType}`);
      }

      // Update containment status
      containment.status = 'EXECUTED';
      containment.executedAt = new Date();
      await containment.save();

      // Log security events for affected users
      await this.logContainmentExecution(containment);

      console.log(`[CrossSession] Containment ${containmentId} executed successfully`);
      return true;
    } catch (error) {
      console.error('[CrossSession] Containment execution error:', error);
      
      // Update containment with error
      await ContainmentAction.findByIdAndUpdate(containmentId, {
        status: 'FAILED',
        error: error.message
      });
      
      return false;
    }
  }

  /**
   * Reverse containment action
   */
  async reverseContainment(containmentId, analystId, reason) {
    try {
      const containment = await ContainmentAction.findById(containmentId);
      
      if (!containment || containment.status !== 'EXECUTED') {
        throw new Error('Containment not found or not executed');
      }

      console.log(`[CrossSession] Reversing containment ${containmentId}`);

      switch (containment.actionType) {
        case 'LOCK_ACCOUNTS':
          await this.unlockAccounts(containment.affectedUsers);
          break;
        
        case 'RESTRICT_PERMISSIONS':
          await this.restorePermissions(containment.affectedUsers);
          break;
        
        case 'REQUIRE_2FA':
          await this.remove2FARequirement(containment.affectedUsers);
          break;
      }

      // Update containment status
      containment.status = 'REVERSED';
      containment.reversedAt = new Date();
      containment.reversedBy = analystId;
      containment.reverseReason = reason;
      await containment.save();

      // Log reversal
      await this.logContainmentReversal(containment, analystId, reason);

      return true;
    } catch (error) {
      console.error('[CrossSession] Containment reversal error:', error);
      throw error;
    }
  }

  // ==================== Helper Methods ====================

  async createOrUpdateCluster(clusterData) {
    try {
      const existing = await SessionCorrelationCluster.findOne({
        correlationType: clusterData.correlationType,
        correlationKey: clusterData.correlationKey,
        status: 'ACTIVE',
        createdAt: { $gte: new Date(Date.now() - this.correlationWindow) }
      });

      if (existing) {
        // Update existing cluster
        existing.userIds = [...new Set([...existing.userIds, ...clusterData.userIds])];
        existing.sessionIds = [...new Set([...existing.sessionIds, ...clusterData.sessionIds])];
        existing.severity = clusterData.severity;
        existing.lastUpdated = new Date();
        existing.indicators = clusterData.indicators;
        existing.metadata = { ...existing.metadata, ...clusterData.metadata };
        return await existing.save();
      }

      // Create new cluster
      return await SessionCorrelationCluster.create(clusterData);
    } catch (error) {
      console.error('[CrossSession] Cluster creation error:', error);
      throw error;
    }
  }

  async logCorrelationEvent(eventData) {
    try {
      await ThreatCorrelationEvent.create({
        ...eventData,
        timestamp: new Date()
      });
    } catch (error) {
      console.error('[CrossSession] Event logging error:', error);
    }
  }

  async getTrustedUsers(userId) {
    try {
      const relationships = await TrustedRelationship.find({
        $or: [
          { userId1: userId, status: 'ACTIVE' },
          { userId2: userId, status: 'ACTIVE' }
        ]
      });

      return relationships.map(r => 
        r.userId1.toString() === userId.toString() 
          ? r.userId2.toString() 
          : r.userId1.toString()
      );
    } catch (error) {
      console.error('[CrossSession] Get trusted users error:', error);
      return [];
    }
  }

  groupByCorrelation(events, fields) {
    const groups = new Map();

    events.forEach(event => {
      const keys = fields
        .map(field => this.getNestedValue(event, field))
        .filter(Boolean);

      keys.forEach(key => {
        if (!groups.has(key)) {
          groups.set(key, { key, events: [] });
        }
        groups.get(key).events.push(event);
      });
    });

    return Array.from(groups.values());
  }

  getNestedValue(obj, path) {
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
  }

  clusterAnomaliesBySimilarity(anomalies) {
    const clusters = new Map();

    anomalies.forEach(anomaly => {
      // Use IP or device as clustering key
      const key = anomaly.requestContext?.ipAddress || anomaly.requestContext?.userAgent || 'unknown';
      
      if (!clusters.has(key)) {
        clusters.set(key, {
          key,
          anomalies: [],
          totalScore: 0
        });
      }

      const cluster = clusters.get(key);
      cluster.anomalies.push(anomaly);
      cluster.totalScore += anomaly.compositeScore;
    });

    // Calculate average scores
    clusters.forEach(cluster => {
      cluster.avgScore = cluster.totalScore / cluster.anomalies.length;
    });

    return Array.from(clusters.values());
  }

  groupByAttackVector(entities) {
    const vectors = new Map();

    entities.forEach(entity => {
      const vector = entity.metadata?.attackVector || entity.entityType;
      
      if (!vectors.has(vector)) {
        vectors.set(vector, {
          vector,
          entities: [],
          totalRisk: 0
        });
      }

      const group = vectors.get(vector);
      group.entities.push(entity);
      group.totalRisk += entity.riskScore;
    });

    // Calculate averages
    vectors.forEach(group => {
      group.avgRiskScore = group.totalRisk / group.entities.length;
      group.pattern = this.extractAttackPattern(group.entities);
    });

    return Array.from(vectors.values());
  }

  extractAttackPattern(entities) {
    // Simple pattern extraction - could be enhanced
    const types = entities.map(e => e.entityType).filter((v, i, a) => a.indexOf(v) === i);
    return types.join('+');
  }

  determineContainmentAction(cluster) {
    const { type, severity, userCount } = cluster;

    // Critical threats require immediate action
    if (severity === 'CRITICAL') {
      if (type === 'DEVICE_REUSE') {
        return {
          type: 'LOCK_ACCOUNTS',
          requiresApproval: true,
          autoExecute: false
        };
      }
      if (type === 'COORDINATED_PRIVILEGE_ESCALATION') {
        return {
          type: 'REVOKE_SESSIONS',
          requiresApproval: false,
          autoExecute: true
        };
      }
      if (type === 'IP_BASED' && userCount >= 5) {
        return {
          type: 'REQUIRE_2FA',
          requiresApproval: false,
          autoExecute: true
        };
      }
    }

    // Default to monitoring for lower severity
    return {
      type: 'MONITOR_ONLY',
      requiresApproval: false,
      autoExecute: true
    };
  }

  getThresholdKey(correlationType) {
    const map = {
      'IP_BASED': 'ipBasedCorrelation',
      'DEVICE_REUSE': 'deviceFingerprintReuse',
      'COORDINATED_PRIVILEGE_ESCALATION': 'privilegeEscalation',
      'ANOMALY_CLUSTER': 'anomalyCluster',
      'ATTACK_VECTOR': 'attackVectorMatch'
    };
    return map[correlationType] || 'ipBasedCorrelation';
  }

  async lockAccounts(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { 
        $set: { 
          isLocked: true,
          lockedAt: new Date(),
          lockReason: 'CORRELATED_THREAT'
        }
      }
    );
  }

  async unlockAccounts(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { 
        $set: { isLocked: false },
        $unset: { lockedAt: 1, lockReason: 1 }
      }
    );
  }

  async revokeSessions(userIds) {
    await Session.updateMany(
      { userId: { $in: userIds }, isActive: true },
      {
        $set: {
          isActive: false,
          revokedAt: new Date(),
          revocationReason: 'CORRELATED_THREAT'
        }
      }
    );
  }

  async enforce2FA(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { requires2FA: true, require2FAUntil: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) } }
    );
  }

  async remove2FARequirement(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { $unset: { require2FAUntil: 1 } }
    );
  }

  async restrictPermissions(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { restrictedPermissions: true, restrictedAt: new Date() } }
    );
  }

  async restorePermissions(userIds) {
    await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { restrictedPermissions: false }, $unset: { restrictedAt: 1 } }
    );
  }

  async logContainmentExecution(containment) {
    await SecurityEvent.create({
      eventType: 'CONTAINMENT_EXECUTED',
      severity: containment.severity,
      description: `Containment action executed: ${containment.actionType}`,
      metadata: {
        containmentId: containment._id,
        affectedUsers: containment.affectedUsers,
        correlationType: containment.correlationType
      }
    });
  }

  async logContainmentReversal(containment, analystId, reason) {
    await SecurityEvent.create({
      eventType: 'CONTAINMENT_REVERSED',
      severity: 'MODERATE',
      description: `Containment action reversed by analyst`,
      metadata: {
        containmentId: containment._id,
        analystId,
        reason,
        affectedUsers: containment.affectedUsers
      }
    });
  }

  async notifySecurityTeam(containment) {
    // Integration point for notification system
    console.log(`[CrossSession] Security team notified of containment ${containment._id}`);
  }

  startCorrelationMonitoring() {
    if (this.isMonitoring) return;
    
    this.isMonitoring = true;
    
    // Run correlation analysis every 5 minutes
    setInterval(async () => {
      try {
        await this.runPeriodicCorrelationAnalysis();
      } catch (error) {
        console.error('[CrossSession] Periodic analysis error:', error);
      }
    }, 5 * 60 * 1000);
  }

  async runPeriodicCorrelationAnalysis() {
    // Analyze active sessions for patterns
    const activeSessions = await Session.find({ isActive: true }).limit(100);
    
    for (const session of activeSessions) {
      await this.analyzeSession(session._id, session.userId, {});
    }
  }

  async cleanupOldClusters() {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    await SessionCorrelationCluster.updateMany(
      { createdAt: { $lt: cutoff }, status: 'ACTIVE' },
      { $set: { status: 'EXPIRED' } }
    );
  }
}

// Singleton instance
const crossSessionThreatCorrelationService = new CrossSessionThreatCorrelationService();

module.exports = crossSessionThreatCorrelationService;
