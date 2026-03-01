/**
 * Cross-Session Threat Correlation Middleware
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Express middleware for detecting coordinated attacks across sessions
 */

const crossSessionThreatCorrelationService = require('../services/crossSessionThreatCorrelationService');
const SessionCorrelationCluster = require('../models/SessionCorrelationCluster');
const ContainmentAction = require('../models/ContainmentAction');
const SecurityEvent = require('../models/SecurityEvent');

/**
 * Standard correlation check middleware
 */
async function correlationCheck(req, res, next) {
  try {
    // Skip for unauthenticated requests
    if (!req.user || !req.session) {
      return next();
    }
    
    // Skip for system/admin operations
    if (req.user.role === 'SYSTEM' || req.path.startsWith('/api/admin')) {
      return next();
    }
    
    // Check if user is in active containment
    const activeContainment = await ContainmentAction.findOne({
      affectedUsers: req.user._id,
      status: 'EXECUTED'
    });
    
    if (activeContainment) {
      return handleActiveContainment(req, res, activeContainment);
    }
    
    // Perform correlation analysis (async, non-blocking)
    setImmediate(async () => {
      try {
        await crossSessionThreatCorrelationService.analyzeSession(
          req.session._id,
          req.user._id
        );
      } catch (error) {
        console.error('[CorrelationMiddleware] Error analyzing session:', error);
      }
    });
    
    next();
    
  } catch (error) {
    console.error('[CorrelationMiddleware] Error in correlation check:', error);
    next(); // Continue despite errors
  }
}

/**
 * Strict correlation check with blocking
 */
async function strictCorrelationCheck(req, res, next) {
  try {
    // Skip for unauthenticated requests
    if (!req.user || !req.session) {
      return next();
    }
    
    // Check if user is in active containment
    const activeContainment = await ContainmentAction.findOne({
      affectedUsers: req.user._id,
      status: 'EXECUTED'
    });
    
    if (activeContainment) {
      return handleActiveContainment(req, res, activeContainment);
    }
    
    // Check if user is in active correlation cluster
    const activeClusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
    
    if (activeClusters.length > 0) {
      // Block high-severity clusters
      const criticalCluster = activeClusters.find(c => c.severity === 'CRITICAL');
      if (criticalCluster) {
        await logSecurityEvent({
          eventType: 'CORRELATION_BLOCKED',
          severity: 'CRITICAL',
          userId: req.user._id,
          sessionId: req.session._id,
          description: 'Request blocked due to active critical correlation cluster',
          metadata: {
            clusterId: criticalCluster._id,
            correlationType: criticalCluster.correlationType,
            path: req.path
          }
        });
        
        return res.status(403).json({
          error: 'ACCESS_BLOCKED',
          message: 'Your account is temporarily restricted due to security concerns',
          supportContact: 'security@expenseflow.com'
        });
      }
      
      // Challenge on high-severity clusters
      const highCluster = activeClusters.find(c => c.severity === 'HIGH');
      if (highCluster && !req.session.correlationChallenged) {
        return res.status(403).json({
          error: 'CHALLENGE_REQUIRED',
          message: 'Additional verification required',
          challengeType: '2FA',
          clusterId: highCluster._id
        });
      }
    }
    
    // Perform blocking correlation analysis
    await crossSessionThreatCorrelationService.analyzeSession(
      req.session._id,
      req.user._id
    );
    
    next();
    
  } catch (error) {
    console.error('[CorrelationMiddleware] Error in strict correlation check:', error);
    
    // Fail closed on errors in strict mode
    return res.status(500).json({
      error: 'SECURITY_CHECK_FAILED',
      message: 'Unable to verify security status'
    });
  }
}

/**
 * High-value operation protection
 */
async function protectHighValueOperation(req, res, next) {
  try {
    if (!req.user || !req.session) {
      return next();
    }
    
    // Check active containments
    const activeContainment = await ContainmentAction.findOne({
      affectedUsers: req.user._id,
      status: 'EXECUTED',
      actionType: { $in: ['LOCK_ACCOUNTS', 'REVOKE_SESSIONS', 'RESTRICT_PERMISSIONS'] }
    });
    
    if (activeContainment) {
      await logSecurityEvent({
        eventType: 'HIGH_VALUE_OPERATION_BLOCKED',
        severity: 'HIGH',
        userId: req.user._id,
        sessionId: req.session._id,
        description: 'High-value operation blocked due to active containment',
        metadata: {
          containmentId: activeContainment._id,
          actionType: activeContainment.actionType,
          path: req.path
        }
      });
      
      return res.status(403).json({
        error: 'OPERATION_BLOCKED',
        message: 'This operation is temporarily restricted',
        reason: 'ACTIVE_SECURITY_CONTAINMENT',
        supportContact: 'security@expenseflow.com'
      });
    }
    
    // Check for active correlation clusters
    const activeClusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
    
    if (activeClusters.length > 0) {
      const severity = Math.max(...activeClusters.map(c => {
        const levels = { LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
        return levels[c.severity] || 0;
      }));
      
      if (severity >= 3) { // HIGH or CRITICAL
        await logSecurityEvent({
          eventType: 'HIGH_VALUE_OPERATION_BLOCKED',
          severity: 'HIGH',
          userId: req.user._id,
          sessionId: req.session._id,
          description: 'High-value operation blocked due to correlation cluster',
          metadata: {
            clusterCount: activeClusters.length,
            maxSeverity: severity,
            path: req.path
          }
        });
        
        return res.status(403).json({
          error: 'OPERATION_BLOCKED',
          message: 'This operation requires additional verification',
          reason: 'SECURITY_CORRELATION_DETECTED',
          requiresApproval: true
        });
      }
    }
    
    next();
    
  } catch (error) {
    console.error('[CorrelationMiddleware] Error protecting high-value operation:', error);
    
    // Fail closed for high-value operations
    return res.status(500).json({
      error: 'SECURITY_CHECK_FAILED',
      message: 'Unable to verify security status'
    });
  }
}

/**
 * Handle active containment actions
 */
async function handleActiveContainment(req, res, containment) {
  await logSecurityEvent({
    eventType: 'CONTAINMENT_ENFORCEMENT',
    severity: containment.severity,
    userId: req.user._id,
    sessionId: req.session._id,
    description: `Access denied due to active ${containment.actionType}`,
    metadata: {
      containmentId: containment._id,
      actionType: containment.actionType,
      path: req.path
    }
  });
  
  const messages = {
    LOCK_ACCOUNTS: 'Your account has been temporarily locked due to security concerns',
    REVOKE_SESSIONS: 'Your session has been invalidated due to security concerns',
    REQUIRE_2FA: 'Two-factor authentication is now required',
    RESTRICT_PERMISSIONS: 'Your permissions have been temporarily restricted'
  };
  
  return res.status(403).json({
    error: 'ACCOUNT_CONTAINED',
    message: messages[containment.actionType] || 'Access restricted due to security measures',
    actionType: containment.actionType,
    containmentId: containment._id,
    supportContact: 'security@expenseflow.com',
    canAppeal: containment.isReversible
  });
}

/**
 * Correlation awareness middleware (adds context to req)
 */
async function addCorrelationContext(req, res, next) {
  try {
    if (!req.user || !req.session) {
      return next();
    }
    
    // Add correlation context to request
    req.correlationContext = {
      activeClusters: [],
      activeContainments: [],
      riskLevel: 'LOW'
    };
    
    // Get active clusters
    const clusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
    req.correlationContext.activeClusters = clusters;
    
    // Get active containments
    const containments = await ContainmentAction.getUserContainments(req.user._id);
    req.correlationContext.activeContainments = containments;
    
    // Calculate risk level
    if (containments.some(c => c.status === 'EXECUTED')) {
      req.correlationContext.riskLevel = 'CRITICAL';
    } else if (clusters.some(c => c.severity === 'CRITICAL')) {
      req.correlationContext.riskLevel = 'CRITICAL';
    } else if (clusters.some(c => c.severity === 'HIGH')) {
      req.correlationContext.riskLevel = 'HIGH';
    } else if (clusters.length > 0) {
      req.correlationContext.riskLevel = 'MODERATE';
    }
    
    next();
    
  } catch (error) {
    console.error('[CorrelationMiddleware] Error adding correlation context:', error);
    next(); // Continue despite errors
  }
}

/**
 * Rate limiting based on correlation status
 */
function correlationBasedRateLimit(baseLimit = 100) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.correlationContext) {
        return next();
      }
      
      // Adjust rate limit based on risk level
      const limitMultipliers = {
        LOW: 1,
        MODERATE: 0.5,
        HIGH: 0.25,
        CRITICAL: 0.1
      };
      
      const adjustedLimit = baseLimit * (limitMultipliers[req.correlationContext.riskLevel] || 1);
      
      // Implement rate limiting logic here
      // This is a placeholder - integrate with your rate limiting system
      req.rateLimit = {
        limit: Math.floor(adjustedLimit),
        riskAdjusted: true,
        riskLevel: req.correlationContext.riskLevel
      };
      
      next();
      
    } catch (error) {
      console.error('[CorrelationMiddleware] Error in rate limit adjustment:', error);
      next();
    }
  };
}

/**
 * API endpoint protection wrapper
 */
function protectEndpoint(options = {}) {
  const {
    requireNoCorrelation = false,
    maxSeverity = 'HIGH',
    blockOnContainment = true
  } = options;
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next();
      }
      
      // Check containments
      if (blockOnContainment) {
        const activeContainment = await ContainmentAction.findOne({
          affectedUsers: req.user._id,
          status: 'EXECUTED'
        });
        
        if (activeContainment) {
          return handleActiveContainment(req, res, activeContainment);
        }
      }
      
      // Check correlation clusters
      if (requireNoCorrelation) {
        const clusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
        if (clusters.length > 0) {
          return res.status(403).json({
            error: 'CORRELATION_DETECTED',
            message: 'This operation is not allowed while under security review'
          });
        }
      }
      
      // Check severity threshold
      const severityLevels = { LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
      const maxLevel = severityLevels[maxSeverity] || 3;
      
      const clusters = await SessionCorrelationCluster.getUserClusters(req.user._id);
      const exceedsSeverity = clusters.some(c => severityLevels[c.severity] > maxLevel);
      
      if (exceedsSeverity) {
        return res.status(403).json({
          error: 'SEVERITY_THRESHOLD_EXCEEDED',
          message: 'This operation requires additional verification'
        });
      }
      
      next();
      
    } catch (error) {
      console.error('[CorrelationMiddleware] Error protecting endpoint:', error);
      return res.status(500).json({
        error: 'SECURITY_CHECK_FAILED',
        message: 'Unable to verify security status'
      });
    }
  };
}

/**
 * Log security event
 */
async function logSecurityEvent(event) {
  try {
    await SecurityEvent.create({
      ...event,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('[CorrelationMiddleware] Error logging security event:', error);
  }
}

module.exports = {
  correlationCheck,
  strictCorrelationCheck,
  protectHighValueOperation,
  addCorrelationContext,
  correlationBasedRateLimit,
  protectEndpoint
};
