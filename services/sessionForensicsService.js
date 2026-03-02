const SessionHijackingEvent = require('../models/SessionHijackingEvent');
const AuditLog = require('../models/AuditLog');
const SecurityEvent = require('../models/SecurityEvent');
const Session = require('../models/Session');

/**
 * Session Forensics Service
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Provides forensic analysis capabilities including:
 * - Session replay
 * - Data access auditing
 * - Request pattern analysis
 * - Timeline reconstruction
 */

class SessionForensicsService {
  /**
   * Initialize forensics collection for a session
   */
  static async initializeForensics(sessionId) {
    try {
      // Create forensics tracking for session
      return {
        sessionId,
        startTime: new Date(),
        requestLog: [],
        dataAccessLog: [],
        enabled: true
      };
    } catch (error) {
      console.error('[SessionForensics] Initialize error:', error);
      throw error;
    }
  }

  /**
   * Record request for forensics
   */
  static async recordRequest(sessionId, req, res) {
    try {
      const requestData = {
        timestamp: new Date(),
        method: req.method,
        endpoint: req.originalUrl || req.url,
        statusCode: res.statusCode,
        responseTime: res.locals.responseTime || 0,
        ipAddress: req.ip || req.connection?.remoteAddress,
        userAgent: req.headers['user-agent'],
        headers: this.sanitizeHeaders(req.headers),
        query: req.query,
        body: this.sanitizeBody(req.body),
        cookies: this.sanitizeCookies(req.cookies)
      };

      // Store in session's forensic log
      // This would typically be stored in a separate forensics collection
      // or added to the SessionHijackingEvent when anomaly is detected

      return requestData;
    } catch (error) {
      console.error('[SessionForensics] Record request error:', error);
      return null;
    }
  }

  /**
   * Record data access for forensics
   */
  static async recordDataAccess(sessionId, userId, resource, action, recordIds = [], sensitive = false) {
    try {
      const accessData = {
        timestamp: new Date(),
        sessionId,
        userId,
        resource,
        action,
        recordIds: recordIds.slice(0, 100), // Limit to prevent large arrays
        sensitive
      };

      // Log to audit system
      await AuditLog.create({
        userId,
        action,
        resource,
        details: {
          sessionId,
          recordCount: recordIds.length,
          sensitive,
          recordIds: recordIds.slice(0, 10) // Only store first 10 in audit
        },
        ipAddress: 'system',
        userAgent: 'forensics-service'
      });

      return accessData;
    } catch (error) {
      console.error('[SessionForensics] Record data access error:', error);
      return null;
    }
  }

  /**
   * Generate session replay data
   */
  static async generateSessionReplay(hijackingEventId) {
    try {
      const event = await SessionHijackingEvent.findById(hijackingEventId);
      
      if (!event) {
        throw new Error('Hijacking event not found');
      }

      const session = await Session.findById(event.sessionId);
      
      if (!session) {
        throw new Error('Session not found');
      }

      // Get audit logs for this session
      const auditLogs = await AuditLog.find({
        userId: event.userId,
        createdAt: {
          $gte: session.createdAt,
          $lte: event.detectedAt
        }
      }).sort({ createdAt: 1 });

      // Get security events for this session
      const securityEvents = await SecurityEvent.find({
        userId: event.userId,
        createdAt: {
          $gte: session.createdAt,
          $lte: event.detectedAt
        }
      }).sort({ createdAt: 1 });

      // Build timeline
      const timeline = this.buildTimeline(
        session,
        event.forensics.requestLog,
        auditLogs,
        securityEvents
      );

      // Analyze patterns
      const patterns = this.analyzeSessionPatterns(timeline);

      // Identify suspicious activities
      const suspiciousActivities = this.identifySuspiciousActivities(
        timeline,
        patterns,
        event
      );

      // Generate replay data
      const replay = {
        sessionId: session._id,
        userId: event.userId,
        startTime: session.createdAt,
        endTime: event.detectedAt,
        duration: event.detectedAt - session.createdAt,
        timeline,
        patterns,
        suspiciousActivities,
        statistics: {
          totalRequests: timeline.filter(e => e.type === 'request').length,
          totalDataAccess: timeline.filter(e => e.type === 'data_access').length,
          securityEvents: securityEvents.length,
          suspiciousCount: suspiciousActivities.length
        }
      };

      // Store replay in hijacking event
      event.forensics.sessionReplayAvailable = true;
      event.forensics.requestLog = event.forensics.requestLog || [];
      await event.save();

      return replay;
    } catch (error) {
      console.error('[SessionForensics] Generate replay error:', error);
      throw error;
    }
  }

  /**
   * Build timeline from various logs
   */
  static buildTimeline(session, requestLog = [], auditLogs = [], securityEvents = []) {
    const timeline = [];

    // Add session start
    timeline.push({
      timestamp: session.createdAt,
      type: 'session_start',
      data: {
        sessionId: session._id,
        ipAddress: session.location?.ipAddress,
        device: session.device,
        location: session.location
      }
    });

    // Add requests
    requestLog.forEach(req => {
      timeline.push({
        timestamp: req.timestamp,
        type: 'request',
        data: req
      });
    });

    // Add audit logs
    auditLogs.forEach(log => {
      timeline.push({
        timestamp: log.createdAt,
        type: 'audit',
        data: {
          action: log.action,
          resource: log.resource,
          details: log.details
        }
      });
    });

    // Add security events
    securityEvents.forEach(event => {
      timeline.push({
        timestamp: event.createdAt,
        type: 'security_event',
        data: {
          eventType: event.eventType,
          severity: event.severity,
          details: event.details
        }
      });
    });

    // Sort by timestamp
    timeline.sort((a, b) => a.timestamp - b.timestamp);

    return timeline;
  }

  /**
   * Analyze session patterns
   */
  static analyzeSessionPatterns(timeline) {
    const patterns = {
      requestCadence: [],
      endpointFrequency: {},
      hourlyDistribution: new Array(24).fill(0),
      methodDistribution: {},
      activityBursts: [],
      accessPatterns: {}
    };

    const requests = timeline.filter(e => e.type === 'request');

    // Calculate request cadence
    for (let i = 1; i < requests.length; i++) {
      const interval = requests[i].timestamp - requests[i - 1].timestamp;
      patterns.requestCadence.push(interval);
    }

    // Endpoint frequency
    requests.forEach(req => {
      const endpoint = req.data.endpoint;
      patterns.endpointFrequency[endpoint] = (patterns.endpointFrequency[endpoint] || 0) + 1;
    });

    // Hourly distribution
    requests.forEach(req => {
      const hour = new Date(req.timestamp).getHours();
      patterns.hourlyDistribution[hour]++;
    });

    // Method distribution
    requests.forEach(req => {
      const method = req.data.method;
      patterns.methodDistribution[method] = (patterns.methodDistribution[method] || 0) + 1;
    });

    // Detect activity bursts (> 10 requests in 30 seconds)
    const burstWindow = 30000; // 30 seconds
    const burstThreshold = 10;

    for (let i = 0; i < requests.length; i++) {
      const windowStart = requests[i].timestamp;
      const windowEnd = new Date(windowStart.getTime() + burstWindow);
      
      const burstRequests = requests.filter(r => 
        r.timestamp >= windowStart && r.timestamp <= windowEnd
      );

      if (burstRequests.length >= burstThreshold) {
        patterns.activityBursts.push({
          startTime: windowStart,
          endTime: windowEnd,
          requestCount: burstRequests.length,
          endpoints: burstRequests.map(r => r.data.endpoint)
        });
        i += burstRequests.length; // Skip analyzed requests
      }
    }

    // Access patterns
    const dataAccess = timeline.filter(e => e.type === 'audit');
    dataAccess.forEach(access => {
      const resource = access.data.resource;
      if (!patterns.accessPatterns[resource]) {
        patterns.accessPatterns[resource] = {
          count: 0,
          actions: {},
          firstAccess: access.timestamp,
          lastAccess: access.timestamp
        };
      }
      patterns.accessPatterns[resource].count++;
      patterns.accessPatterns[resource].lastAccess = access.timestamp;
      
      const action = access.data.action;
      patterns.accessPatterns[resource].actions[action] = 
        (patterns.accessPatterns[resource].actions[action] || 0) + 1;
    });

    return patterns;
  }

  /**
   * Identify suspicious activities
   */
  static identifySuspiciousActivities(timeline, patterns, hijackingEvent) {
    const suspicious = [];

    // Check for activity bursts
    if (patterns.activityBursts.length > 0) {
      patterns.activityBursts.forEach(burst => {
        suspicious.push({
          type: 'ACTIVITY_BURST',
          severity: 'high',
          timestamp: burst.startTime,
          description: `Unusual activity burst: ${burst.requestCount} requests in 30 seconds`,
          details: burst
        });
      });
    }

    // Check for unusual endpoint access
    const rareEndpoints = Object.entries(patterns.endpointFrequency)
      .filter(([endpoint, count]) => count === 1)
      .map(([endpoint]) => endpoint);

    if (rareEndpoints.length > 0) {
      suspicious.push({
        type: 'RARE_ENDPOINT_ACCESS',
        severity: 'medium',
        timestamp: new Date(),
        description: `Accessed ${rareEndpoints.length} endpoints only once`,
        details: { endpoints: rareEndpoints.slice(0, 10) }
      });
    }

    // Check for data access anomalies
    Object.entries(patterns.accessPatterns).forEach(([resource, data]) => {
      // High volume access
      if (data.count > 100) {
        suspicious.push({
          type: 'HIGH_VOLUME_ACCESS',
          severity: 'high',
          timestamp: data.lastAccess,
          description: `Excessive access to ${resource}: ${data.count} times`,
          details: { resource, count: data.count, actions: data.actions }
        });
      }

      // Check for delete operations
      if (data.actions.DELETE || data.actions.delete) {
        suspicious.push({
          type: 'DELETE_OPERATION',
          severity: 'critical',
          timestamp: data.lastAccess,
          description: `Delete operations performed on ${resource}`,
          details: { resource, deleteCount: data.actions.DELETE || data.actions.delete }
        });
      }
    });

    // Check for privilege escalation from hijacking event
    if (hijackingEvent.indicators) {
      const privilegeIndicators = hijackingEvent.indicators.filter(
        i => i.type === 'PRIVILEGE_ESCALATION'
      );

      privilegeIndicators.forEach(indicator => {
        suspicious.push({
          type: 'PRIVILEGE_ESCALATION',
          severity: 'critical',
          timestamp: indicator.timestamp,
          description: 'Attempted privilege escalation detected',
          details: indicator.details
        });
      });
    }

    // Sort by timestamp
    suspicious.sort((a, b) => a.timestamp - b.timestamp);

    return suspicious;
  }

  /**
   * Generate forensic report
   */
  static async generateForensicReport(hijackingEventId) {
    try {
      const event = await SessionHijackingEvent.findById(hijackingEventId)
        .populate('userId')
        .populate('sessionId');

      if (!event) {
        throw new Error('Hijacking event not found');
      }

      // Generate session replay
      const replay = await this.generateSessionReplay(hijackingEventId);

      // Build report
      const report = {
        eventId: event._id,
        generatedAt: new Date(),
        user: {
          id: event.userId._id,
          email: event.userId.email,
          name: event.userId.name
        },
        detection: {
          detectedAt: event.detectedAt,
          detectionMethod: event.detectionMethod,
          riskScore: event.riskScore,
          confidenceLevel: event.confidenceLevel,
          indicators: event.indicators
        },
        session: {
          sessionId: event.sessionId._id,
          createdAt: event.sessionId.createdAt,
          originalIP: event.originalSession.ipAddress,
          originalLocation: event.originalSession.location,
          suspiciousIP: event.suspiciousSession.ipAddress,
          suspiciousLocation: event.suspiciousSession.location
        },
        forensics: {
          timeline: replay.timeline,
          patterns: replay.patterns,
          suspiciousActivities: replay.suspiciousActivities,
          statistics: replay.statistics
        },
        containment: {
          executed: event.containment.executed,
          executedAt: event.containment.executedAt,
          actions: event.containment.actions
        },
        recovery: {
          initiated: event.recovery.initiated,
          completed: event.recovery.restored,
          stepUpCompleted: event.recovery.stepUpChallengeCompleted
        },
        analysis: this.generateAnalysis(event, replay),
        recommendations: this.generateRecommendations(event, replay)
      };

      // Store report in event
      event.forensics.forensicAnalysisCompleted = true;
      event.forensics.forensicReport = JSON.stringify(report);
      await event.save();

      return report;
    } catch (error) {
      console.error('[SessionForensics] Generate report error:', error);
      throw error;
    }
  }

  /**
   * Generate analysis summary
   */
  static generateAnalysis(event, replay) {
    const analysis = {
      summary: '',
      keyFindings: [],
      attackVector: '',
      impactAssessment: ''
    };

    // Generate summary
    analysis.summary = `Session hijacking detected with risk score ${event.riskScore}/100. ` +
      `${event.indicators.length} indicators identified. ` +
      `Session activity monitored for ${Math.floor((event.detectedAt - event.sessionId.createdAt) / 60000)} minutes.`;

    // Key findings
    if (event.indicators.find(i => i.type === 'IMPOSSIBLE_LOCATION')) {
      analysis.keyFindings.push('Impossible travel detected between geographic locations');
    }
    if (event.indicators.find(i => i.type === 'DEVICE_FINGERPRINT_SWAP')) {
      analysis.keyFindings.push('Device fingerprint changed during active session');
    }
    if (event.indicators.find(i => i.type === 'BEHAVIORAL_DIVERGENCE')) {
      analysis.keyFindings.push('Significant behavioral divergence from established baseline');
    }
    if (replay.suspiciousActivities.find(a => a.type === 'DELETE_OPERATION')) {
      analysis.keyFindings.push('Delete operations performed during suspicious session');
    }

    // Attack vector
    const primaryIndicator = event.indicators[0];
    analysis.attackVector = this.determineAttackVector(primaryIndicator?.type);

    // Impact assessment
    const sensitiveAccess = replay.timeline.filter(
      e => e.type === 'audit' && e.data.details?.sensitive
    ).length;
    
    analysis.impactAssessment = sensitiveAccess > 0
      ? `High impact: ${sensitiveAccess} sensitive resource access attempts detected`
      : 'Moderate impact: No sensitive data access detected';

    return analysis;
  }

  /**
   * Determine likely attack vector
   */
  static determineAttackVector(indicatorType) {
    const vectors = {
      'IMPOSSIBLE_LOCATION': 'Possible session token theft or man-in-the-middle attack',
      'DEVICE_FINGERPRINT_SWAP': 'Likely session token theft and replay from different device',
      'BEHAVIORAL_DIVERGENCE': 'Possible credential compromise or session hijacking',
      'PRIVILEGE_ESCALATION': 'Targeted attack attempting unauthorized access',
      'REQUEST_PATTERN_ANOMALY': 'Possible automated attack or bot activity'
    };

    return vectors[indicatorType] || 'Unknown attack vector';
  }

  /**
   * Generate recommendations
   */
  static generateRecommendations(event, replay) {
    const recommendations = [];

    // Based on indicators
    if (event.indicators.find(i => i.type === 'BEHAVIORAL_DIVERGENCE')) {
      recommendations.push({
        priority: 'high',
        recommendation: 'Implement stricter behavioral monitoring and baseline refinement',
        action: 'Review and adjust behavioral anomaly detection thresholds'
      });
    }

    if (event.indicators.find(i => i.type === 'DEVICE_FINGERPRINT_SWAP')) {
      recommendations.push({
        priority: 'high',
        recommendation: 'Enforce device binding for sensitive operations',
        action: 'Require device re-verification for high-risk actions'
      });
    }

    // Based on user 2FA status
    if (!event.userId.twoFactorEnabled) {
      recommendations.push({
        priority: 'critical',
        recommendation: 'Enforce mandatory 2FA for all users',
        action: 'Require 2FA enrollment for account recovery'
      });
    }

    // Based on suspicious activities
    if (replay.suspiciousActivities.length > 5) {
      recommendations.push({
        priority: 'high',
        recommendation: 'Implement real-time activity monitoring alerts',
        action: 'Set up automated alerts for suspicious activity patterns'
      });
    }

    // General recommendations
    recommendations.push({
      priority: 'medium',
      recommendation: 'Regular security awareness training',
      action: 'Educate users about session security and phishing prevention'
    });

    return recommendations;
  }

  /**
   * Sanitize headers for logging
   */
  static sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    const sensitive = ['authorization', 'cookie', 'x-api-key'];
    
    sensitive.forEach(key => {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  /**
   * Sanitize body for logging
   */
  static sanitizeBody(body) {
    if (!body || typeof body !== 'object') {
      return body;
    }

    const sanitized = { ...body };
    const sensitive = ['password', 'token', 'secret', 'apiKey', 'creditCard'];

    sensitive.forEach(key => {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  /**
   * Sanitize cookies for logging
   */
  static sanitizeCookies(cookies) {
    if (!cookies || typeof cookies !== 'object') {
      return cookies;
    }

    const sanitized = { ...cookies };
    Object.keys(sanitized).forEach(key => {
      sanitized[key] = '[REDACTED]';
    });

    return sanitized;
  }
}

module.exports = SessionForensicsService;
