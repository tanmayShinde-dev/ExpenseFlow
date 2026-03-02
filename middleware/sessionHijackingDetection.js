const sessionHijackingDetectionService = require('../services/sessionHijackingDetectionService');
const sessionHijackingRecoveryService = require('../services/sessionHijackingRecoveryService');
const sessionForensicsService = require('../services/sessionForensicsService');
const Session = require('../models/Session');
const SessionBehaviorProfile = require('../models/SessionBehaviorProfile');

/**
 * Session Hijacking Detection Middleware
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Real-time session hijacking detection and containment
 */

class SessionHijackingMiddleware {
  /**
   * Main middleware function
   */
  static async detectAndContain(req, res, next) {
    try {
      // Skip for non-authenticated requests
      if (!req.user || !req.user._id) {
        return next();
      }

      // Get current session
      const session = await Session.findOne({
        userId: req.user._id,
        jwtId: req.jwtId, // Assuming JWT ID is attached by auth middleware
        status: 'active'
      });

      if (!session) {
        return res.status(401).json({
          success: false,
          message: 'Session not found or expired'
        });
      }

      // Record request for forensics (async, non-blocking)
      sessionForensicsService.recordRequest(session._id, req, res)
        .catch(err => console.error('[SessionHijackingMiddleware] Forensics error:', err));

      // Perform hijacking detection
      const detectionResult = await sessionHijackingDetectionService.detectHijacking(
        req,
        session,
        req.user
      );

      // Store detection result in request for downstream access
      req.hijackingDetection = detectionResult;

      // If hijacking detected, execute containment
      if (detectionResult.hijackingDetected) {
        console.warn('[SessionHijackingMiddleware] HIJACKING DETECTED:', {
          userId: req.user._id,
          sessionId: session._id,
          riskScore: detectionResult.riskScore,
          indicators: detectionResult.indicators.length
        });

        // Create hijacking event
        const event = await sessionHijackingDetectionService.createHijackingEvent(
          detectionResult,
          session,
          req
        );

        // Execute containment
        await sessionHijackingRecoveryService.executeContainment(event, session);

        // Return immediate response
        return res.status(403).json({
          success: false,
          error: 'SESSION_HIJACKING_DETECTED',
          message: 'Suspicious activity detected. Your session has been terminated for security.',
          details: {
            riskScore: detectionResult.riskScore,
            detectionMethod: detectionResult.detectionMethod,
            hijackingEventId: event._id
          },
          recovery: {
            available: true,
            message: 'Check your email for account recovery instructions'
          }
        });
      }

      // If medium risk, issue challenge but allow request to continue
      if (detectionResult.riskScore >= 50 && detectionResult.riskScore < 75) {
        req.securityChallenge = {
          required: true,
          reason: 'Suspicious activity detected',
          riskScore: detectionResult.riskScore
        };
      }

      // Update session activity
      session.activity.lastAccessAt = new Date();
      session.activity.lastAccessIp = req.ip || req.connection?.remoteAddress;
      session.activity.accessCount += 1;
      session.activity.lastEndpoint = req.originalUrl;
      await session.save();

      next();
    } catch (error) {
      console.error('[SessionHijackingMiddleware] Error:', error);
      // Don't block request on middleware error
      next();
    }
  }

  /**
   * Behavioral tracking middleware
   */
  static async trackBehavior(req, res, next) {
    try {
      // Skip for non-authenticated requests
      if (!req.user || !req.user._id) {
        return next();
      }

      const session = await Session.findOne({
        userId: req.user._id,
        jwtId: req.jwtId,
        status: 'active'
      });

      if (session) {
        // Get or create behavior profile
        const profile = await SessionBehaviorProfile.getOrCreate(session._id, req.user._id);

        // Record request (async)
        profile.recordRequest(req)
          .catch(err => console.error('[SessionHijackingMiddleware] Behavior tracking error:', err));
      }

      next();
    } catch (error) {
      console.error('[SessionHijackingMiddleware] Behavior tracking error:', error);
      // Don't block request
      next();
    }
  }

  /**
   * Response time tracking middleware
   */
  static responseTimeTracker(req, res, next) {
    const startTime = Date.now();

    // Intercept response finish
    res.on('finish', () => {
      res.locals.responseTime = Date.now() - startTime;
    });

    next();
  }

  /**
   * Data access audit middleware
   */
  static auditDataAccess(resource, action) {
    return async (req, res, next) => {
      try {
        // Skip for non-authenticated requests
        if (!req.user || !req.user._id) {
          return next();
        }

        const session = await Session.findOne({
          userId: req.user._id,
          jwtId: req.jwtId,
          status: 'active'
        });

        if (session) {
          // Determine if resource is sensitive
          const sensitiveResources = [
            'users',
            'accounts',
            'payments',
            'security',
            'audit',
            'admin'
          ];
          const isSensitive = sensitiveResources.some(sr => resource.includes(sr));

          // Record data access after request completes
          res.on('finish', () => {
            if (res.statusCode < 400) {
              // Only audit successful requests
              const recordIds = req.body?.ids || req.params?.id ? [req.params.id] : [];
              
              sessionForensicsService.recordDataAccess(
                session._id,
                req.user._id,
                resource,
                action,
                recordIds,
                isSensitive
              ).catch(err => console.error('[SessionHijackingMiddleware] Audit error:', err));
            }
          });
        }

        next();
      } catch (error) {
        console.error('[SessionHijackingMiddleware] Audit error:', error);
        // Don't block request
        next();
      }
    };
  }

  /**
   * Check if request requires security challenge
   */
  static checkSecurityChallenge(req, res, next) {
    if (req.securityChallenge && req.securityChallenge.required) {
      // Challenge can be handled in various ways:
      // 1. Return challenge requirement to client
      // 2. Force 2FA
      // 3. Step-up authentication

      const challengeType = req.user.twoFactorEnabled ? '2FA' : 'EMAIL_CODE';

      return res.status(403).json({
        success: false,
        error: 'SECURITY_CHALLENGE_REQUIRED',
        message: 'Additional verification required to continue',
        challenge: {
          type: challengeType,
          reason: req.securityChallenge.reason,
          riskScore: req.securityChallenge.riskScore
        }
      });
    }

    next();
  }

  /**
   * Recovery session validator
   */
  static async validateRecoverySession(req, res, next) {
    try {
      const recoveryToken = req.headers['x-recovery-token'] || req.query.recoveryToken;

      if (!recoveryToken) {
        return res.status(401).json({
          success: false,
          message: 'Recovery token required'
        });
      }

      const recoverySession = await sessionHijackingRecoveryService.getRecoverySessionByToken(
        recoveryToken
      );

      if (!recoverySession) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired recovery token'
        });
      }

      // Check if expired
      if (recoverySession.isExpired()) {
        return res.status(401).json({
          success: false,
          message: 'Recovery session expired'
        });
      }

      // Check if step-up authentication is required
      if (recoverySession.stepUpAuthentication.required && 
          !recoverySession.stepUpAuthentication.completed) {
        return res.status(403).json({
          success: false,
          message: 'Step-up authentication required',
          stepUpMethod: recoverySession.stepUpAuthentication.method
        });
      }

      // Attach recovery session to request
      req.recoverySession = recoverySession;
      req.user = await recoverySession.populate('userId');

      next();
    } catch (error) {
      console.error('[SessionHijackingMiddleware] Recovery validation error:', error);
      return res.status(500).json({
        success: false,
        message: 'Recovery session validation failed'
      });
    }
  }

  /**
   * Check if action is allowed in recovery mode
   */
  static checkRecoveryPermission(action) {
    return (req, res, next) => {
      if (!req.recoverySession) {
        return res.status(401).json({
          success: false,
          message: 'Recovery session required'
        });
      }

      if (!req.recoverySession.isActionAllowed(action)) {
        return res.status(403).json({
          success: false,
          message: `Action ${action} not allowed in recovery mode`,
          allowedActions: req.recoverySession.restrictions.allowedActions
        });
      }

      next();
    };
  }

  /**
   * Apply hijacking detection to specific routes
   */
  static applyToRoutes(app, routes = []) {
    routes.forEach(route => {
      app.use(route, this.responseTimeTracker);
      app.use(route, this.trackBehavior);
      app.use(route, this.detectAndContain);
      app.use(route, this.checkSecurityChallenge);
    });
  }

  /**
   * Apply data access auditing to specific routes
   */
  static applyAuditing(router, resource, action) {
    return this.auditDataAccess(resource, action);
  }
}

module.exports = SessionHijackingMiddleware;
