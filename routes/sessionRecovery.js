const express = require('express');
const router = express.Router();
const sessionHijackingRecoveryService = require('../services/sessionHijackingRecoveryService');
const sessionForensicsService = require('../services/sessionForensicsService');
const SessionHijackingEvent = require('../models/SessionHijackingEvent');
const RecoverySession = require('../models/RecoverySession');
const User = require('../models/User');
const auth = require('../middleware/auth');
const sessionHijackingMiddleware = require('../middleware/sessionHijackingDetection');

/**
 * Session Hijacking Recovery Routes
 * Issue #881: Session Hijacking Prevention & Recovery
 */

/**
 * @route   POST /api/session-recovery/verify-step-up
 * @desc    Verify step-up authentication for recovery session
 * @access  Public (requires recovery token)
 */
router.post('/verify-step-up', async (req, res) => {
  try {
    const { recoveryToken, code, method } = req.body;

    if (!recoveryToken || !code || !method) {
      return res.status(400).json({
        success: false,
        message: 'Recovery token, code, and method are required'
      });
    }

    // Get recovery session
    const recoverySession = await sessionHijackingRecoveryService.getRecoverySessionByToken(
      recoveryToken
    );

    if (!recoverySession) {
      return res.status(404).json({
        success: false,
        message: 'Recovery session not found or expired'
      });
    }

    // Verify step-up authentication
    const result = await sessionHijackingRecoveryService.verifyStepUpAuthentication(
      recoverySession,
      code,
      method
    );

    if (!result.success) {
      return res.status(401).json(result);
    }

    res.json({
      success: true,
      message: 'Step-up authentication successful',
      recoveryToken: result.recoveryToken,
      allowedActions: recoverySession.restrictions.allowedActions
    });
  } catch (error) {
    console.error('[SessionRecovery] Verify step-up error:', error);
    res.status(500).json({
      success: false,
      message: 'Step-up verification failed',
      error: error.message
    });
  }
});

/**
 * @route   POST /api/session-recovery/resend-code
 * @desc    Resend recovery verification code
 * @access  Public (requires recovery token)
 */
router.post('/resend-code', async (req, res) => {
  try {
    const { recoveryToken } = req.body;

    if (!recoveryToken) {
      return res.status(400).json({
        success: false,
        message: 'Recovery token required'
      });
    }

    const recoverySession = await RecoverySession.findOne({
      recoveryToken,
      status: { $in: ['PENDING', 'AUTHENTICATED'] }
    }).populate('userId');

    if (!recoverySession) {
      return res.status(404).json({
        success: false,
        message: 'Recovery session not found'
      });
    }

    // Generate new code
    const crypto = require('crypto');
    const code = sessionHijackingRecoveryService.generateRecoveryCode();
    const hashedCode = crypto.createHash('sha256').update(code).digest('hex');

    // Update recovery session
    recoverySession.stepUpAuthentication.challengeCode = hashedCode;
    recoverySession.stepUpAuthentication.challengeCodeExpiresAt = 
      new Date(Date.now() + sessionHijackingRecoveryService.config.recoveryCodeExpiry);
    await recoverySession.save();

    // Send code
    await sessionHijackingRecoveryService.sendRecoveryCode(recoverySession.userId, code);

    res.json({
      success: true,
      message: 'Verification code resent',
      expiresIn: Math.floor(sessionHijackingRecoveryService.config.recoveryCodeExpiry / 60000)
    });
  } catch (error) {
    console.error('[SessionRecovery] Resend code error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to resend code',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/session-recovery/status
 * @desc    Get recovery session status
 * @access  Private (recovery session)
 */
router.get('/status',
  sessionHijackingMiddleware.validateRecoverySession,
  async (req, res) => {
    try {
      const recoverySession = req.recoverySession;

      const hijackingEvent = await SessionHijackingEvent.findById(
        recoverySession.hijackingEventId
      );

      res.json({
        success: true,
        recovery: {
          sessionId: recoverySession._id,
          status: recoverySession.status,
          createdAt: recoverySession.createdAt,
          expiresAt: recoverySession.expiresAt,
          stepUpCompleted: recoverySession.stepUpAuthentication.completed,
          allowedActions: recoverySession.restrictions.allowedActions,
          actionsPerformed: recoverySession.actionsPerformed.map(a => ({
            action: a.action,
            timestamp: a.timestamp
          }))
        },
        hijacking: {
          detectedAt: hijackingEvent.detectedAt,
          riskScore: hijackingEvent.riskScore,
          detectionMethod: hijackingEvent.detectionMethod,
          indicatorCount: hijackingEvent.indicators.length
        }
      });
    } catch (error) {
      console.error('[SessionRecovery] Get status error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get recovery status',
        error: error.message
      });
    }
  }
);

/**
 * @route   POST /api/session-recovery/change-password
 * @desc    Change password during recovery
 * @access  Private (recovery session)
 */
router.post('/change-password',
  sessionHijackingMiddleware.validateRecoverySession,
  sessionHijackingMiddleware.checkRecoveryPermission('CHANGE_PASSWORD'),
  async (req, res) => {
    try {
      const { newPassword, confirmPassword } = req.body;

      if (!newPassword || !confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'New password and confirmation required'
        });
      }

      if (newPassword !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match'
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters'
        });
      }

      // Execute password change
      const result = await sessionHijackingRecoveryService.executeRecoveryAction(
        req.recoverySession,
        'CHANGE_PASSWORD',
        { newPassword }
      );

      res.json({
        success: true,
        message: 'Password changed successfully',
        result
      });
    } catch (error) {
      console.error('[SessionRecovery] Change password error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to change password',
        error: error.message
      });
    }
  }
);

/**
 * @route   POST /api/session-recovery/revoke-sessions
 * @desc    Revoke all active sessions
 * @access  Private (recovery session)
 */
router.post('/revoke-sessions',
  sessionHijackingMiddleware.validateRecoverySession,
  sessionHijackingMiddleware.checkRecoveryPermission('REVOKE_SESSIONS'),
  async (req, res) => {
    try {
      const result = await sessionHijackingRecoveryService.executeRecoveryAction(
        req.recoverySession,
        'REVOKE_SESSIONS'
      );

      res.json({
        success: true,
        message: 'All sessions revoked',
        result
      });
    } catch (error) {
      console.error('[SessionRecovery] Revoke sessions error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to revoke sessions',
        error: error.message
      });
    }
  }
);

/**
 * @route   POST /api/session-recovery/enable-2fa
 * @desc    Enable 2FA during recovery
 * @access  Private (recovery session)
 */
router.post('/enable-2fa',
  sessionHijackingMiddleware.validateRecoverySession,
  sessionHijackingMiddleware.checkRecoveryPermission('ENABLE_2FA'),
  async (req, res) => {
    try {
      const result = await sessionHijackingRecoveryService.executeRecoveryAction(
        req.recoverySession,
        'ENABLE_2FA'
      );

      res.json({
        success: true,
        message: '2FA enabled successfully',
        result
      });
    } catch (error) {
      console.error('[SessionRecovery] Enable 2FA error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to enable 2FA',
        error: error.message
      });
    }
  }
);

/**
 * @route   GET /api/session-recovery/security-log
 * @desc    Get security log during recovery
 * @access  Private (recovery session)
 */
router.get('/security-log',
  sessionHijackingMiddleware.validateRecoverySession,
  sessionHijackingMiddleware.checkRecoveryPermission('VIEW_SECURITY_LOG'),
  async (req, res) => {
    try {
      const result = await sessionHijackingRecoveryService.executeRecoveryAction(
        req.recoverySession,
        'VIEW_SECURITY_LOG'
      );

      res.json({
        success: true,
        events: result.events
      });
    } catch (error) {
      console.error('[SessionRecovery] Get security log error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get security log',
        error: error.message
      });
    }
  }
);

/**
 * @route   POST /api/session-recovery/complete
 * @desc    Complete recovery process
 * @access  Private (recovery session)
 */
router.post('/complete',
  sessionHijackingMiddleware.validateRecoverySession,
  async (req, res) => {
    try {
      const result = await sessionHijackingRecoveryService.completeRecovery(
        req.recoverySession
      );

      res.json({
        success: true,
        message: 'Recovery completed successfully',
        result
      });
    } catch (error) {
      console.error('[SessionRecovery] Complete recovery error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to complete recovery',
        error: error.message
      });
    }
  }
);

/**
 * @route   GET /api/session-recovery/hijacking-events
 * @desc    Get user's hijacking event history
 * @access  Private
 */
router.get('/hijacking-events',
  auth,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 10;
      
      const events = await SessionHijackingEvent.getUserHistory(req.user._id, limit);

      res.json({
        success: true,
        events: events.map(e => ({
          id: e._id,
          detectedAt: e.detectedAt,
          riskScore: e.riskScore,
          detectionMethod: e.detectionMethod,
          status: e.status,
          containmentExecuted: e.containment.executed,
          recoveryCompleted: e.recovery.restored,
          location: e.suspiciousSession.location
        }))
      });
    } catch (error) {
      console.error('[SessionRecovery] Get hijacking events error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get hijacking events',
        error: error.message
      });
    }
  }
);

/**
 * @route   GET /api/session-recovery/forensics/:eventId
 * @desc    Get forensic report for hijacking event
 * @access  Private (Admin or event owner)
 */
router.get('/forensics/:eventId',
  auth,
  async (req, res) => {
    try {
      const event = await SessionHijackingEvent.findById(req.params.eventId);

      if (!event) {
        return res.status(404).json({
          success: false,
          message: 'Hijacking event not found'
        });
      }

      // Check permissions
      if (event.userId.toString() !== req.user._id.toString() && 
          req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Access denied'
        });
      }

      // Generate forensic report
      const report = await sessionForensicsService.generateForensicReport(event._id);

      res.json({
        success: true,
        report
      });
    } catch (error) {
      console.error('[SessionRecovery] Get forensics error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to generate forensic report',
        error: error.message
      });
    }
  }
);

/**
 * @route   POST /api/session-recovery/report-false-positive/:eventId
 * @desc    Report hijacking detection as false positive
 * @access  Private
 */
router.post('/report-false-positive/:eventId',
  auth,
  async (req, res) => {
    try {
      const { feedback } = req.body;

      const event = await SessionHijackingEvent.findById(req.params.eventId);

      if (!event) {
        return res.status(404).json({
          success: false,
          message: 'Hijacking event not found'
        });
      }

      // Check ownership
      if (event.userId.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Access denied'
        });
      }

      // Update event
      event.userResponse.acknowledged = true;
      event.userResponse.acknowledgedAt = new Date();
      event.userResponse.actionTaken = 'REPORTED_FALSE_POSITIVE';
      event.userResponse.feedback = feedback;
      event.status = 'FALSE_POSITIVE';

      await event.save();

      res.json({
        success: true,
        message: 'False positive reported'
      });
    } catch (error) {
      console.error('[SessionRecovery] Report false positive error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to report false positive',
        error: error.message
      });
    }
  }
);

module.exports = router;
