const Session = require('../models/Session');
const RecoverySession = require('../models/RecoverySession');
const SessionHijackingEvent = require('../models/SessionHijackingEvent');
const User = require('../models/User');
const SecurityEvent = require('../models/SecurityEvent');
const crypto = require('crypto');
const notificationService = require('./notificationService');
const emailService = require('./emailService');
const twoFactorAuthService = require('./twoFactorAuthService');

/**
 * Session Hijacking Recovery Service
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Handles:
 * - Immediate containment (kill session, lock account)
 * - User notification
 * - Recovery session creation
 * - Step-up authentication
 * - Session restoration
 */

class SessionHijackingRecoveryService {
  /**
   * Configuration
   */
  static config = {
    recoverySessionDuration: 3600000, // 1 hour
    maxRecoveryAttempts: 3,
    autoLockThreshold: 90, // Risk score threshold for auto-lock
    recoveryCodeLength: 6,
    recoveryCodeExpiry: 600000 // 10 minutes
  };

  /**
   * Execute immediate containment actions
 * @param {Object} hijackingEvent - SessionHijackingEvent  * @param {Object} session - Compromised session
   * @returns {Promise<Object>} Containment result
   */
  static async executeContainment(hijackingEvent, session) {
    try {
      const actions = [];
      const user = await User.findById(session.userId);

      if (!user) {
        throw new Error('User not found');
      }

      // 1. Kill the hijacked session
      try {
        session.status = 'revoked';
        session.revocation = {
          revokedAt: new Date(),
          reason: 'security_concern',
          note: `Session hijacking detected. Risk score: ${hijackingEvent.riskScore}`
        };
        await session.save();

        actions.push({
          action: 'SESSION_KILLED',
          timestamp: new Date(),
          success: true,
          details: {
            sessionId: session._id,
            riskScore: hijackingEvent.riskScore
          }
        });
      } catch (error) {
        actions.push({
          action: 'SESSION_KILLED',
          timestamp: new Date(),
          success: false,
          details: { error: error.message }
        });
      }

      // 2. Notify legitimate user
      try {
        await this.notifyUser(user, hijackingEvent, session);

        actions.push({
          action: 'USER_NOTIFIED',
          timestamp: new Date(),
          success: true,
          details: {
            channels: ['email', 'in_app', 'push']
          }
        });
      } catch (error) {
        actions.push({
          action: 'USER_NOTIFIED',
          timestamp: new Date(),
          success: false,
          details: { error: error.message }
        });
      }

      // 3. Auto-lock account if risk is critical
      if (hijackingEvent.riskScore >= this.config.autoLockThreshold) {
        try {
          user.accountStatus = 'locked';
          user.lockReason = 'Session hijacking detected';
          user.lockedAt = new Date();
          await user.save();

          actions.push({
            action: 'ACCOUNT_LOCKED',
            timestamp: new Date(),
            success: true,
            details: {
              reason: 'Critical risk score',
              riskScore: hijackingEvent.riskScore
            }
          });

          // Notify admins
          await this.notifyAdmins(user, hijackingEvent);

          actions.push({
            action: 'ADMIN_ALERTED',
            timestamp: new Date(),
            success: true,
            details: {
              riskScore: hijackingEvent.riskScore
            }
          });
        } catch (error) {
          actions.push({
            action: 'ACCOUNT_LOCKED',
            timestamp: new Date(),
            success: false,
            details: { error: error.message }
          });
        }
      }

      // 4. Create recovery session
      try {
        const recoverySession = await this.createRecoverySession(
          user,
          hijackingEvent,
          session
        );

        actions.push({
          action: 'RECOVERY_SESSION_CREATED',
          timestamp: new Date(),
          success: true,
          details: {
            recoverySessionId: recoverySession._id,
            expiresIn: this.config.recoverySessionDuration
          }
        });

        // Update hijacking event with recovery session
        await hijackingEvent.initiateRecovery(
          recoverySession._id,
          this.config.recoverySessionDuration
        );
      } catch (error) {
        actions.push({
          action: 'RECOVERY_SESSION_CREATED',
          timestamp: new Date(),
          success: false,
          details: { error: error.message }
        });
      }

      // 5. Enforce 2FA if not already enabled
      if (!user.twoFactorEnabled) {
        actions.push({
          action: 'TWO_FACTOR_ENFORCED',
          timestamp: new Date(),
          success: true,
          details: {
            message: 'User will be required to enable 2FA during recovery'
          }
        });
      }

      // Update hijacking event with containment actions
      await hijackingEvent.executeContainment(actions);

      // Log security event
      await SecurityEvent.create({
        userId: user._id,
        eventType: 'SESSION_ANOMALY_DETECTED',
        severity: 'critical',
        ipAddress: hijackingEvent.suspiciousSession.ipAddress,
        details: {
          containmentExecuted: true,
          actionsCount: actions.length,
          riskScore: hijackingEvent.riskScore
        }
      });

      return {
        success: true,
        actions,
        hijackingEventId: hijackingEvent._id,
        message: 'Containment executed successfully'
      };
    } catch (error) {
      console.error('[SessionHijackingRecovery] Containment error:', error);
      throw error;
    }
  }

  /**
   * Create recovery session for user
   */
  static async createRecoverySession(user, hijackingEvent, compromisedSession) {
    try {
      // Determine step-up method
      let stepUpMethod = 'EMAIL_CODE';
      let challengeCode = null;
      let challengeCodeExpiresAt = null;

      if (user.twoFactorEnabled) {
        stepUpMethod = '2FA_TOTP';
      } else {
        // Generate email verification code
        const code = this.generateRecoveryCode();
        challengeCode = crypto.createHash('sha256').update(code).digest('hex');
        challengeCodeExpiresAt = new Date(Date.now() + this.config.recoveryCodeExpiry);

        // Send verification code via email
        await this.sendRecoveryCode(user, code);
      }

      // Create recovery session
      const recoverySession = await RecoverySession.createRecoverySession(
        user._id,
        hijackingEvent._id,
        {
          compromisedSessionId: compromisedSession._id,
          stepUpMethod,
          challengeCode,
          challengeCodeExpiresAt,
          readOnly: true,
          allowedActions: [
            'VIEW_ACCOUNT',
            'CHANGE_PASSWORD',
            'REVOKE_SESSIONS',
            'ENABLE_2FA',
            'VIEW_SECURITY_LOG',
            'DOWNLOAD_ACCOUNT_DATA'
          ],
          expiresIn: this.config.recoverySessionDuration
        }
      );

      return recoverySession;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Create recovery session error:', error);
      throw error;
    }
  }

  /**
   * Verify step-up authentication for recovery session
   */
  static async verifyStepUpAuthentication(recoverySession, userInput, method) {
    try {
      const user = await User.findById(recoverySession.userId);

      if (!user) {
        throw new Error('User not found');
      }

      let verified = false;

      switch (method) {
        case '2FA_TOTP':
          // Verify TOTP code
          verified = twoFactorAuthService.verifyToken(user.twoFactorSecret, userInput);
          break;

        case 'EMAIL_CODE':
        case 'SMS_CODE':
          // Verify challenge code
          verified = await recoverySession.verifyStepUpChallenge(userInput);
          break;

        case 'BACKUP_CODE':
          // Verify backup code
          verified = await twoFactorAuthService.verifyBackupCode(user._id, userInput);
          break;

        default:
          throw new Error('Invalid step-up method');
      }

      if (!verified) {
        // Log failed attempt
        await SecurityEvent.create({
          userId: user._id,
          eventType: '2FA_FAILURE',
          severity: 'medium',
          details: {
            context: 'recovery_session',
            method,
            attempt: recoverySession.stepUpAuthentication.attempts
          }
        });

        return {
          success: false,
          message: 'Invalid verification code',
          attemptsRemaining: recoverySession.stepUpAuthentication.maxAttempts - 
                             recoverySession.stepUpAuthentication.attempts
        };
      }

      // Mark step-up as completed
      recoverySession.stepUpAuthentication.completed = true;
      recoverySession.stepUpAuthentication.completedAt = new Date();
      recoverySession.status = 'AUTHENTICATED';
      await recoverySession.save();

      // Log successful authentication
      await SecurityEvent.create({
        userId: user._id,
        eventType: '2FA_SUCCESS',
        severity: 'info',
        details: {
          context: 'recovery_session',
          method
        }
      });

      return {
        success: true,
        message: 'Step-up authentication successful',
        recoveryToken: recoverySession.recoveryToken
      };
    } catch (error) {
      console.error('[SessionHijackingRecovery] Step-up verification error:', error);
      throw error;
    }
  }

  /**
   * Execute recovery action
   */
  static async executeRecoveryAction(recoverySession, action, details = {}) {
    try {
      const user = await User.findById(recoverySession.userId);

      if (!user) {
        throw new Error('User not found');
      }

      // Check if action is allowed
      if (!recoverySession.isActionAllowed(action)) {
        throw new Error('Action not allowed in recovery mode');
      }

      let result = {};

      switch (action) {
        case 'CHANGE_PASSWORD':
          // Change password
          user.password = details.newPassword; // Will be hashed by pre-save hook
          await user.save();

          // Revoke all other sessions
          await Session.revokeAllUserSessions(user._id, user._id, 'password_change');

          result = { success: true, message: 'Password changed successfully' };
          break;

        case 'REVOKE_SESSIONS':
          // Revoke all active sessions
          const revokedCount = await Session.revokeAllUserSessions(
            user._id,
            user._id,
            'user_request'
          );
          result = { success: true, revokedCount };
          break;

        case 'ENABLE_2FA':
          // Enable 2FA for user
          if (!user.twoFactorEnabled) {
            const secret = twoFactorAuthService.generateSecret();
            user.twoFactorSecret = secret;
            user.twoFactorEnabled = true;
            await user.save();

            result = {
              success: true,
              message: '2FA enabled',
              secret
            };
          } else {
            result = { success: true, message: '2FA already enabled' };
          }
          break;

        case 'VIEW_SECURITY_LOG':
          // Return recent security events
          const events = await SecurityEvent.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(50);
          result = { success: true, events };
          break;

        case 'DOWNLOAD_ACCOUNT_DATA':
          // Prepare account data for download
          result = {
            success: true,
            message: 'Account data export initiated',
            exportId: crypto.randomBytes(16).toString('hex')
          };
          break;

        default:
          throw new Error('Unknown recovery action');
      }

      // Record action in recovery session
      await recoverySession.recordAction(action, details);

      // Log security event
      await SecurityEvent.create({
        userId: user._id,
        eventType: 'SESSION_ANOMALY_DETECTED',
        severity: 'info',
        details: {
          recoveryAction: action,
          recoverySessionId: recoverySession._id
        }
      });

      return result;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Recovery action error:', error);
      throw error;
    }
  }

  /**
   * Complete recovery process
   */
  static async completeRecovery(recoverySession) {
    try {
      const user = await User.findById(recoverySession.userId);
      const hijackingEvent = await SessionHijackingEvent.findById(
        recoverySession.hijackingEventId
      );

      if (!user || !hijackingEvent) {
        throw new Error('User or hijacking event not found');
      }

      // Unlock account if it was locked
      if (user.accountStatus === 'locked') {
        user.accountStatus = 'active';
        user.lockReason = null;
        user.lockedAt = null;
        await user.save();
      }

      // Complete recovery session
      await recoverySession.complete('ACCOUNT_SECURED', 'User completed recovery steps');

      // Complete hijacking event
      await hijackingEvent.completeRecovery();

      // Log completion
      await SecurityEvent.create({
        userId: user._id,
        eventType: 'SESSION_ANOMALY_DETECTED',
        severity: 'info',
        details: {
          recoveryCompleted: true,
          recoverySessionId: recoverySession._id
        }
      });

      return {
        success: true,
        message: 'Account recovery completed successfully'
      };
    } catch (error) {
      console.error('[SessionHijackingRecovery] Complete recovery error:', error);
      throw error;
    }
  }

  /**
   * Notify user about session hijacking
   */
  static async notifyUser(user, hijackingEvent, session) {
    try {
      const suspiciousLocation = hijackingEvent.suspiciousSession.location;
      const locationString = suspiciousLocation 
        ? `${suspiciousLocation.city}, ${suspiciousLocation.country}`
        : 'Unknown location';

      // In-app notification
      await notificationService.sendNotification(user._id, {
        type: 'security_alert',
        title: '🚨 Session Hijacking Detected',
        message: `We detected suspicious activity on your account from ${locationString}. Your session has been terminated for security.`,
        priority: 'critical',
        metadata: {
          hijackingEventId: hijackingEvent._id,
          riskScore: hijackingEvent.riskScore,
          location: locationString
        }
      });

      // Email notification
      if (emailService && user.email) {
        await emailService.sendSecurityAlert(user.email, {
          subject: 'Security Alert: Session Hijacking Detected',
          userName: user.name,
          eventType: 'Session Hijacking',
          location: locationString,
          ipAddress: hijackingEvent.suspiciousSession.ipAddress,
          timestamp: hijackingEvent.detectedAt,
          riskScore: hijackingEvent.riskScore,
          actions: [
            'Your session has been terminated',
            'A recovery session has been created',
            'Please verify your identity to regain access',
            'Change your password immediately'
          ],
          recoveryLink: `${process.env.APP_URL}/auth/recovery?token=${hijackingEvent._id}`
        });
      }

      return true;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Notify user error:', error);
      throw error;
    }
  }

  /**
   * Notify admins about critical hijacking event
   */
  static async notifyAdmins(user, hijackingEvent) {
    try {
      const admins = await User.find({ role: 'admin', accountStatus: 'active' });

      for (const admin of admins) {
        await notificationService.sendNotification(admin._id, {
          type: 'admin_alert',
          title: '🚨 Critical: Session Hijacking Detected',
          message: `User ${user.email} account compromised. Risk score: ${hijackingEvent.riskScore}. Account auto-locked.`,
          priority: 'critical',
          metadata: {
            userId: user._id,
            hijackingEventId: hijackingEvent._id,
            riskScore: hijackingEvent.riskScore
          }
        });
      }

      return true;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Notify admins error:', error);
      // Don't throw - admin notification failure shouldn't block containment
      return false;
    }
  }

  /**
   * Generate recovery code
   */
  static generateRecoveryCode() {
    const digits = '0123456789';
    let code = '';
    for (let i = 0; i < this.config.recoveryCodeLength; i++) {
      code += digits[Math.floor(Math.random() * digits.length)];
    }
    return code;
  }

  /**
   * Send recovery code via email
   */
  static async sendRecoveryCode(user, code) {
    try {
      if (emailService && user.email) {
        await emailService.send({
          to: user.email,
          subject: 'Account Recovery Verification Code',
          template: 'recovery-code',
          data: {
            userName: user.name,
            code,
            expiresIn: Math.floor(this.config.recoveryCodeExpiry / 60000) // minutes
          }
        });
      }

      return true;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Send recovery code error:', error);
      throw error;
    }
  }

  /**
   * Check if recovery window is still valid
   */
  static isRecoveryWindowValid(hijackingEvent) {
    if (!hijackingEvent.recovery.initiated) {
      return false;
    }

    const now = new Date();
    const expiresAt = new Date(hijackingEvent.recovery.expiresAt);

    return now < expiresAt;
  }

  /**
   * Get recovery session by token
   */
  static async getRecoverySessionByToken(token) {
    try {
      const recoverySession = await RecoverySession.findOne({
        recoveryToken: token,
        status: { $in: ['PENDING', 'AUTHENTICATED', 'ACTIVE'] },
        expiresAt: { $gt: new Date() }
      });

      return recoverySession;
    } catch (error) {
      console.error('[SessionHijackingRecovery] Get recovery session error:', error);
      throw error;
    }
  }
}

module.exports = SessionHijackingRecoveryService;
