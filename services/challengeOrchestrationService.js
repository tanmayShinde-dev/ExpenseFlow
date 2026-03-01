/**
 * Challenge Orchestration Service
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Manages challenge selection and execution with anti-friction controls.
 * Uses confidence-aware challenge selection to minimize user disruption.
 */

const SessionChallenge = require('../models/SessionChallenge');
const SessionTrustScore = require('../models/SessionTrustScore');
const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');
const User = require('../models/User');
const notificationService = require('./notificationService');
const emailService = require('./emailService');

class ChallengeOrchestrationService {
  /**
   * Select and issue appropriate challenge
   */
  async selectAndIssueChallenge(sessionId, userId, triggerReason, trustScore = null) {
    try {
      // Get user's adaptive threshold policy
      const policy = await AdaptiveThresholdPolicy.findOne({ userId });

      // Check if should actually challenge (anti-friction)
      if (!this.shouldChallenge(policy, trustScore)) {
        return null;
      }

      // Check if too many challenges recently (throttling)
      const recentChallenges = await SessionChallenge.find({
        sessionId,
        status: { $in: ['PENDING', 'COMPLETED'] },
        issuedAt: { $gte: new Date(Date.now() - 3600000) }, // Last hour
      });

      if (recentChallenges.length >= (policy?.challengeStrategy?.maxChallengesPerHour || 3)) {
        console.log(`Challenge throttled: ${recentChallenges.length} challenges in last hour`);
        return null;
      }

      // Select challenge type based on strategy
      const challengeType = this.selectChallengeType(policy, trustScore);

      // Determine challenge strength
      const strength = this.determineChallengeStrength(
        triggerReason,
        trustScore,
        policy?.confidenceLevel || 'MEDIUM'
      );

      // Create challenge
      const challenge = new SessionChallenge({
        sessionId,
        userId,
        challengeType,
        strength,
        triggerReason,
        confidenceLevel: policy?.confidenceLevel || 'MEDIUM',
        trustScoreAtTrigger: trustScore,
        status: 'PENDING',
        config: this.getChallengeConfig(challengeType),
        issuedAt: new Date(),
      });

      challenge.expiresAt = new Date(
        Date.now() + (challenge.config.expirationMinutes * 60000)
      );

      await challenge.save();

      // Send challenge via appropriate channels
      await this.issueChallengeToUser(challenge, userId);

      // Update trust score with active challenge
      if (trustScore) {
        const score = await SessionTrustScore.findById(trustScore._id || trustScore);
        if (score) {
          score.activeChallengeId = challenge._id;
          score.lastChallengeAt = new Date();
          score.challengeCount = (score.challengeCount || 0) + 1;
          await score.save();
        }
      }

      return challenge;
    } catch (error) {
      console.error('Error selecting and issuing challenge:', error);
      throw error;
    }
  }

  /**
   * Determine if user should be challenged (anti-friction)
   */
  shouldChallenge(policy, trustScore) {
    if (!policy) return true; // Default to challenge if no policy

    // Check confidence level
    if (policy.confidenceLevel === 'LOW') {
      // Only challenge if high risk signal
      return trustScore < 60;
    }

    // MEDIUM confidence: challenge below 70
    if (policy.confidenceLevel === 'MEDIUM') {
      return trustScore < 70;
    }

    // HIGH confidence: challenge below 50
    return trustScore < 50;
  }

  /**
   * Select challenge type based on strategy and risk level
   */
  selectChallengeType(policy, trustScore) {
    if (!policy?.challengeStrategy?.challengePreferenceOrder) {
      // Default challenge preference
      return this.getDefaultChallenge(trustScore);
    }

    // Sort by frequency (first = preferred)
    const preferences = policy.challengeStrategy.challengePreferenceOrder
      .sort((a, b) => a.frequency - b.frequency);

    // High trust score = weak challenges (user-friendly)
    // Low trust score = strong challenges (security-focused)

    if (trustScore > 85) {
      // Use weakest challenge
      return preferences.find(p => 
        ['DEVICE_CHECK', 'EMAIL_VERIFY'].includes(p.challengeType)
      )?.challengeType || 'EMAIL_VERIFY';
    } else if (trustScore > 60) {
      // Use medium challenge
      return preferences.find(p =>
        ['OTP', 'SECURITY_QUESTIONS'].includes(p.challengeType)
      )?.challengeType || 'OTP';
    } else {
      // Use strongest challenge
      return preferences.find(p =>
        ['BIOMETRIC', 'PASSWORD_2FA'].includes(p.challengeType)
      )?.challengeType || 'PASSWORD_2FA';
    }
  }

  /**
   * Determine challenge strength (weak/medium/strong)
   */
  determineChallengeStrength(triggerReason, trustScore, confidenceLevel) {
    // Strong challenges for critical triggers
    const criticalTriggers = [
      'trust_score_below_threshold',
      'impossible_travel',
      'privilege_escalation',
      'known_threat',
    ];

    if (criticalTriggers.includes(triggerReason)) {
      return 'STRONG';
    }

    // Medium challenges for moderate issues
    if (trustScore < 70) {
      return 'MEDIUM';
    }

    // Weak challenges for minor issues
    if (confidenceLevel === 'HIGH') {
      return 'WEAK';
    }

    return 'MEDIUM';
  }

  /**
   * Get challenge configuration
   */
  getChallengeConfig(challengeType) {
    const configs = {
      DEVICE_CHECK: {
        expirationMinutes: 10,
        maxAttempts: 2,
        allowSkip: false,
        deviceFingerprint: true,
      },
      EMAIL_VERIFY: {
        expirationMinutes: 15,
        maxAttempts: 3,
        allowSkip: false,
        otpDeliveryMethod: 'EMAIL',
      },
      OTP: {
        expirationMinutes: 10,
        maxAttempts: 3,
        allowSkip: false,
        otpDeliveryMethod: 'EMAIL',
        otpCodeLength: 6,
      },
      BIOMETRIC: {
        expirationMinutes: 5,
        maxAttempts: 3,
        allowSkip: false,
      },
      PASSWORD_2FA: {
        expirationMinutes: 15,
        maxAttempts: 3,
        allowSkip: false,
      },
      SECURITY_QUESTIONS: {
        expirationMinutes: 10,
        maxAttempts: 2,
        allowSkip: false,
        questionCount: 2,
      },
    };

    return configs[challengeType] || configs.OTP;
  }

  /**
   * Get default challenge (used when no policy)
   */
  getDefaultChallenge(trustScore) {
    if (trustScore > 80) return 'DEVICE_CHECK';
    if (trustScore > 60) return 'OTP';
    return 'PASSWORD_2FA';
  }

  /**
   * Issue challenge to user via appropriate channels
   */
  async issueChallengeToUser(challenge, userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        console.error(`User ${userId} not found`);
        return;
      }

      const explanation = challenge.getExplanation();
      const strengthExplanation = challenge.getStrengthExplanation();

      // Send via email (primary)
      if (user.email) {
        try {
          await emailService.send({
            to: user.email,
            subject: 'Verify Your Identity',
            template: 'sessionChallenge',
            data: {
              userName: user.name || user.email,
              challengeType: challenge.challengeType,
              explanation,
              strength: strengthExplanation,
              expirationMinutes: challenge.config.expirationMinutes,
              challengeLink: `${process.env.APP_URL}/verify-session/${challenge._id}`,
            },
          });

          challenge.channels.push({
            channel: 'EMAIL',
            sentAt: new Date(),
            deliveryStatus: 'PENDING',
          });
        } catch (error) {
          console.error('Error sending email challenge:', error);
        }
      }

      // Send via in-app notification
      try {
        await notificationService.notify({
          userId,
          type: 'SESSION_CHALLENGE',
          title: 'Verify Your Identity',
          message: explanation,
          severity: challenge.strength === 'STRONG' ? 'CRITICAL' : 'HIGH',
          data: {
            challengeId: challenge._id,
            challengeType: challenge.challengeType,
            expiresAt: challenge.expiresAt,
          },
        });

        challenge.channels.push({
          channel: 'IN_APP',
          sentAt: new Date(),
          deliveryStatus: 'DELIVERED',
        });
      } catch (error) {
        console.error('Error sending in-app notification:', error);
      }

      await challenge.save();
    } catch (error) {
      console.error('Error issuing challenge to user:', error);
      throw error;
    }
  }

  /**
   * Process challenge response
   */
  async processChallengeResponse(challengeId, userResponse, responseTimeMs = 0) {
    try {
      const challenge = await SessionChallenge.findById(challengeId);

      if (!challenge) {
        throw new Error('Challenge not found');
      }

      if (!challenge.isPending()) {
        throw new Error('Challenge is not pending');
      }

      // Verify response (simplified - actual verification depends on challenge type)
      const isCorrect = await this.verifyChallengeResponse(challenge, userResponse);

      // Record attempt
      challenge.recordAttempt(userResponse, isCorrect);

      // Calculate response time
      challenge.userResponse.responseTimeMs = responseTimeMs;
      challenge.userResponse.responseWasFast = responseTimeMs < 2000;

      // Calculate friction metrics
      challenge.calculateFrictionMetrics();

      if (isCorrect) {
        // Update trust score reward
        const trustScore = await SessionTrustScore.find({ activeChallengeId: challengeId }).findOne();

        if (trustScore) {
          // Successful challenge increases trust
          trustScore.components.reAuthScore = Math.min(
            100,
            trustScore.components.reAuthScore + 15
          );

          // Fast response is rewarded more
          if (challenge.userResponse.responseWasFast) {
            trustScore.components.reAuthScore = Math.min(
              100,
              trustScore.components.reAuthScore + 5
            );
          }

          trustScore.recordSuccessfulReAuth();
          await trustScore.save();
        }
      }

      await challenge.save();

      return {
        success: isCorrect,
        remaining_attempts: challenge.config.maxAttempts - challenge.userResponse.attemptCount,
        friction: challenge.frictionMetrics.estimatedUserFriction,
      };
    } catch (error) {
      console.error('Error processing challenge response:', error);
      throw error;
    }
  }

  /**
   * Verify challenge response
   */
  async verifyChallengeResponse(challenge, userResponse) {
    try {
      switch (challenge.challengeType) {
        case 'DEVICE_CHECK':
          // Verify device fingerprint
          return challenge.config.deviceFingerprint === userResponse;

        case 'EMAIL_VERIFY':
          // Verify email token
          return this.verifyEmailToken(challenge, userResponse);

        case 'OTP':
          // Verify OTP code
          return this.verifyOTP(challenge, userResponse);

        case 'BIOMETRIC':
          // Verify biometric (simplified)
          return userResponse && userResponse.biometric_verified === true;

        case 'PASSWORD_2FA':
          // Verify password + 2FA
          return this.verifyPassword2FA(challenge, userResponse);

        case 'SECURITY_QUESTIONS':
          // Verify security answers
          return this.verifySecurityAnswers(challenge, userResponse);

        default:
          return false;
      }
    } catch (error) {
      console.error('Error verifying challenge response:', error);
      return false;
    }
  }

  /**
   * Verify email token (placeholder)
   */
  verifyEmailToken(challenge, token) {
    // Actual implementation would validate token against generated token
    return token && token.length > 20;
  }

  /**
   * Verify OTP code (placeholder)
   */
  verifyOTP(challenge, code) {
    // Actual implementation would check against generated OTP
    return code && code.length === 6 && /^\d+$/.test(code);
  }

  /**
   * Verify password + 2FA (placeholder)
   */
  async verifyPassword2FA(challenge, credentials) {
    // Actual implementation would verify against user's password and 2FA
    return credentials && credentials.password && credentials.twoFACode;
  }

  /**
   * Verify security answers (placeholder)
   */
  async verifySecurityAnswers(challenge, answers) {
    // Actual implementation would verify against stored security answers
    return answers && Array.isArray(answers) && answers.length >= 2;
  }

  /**
   * Get challenge status
   */
  async getChallengeStatus(challengeId) {
    try {
      const challenge = await SessionChallenge.findById(challengeId);

      if (!challenge) {
        return {
          status: 'NOT_FOUND',
          error: 'Challenge not found',
        };
      }

      return {
        status: challenge.status,
        type: challenge.challengeType,
        pending: challenge.isPending(),
        expired: challenge.isExpired(),
        explanation: challenge.getExplanation(),
        remaining_attempts: challenge.config.maxAttempts - challenge.userResponse.attemptCount,
        expires_at: challenge.expiresAt,
      };
    } catch (error) {
      console.error('Error getting challenge status:', error);
      throw error;
    }
  }

  /**
   * Cancel challenge
   */
  async cancelChallenge(challengeId, reason = 'Cancelled') {
    try {
      const challenge = await SessionChallenge.findById(challengeId);

      if (challenge) {
        challenge.cancel(reason);
        await challenge.save();
      }

      return { success: true };
    } catch (error) {
      console.error('Error cancelling challenge:', error);
      throw error;
    }
  }

  /**
   * Get pending challenges for user
   */
  async getPendingChallenges(userId) {
    try {
      return await SessionChallenge.find({
        userId,
        status: 'PENDING',
        expiresAt: { $gt: new Date() },
      }).sort({ issuedAt: -1 });
    } catch (error) {
      console.error('Error getting pending challenges:', error);
      return [];
    }
  }
}

module.exports = new ChallengeOrchestrationService();
