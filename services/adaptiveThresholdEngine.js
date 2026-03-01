/**
 * Adaptive Threshold Engine
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Manages user-specific adaptive thresholds to minimize false positives.
 * Learns from baseline behavior and adjusts sensitivity accordingly.
 */

const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');
const SessionBehaviorSignal = require('../models/SessionBehaviorSignal');
const SessionTrustScore = require('../models/SessionTrustScore');
const User = require('../models/User');

class AdaptiveThresholdEngine {
  /**
   * Get or create threshold policy for user
   */
  async getOrCreatePolicy(userId) {
    try {
      let policy = await AdaptiveThresholdPolicy.findOne({ userId });

      if (!policy) {
        policy = new AdaptiveThresholdPolicy({
          userId,
          enabled: true,
          baselineProfile: {
            baselineCalculatedAt: new Date(),
            dataPointsCollected: 0,
          },
        });

        await policy.save();
      }

      return policy;
    } catch (error) {
      console.error('Error getting or creating threshold policy:', error);
      throw error;
    }
  }

  /**
   * Update user baseline from signals
   */
  async updateUserBaseline(userId) {
    try {
      const policy = await this.getOrCreatePolicy(userId);

      // Collect data about user's behavior
      const recentSessions = await SessionTrustScore.find({
        userId,
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }, // Last 7 days
      });

      if (recentSessions.length === 0) {
        return policy;
      }

      // Calculate average across sessions
      const baselineProfile = policy.baselineProfile;

      // Update request cadence baseline
      const avgRequestsPerMinute = recentSessions.reduce((sum, s) => {
        return sum + (s.components?.requestCadenceScore || 100);
      }, 0) / recentSessions.length;

      baselineProfile.averageRequestsPerMinute = Math.max(1, avgRequestsPerMinute / 20); // Rough estimate

      // Collect location data (if available)
      // This would come from actual request data

      // Update baseline calculated timestamp
      baselineProfile.baselineCalculatedAt = new Date();
      baselineProfile.dataPointsCollected = recentSessions.length;

      policy.markModified('baselineProfile');
      await policy.save();

      return policy;
    } catch (error) {
      console.error('Error updating user baseline:', error);
      throw error;
    }
  }

  /**
   * Check if should auto-adjust thresholds (high false positive rate)
   */
  async checkAndApplyAutoAdjustments(userId) {
    try {
      const policy = await this.getOrCreatePolicy(userId);

      if (!policy.autoAdjustment.enabled) {
        return policy;
      }

      // Check if enough time has passed since last adjustment
      const lastAdjustment = policy.autoAdjustment.lastAdjustmentAt || new Date(0);
      const daysSinceAdjustment = (Date.now() - lastAdjustment) / (24 * 60 * 60 * 1000);

      const frequencyDays = policy.autoAdjustment.adjustmentCheckFrequency === 'WEEKLY' ? 7 : 30;

      if (daysSinceAdjustment < frequencyDays) {
        return policy;
      }

      // Calculate false positive rate
      const recentSignals = await SessionBehaviorSignal.find({
        userId,
        createdAt: { $gte: new Date(Date.now() - frequencyDays * 24 * 60 * 60 * 1000) },
      });

      const falsePositives = recentSignals.filter(s => s.falsePositive).length;
      const fpRate = falsePositives / Math.max(1, recentSignals.length);

      // Check if need to relax thresholds
      if (fpRate > policy.autoAdjustment.falsePositiveThreshold) {
        await this.relaxThresholds(policy, policy.autoAdjustment.relaxationFactor);
        policy.falsePositiveTracking.trend = 'INCREASING';
      }

      // Check if need to tighten (attacks detected)
      const recentAttacks = recentSignals.filter(s =>
        s.severity === 'CRITICAL' && !s.falsePositive
      ).length;

      if (recentAttacks > policy.autoAdjustment.threatThreshold) {
        await this.tightenThresholds(policy, policy.autoAdjustment.tighteningFactor);
        policy.falsePositiveTracking.trend = 'DECREASING';
      }

      policy.autoAdjustment.lastAdjustmentAt = new Date();
      await policy.save();

      return policy;
    } catch (error) {
      console.error('Error checking auto-adjustments:', error);
      throw error;
    }
  }

  /**
   * Relax thresholds when false positive rate is high
   */
  async relaxThresholds(policy, relaxationFactor) {
    try {
      // Relax component thresholds
      const thresholds = policy.componentThresholds;

      // Relax endpoint sensitivity
      thresholds.endpointSensitivity.minScoreBeforeChallenge =
        Math.min(100, thresholds.endpointSensitivity.minScoreBeforeChallenge / relaxationFactor);

      // Relax request cadence
      thresholds.requestCadence.deviationThreshold *= relaxationFactor;
      thresholds.requestCadence.minScoreBeforeChallenge =
        Math.min(100, thresholds.requestCadence.minScoreBeforeChallenge / relaxationFactor);

      // Relax geo context
      thresholds.geoContext.toleranceLevel = 'RELAXED';
      thresholds.geoContext.newCountryPenalty *= relaxationFactor;
      thresholds.geoContext.minScoreBeforeChallenge =
        Math.min(100, thresholds.geoContext.minScoreBeforeChallenge / relaxationFactor);

      // Relax user agent
      thresholds.userAgentConsistency.browserChangePenalty *= relaxationFactor;
      thresholds.userAgentConsistency.osChangePenalty *= relaxationFactor;

      // Relax token age
      thresholds.tokenAge.maxAgeHours += 12; // Extend by 12 hours

      console.log(`Thresholds relaxed for user by factor ${relaxationFactor}`);
    } catch (error) {
      console.error('Error relaxing thresholds:', error);
    }
  }

  /**
   * Tighten thresholds when attacks detected
   */
  async tightenThresholds(policy, tighteningFactor) {
    try {
      const thresholds = policy.componentThresholds;

      // Tighten endpoint sensitivity
      thresholds.endpointSensitivity.minScoreBeforeChallenge =
        Math.max(40, thresholds.endpointSensitivity.minScoreBeforeChallenge * tighteningFactor);

      // Tighten request cadence
      thresholds.requestCadence.deviationThreshold /= tighteningFactor;
      thresholds.requestCadence.minScoreBeforeChallenge =
        Math.max(40, thresholds.requestCadence.minScoreBeforeChallenge * tighteningFactor);

      // Tighten geo context
      thresholds.geoContext.toleranceLevel = 'STRICT';
      thresholds.geoContext.newCountryPenalty /= tighteningFactor;
      thresholds.geoContext.minScoreBeforeChallenge =
        Math.max(40, thresholds.geoContext.minScoreBeforeChallenge * tighteningFactor);

      // Tighten token age
      thresholds.tokenAge.maxAgeHours = Math.max(6, thresholds.tokenAge.maxAgeHours - 6);

      // Increase threat checking
      thresholds.threatIndicator.toleranceLevel = 'STRICT';

      console.log(`Thresholds tightened for user by factor ${tighteningFactor}`);
    } catch (error) {
      console.error('Error tightening thresholds:', error);
    }
  }

  /**
   * Record false positive (user confirmed action was legitimate)
   */
  async recordFalsePositive(signalId, userId) {
    try {
      const signal = await SessionBehaviorSignal.findById(signalId);

      if (signal) {
        signal.markAsFalsePositive();
        await signal.save();
      }

      // Update policy tracking
      const policy = await this.getOrCreatePolicy(userId);
      policy.recordFalsePositive();
      await policy.save();

      // Check if should auto-adjust
      await this.checkAndApplyAutoAdjustments(userId);

      return { success: true };
    } catch (error) {
      console.error('Error recording false positive:', error);
      throw error;
    }
  }

  /**
   * Add temporary relaxation exception (e.g., user traveling)
   */
  async addTemporaryException(userId, exceptionType, durationDays, component = null) {
    try {
      const policy = await this.getOrCreatePolicy(userId);

      const exception = {
        exceptionType,
        description: `${exceptionType} period`,
        component: component || null,
        relaxationFactor: 0.7, // 30% relaxation
        validFrom: new Date(),
        validUntil: new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000),
        requiresApproval: exceptionType === 'DEVICE_CHANGE', // Some need approval
      };

      policy.exceptions.push(exception);
      await policy.save();

      return {
        success: true,
        exceptionId: exception._id,
        validUntil: exception.validUntil,
      };
    } catch (error) {
      console.error('Error adding temporary exception:', error);
      throw error;
    }
  }

  /**
   * Get current sensitivity level (STRICT, NORMAL, RELAXED)
   */
  async getCurrentSensitivity(userId) {
    try {
      const policy = await this.getOrCreatePolicy(userId);
      const fpRate = policy.falsePositiveTracking.count / Math.max(1, policy.falsePositiveTracking.count + 100);

      let sensitivity = 'NORMAL';

      if (fpRate > 0.15) {
        sensitivity = 'RELAXED';
      } else if (policy.falsePositiveTracking.trend === 'INCREASING') {
        sensitivity = 'RELAXED';
      }

      if (policy.baselineProfile.dataPointsCollected < 10) {
        sensitivity = 'STRICT'; // Be stricter with insufficient data
      }

      return {
        sensitivity,
        falsePositiveRate: fpRate,
        trend: policy.falsePositiveTracking.trend,
        recommendation: this.getSensitivityRecommendation(sensitivity),
      };
    } catch (error) {
      console.error('Error getting current sensitivity:', error);
      return {
        sensitivity: 'NORMAL',
        error: error.message,
      };
    }
  }

  /**
   * Get sensitivity recommendation
   */
  getSensitivityRecommendation(sensitivity) {
    const recommendations = {
      STRICT: 'Security-focused: More challenges, stricter thresholds',
      NORMAL: 'Balanced: Standard thresholds and challenge frequency',
      RELAXED: 'User-friendly: Fewer challenges, relaxed thresholds',
    };

    return recommendations[sensitivity] || recommendations.NORMAL;
  }

  /**
   * Learn from user behavior over time
   */
  async trainBaselineModel(userId) {
    try {
      const policy = await this.getOrCreatePolicy(userId);

      // Get all non-false-positive signals for this user
      const signals = await SessionBehaviorSignal.find({
        userId,
        falsePositive: false,
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }, // Last 30 days
      });

      // Analyze patterns
      const geoLocations = signals
        .filter(s => s.signalType === 'GEO_DRIFT')
        .map(s => s.details?.currentLocation?.city)
        .filter(Boolean);

      const userAgents = signals
        .filter(s => s.signalType === 'USER_AGENT_CHANGE')
        .map(s => s.details?.currentUserAgent)
        .filter(Boolean);

      // Update baseline with learned patterns
      if (geoLocations.length > 0) {
        policy.baselineProfile.primaryCities = [...new Set(geoLocations)].slice(0, 5);
      }

      if (userAgents.length > 0) {
        policy.baselineProfile.usualUserAgents = [...new Set(userAgents)].slice(0, 5);
      }

      policy.baselineProfile.dataPointsCollected = signals.length;
      policy.baselineProfile.baselineCalculatedAt = new Date();

      await policy.save();

      return {
        success: true,
        signalsAnalyzed: signals.length,
        baselineUpdated: true,
      };
    } catch (error) {
      console.error('Error training baseline model:', error);
      throw error;
    }
  }

  /**
   * Get policy recommendations
   */
  async getPolicyRecommendations(userId) {
    try {
      const policy = await this.getOrCreatePolicy(userId);
      const sensitivity = await this.getCurrentSensitivity(userId);

      const recommendations = [];

      // High false positive rate
      if (sensitivity.falsePositiveRate > 0.1) {
        recommendations.push({
          type: 'RELAX_THRESHOLDS',
          reason: `False positive rate is ${(sensitivity.falsePositiveRate * 100).toFixed(1)}%`,
          action: 'Consider temporarily relaxing thresholds',
        });
      }

      // Insufficient baseline data
      if (policy.baselineProfile.dataPointsCollected < 10) {
        recommendations.push({
          type: 'COLLECT_MORE_DATA',
          reason: 'Insufficient data for accurate baseline',
          action: 'System needs more behavior data (at least 10 sessions)',
        });
      }

      // Challenge fatigue
      const challenge2Count = await SessionTrustScore.countDocuments({
        userId,
        challengeCount: { $gte: 5 },
      });

      if (challenge2Count > 0) {
        recommendations.push({
          type: 'REDUCE_CHALLENGES',
          reason: 'Users are experiencing challenge fatigue',
          action: 'Consider using weaker challenge types',
        });
      }

      return recommendations;
    } catch (error) {
      console.error('Error getting policy recommendations:', error);
      return [];
    }
  }
}

module.exports = new AdaptiveThresholdEngine();
