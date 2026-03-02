/**
 * Feed Quality Control Service
 * Monitors feed quality, detects drift, and manages safe mode
 */

const ProviderSLA = require('../models/ProviderSLA');
const FeedHealthScore = require('../models/FeedHealthScore');
const weightedConsensusEngine = require('./weightedConsensusEngine');

class FeedQualityControlService {
  constructor() {
    this.config = {
      driftCheckInterval: 300000, // 5 minutes
      driftBaselineWindow: 604800000, // 7 days
      driftThreshold: 20, // Percentage
      safeModeActivationThreshold: 70, // Health score
      safeModeAlertThreshold: 50, // Health score
      dataQualityWeights: {
        completeness: 0.20,
        consistency: 0.25,
        reliability: 0.25,
        timeliness: 0.20,
        validity: 0.10
      }
    };

    this.driftMonitors = new Map();
  }

  /**
   * Run quality check on feed
   */
  async runQualityCheck(feedId) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      // Gather quality metrics
      const completeness = await this._checkCompleteness(feedId);
      const consistency = await this._checkConsistency(feedId);
      const reliability = await this._checkReliability(feedId);
      const timeliness = await this._checkTimeliness(feedId);
      const validity = await this._checkValidity(feedId);

      // Update quality metrics
      await feed.updateQualityMetric('completeness', completeness);
      await feed.updateQualityMetric('consistency', consistency);
      await feed.updateQualityMetric('reliability', reliability);
      await feed.updateQualityMetric('timeliness', timeliness);
      await feed.updateQualityMetric('validity', validity);

      // Check for safe mode activation
      if (feed.overallHealth <= this.config.safeModeActivationThreshold) {
        await this._considerSafeModeActivation(feed);
      }

      // Check for safe mode deactivation
      if (
        feed.safeMode.enabled &&
        feed.overallHealth >= 85
      ) {
        await feed.deactivateSafeMode();
      }

      return {
        success: true,
        feedId,
        previousHealth: feed.overallHealth,
        quality: {
          completeness,
          consistency,
          reliability,
          timeliness,
          validity
        },
        overallHealth: feed.overallHealth,
        healthStatus: feed.healthStatus,
        safeModeStatus: feed.safeMode.enabled,
        alerts: feed.activeAlerts.length
      };

    } catch (error) {
      console.error('[FeedQualityControl] Quality check error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Check data completeness
   */
  async _checkCompleteness(feedId) {
    // Compare data records against expected records
    try {
      // Query actual records
      const actualCount = 10000; // Placeholder - would query real data

      // Expected count based on source specification
      const expectedCount = 12000;

      const completeness = (actualCount / expectedCount) * 100;

      return Math.min(100, completeness);
    } catch (error) {
      console.error('[FeedQualityControl] Completeness check error:', error);
      return 80; // Default conservative estimate
    }
  }

  /**
   * Check data consistency
   */
  async _checkConsistency(feedId) {
    try {
      // Check for duplicate entries
      const duplicateCount = 5; // Placeholder

      // Check for conflicting records
      const conflictCount = 2; // Placeholder

      // Total records
      const totalCount = 10000;

      const inconsistencies = duplicateCount + conflictCount;
      const consistency = ((totalCount - inconsistencies) / totalCount) * 100;

      return Math.max(0, Math.min(100, consistency));
    } catch (error) {
      console.error('[FeedQualityControl] Consistency check error:', error);
      return 85;
    }
  }

  /**
   * Check reliability
   */
  async _checkReliability(feedId) {
    try {
      // Get provider SLA data for this feed
      const providers = await ProviderSLA.find({
        providerType: { $in: ['HIBP', 'EXTERNAL_FEED', 'THIRD_PARTY'] }
      });

      if (providers.length === 0) return 90;

      // Average uptime and accuracy
      const avgUptime = providers.reduce((sum, p) => sum + p.metrics.uptime, 0) / providers.length;
      const avgAccuracy = providers.reduce((sum, p) => sum + p.metrics.accuracyScore, 0) / providers.length;

      // Reliability is average of uptime and accuracy
      const reliability = (avgUptime + avgAccuracy) / 2;

      return Math.max(0, Math.min(100, reliability));
    } catch (error) {
      console.error('[FeedQualityControl] Reliability check error:', error);
      return 85;
    }
  }

  /**
   * Check timeliness (data freshness)
   */
  async _checkTimeliness(feedId) {
    try {
      // Check last update time
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed || !feed.lastCheck) {
        return 50; // No recent data
      }

      const timeSinceLastUpdate = Date.now() - feed.lastCheck.getTime();
      const maxAcceptableAge = 3600000; // 1 hour

      // If data is older than 1 hour, score decreases linearly
      if (timeSinceLastUpdate > maxAcceptableAge) {
        const overageFactor = (timeSinceLastUpdate - maxAcceptableAge) / maxAcceptableAge;
        return Math.max(0, 100 - overageFactor * 50);
      }

      return 100; // Data is fresh
    } catch (error) {
      console.error('[FeedQualityControl] Timeliness check error:', error);
      return 80;
    }
  }

  /**
   * Check validity
   */
  async _checkValidity(feedId) {
    try {
      // Check for malformed records
      const malformedCount = 0; // Placeholder

      // Check for invalid values
      const invalidCount = 1; // Placeholder

      // Total records
      const totalCount = 10000;

      const errors = malformedCount + invalidCount;
      const validity = ((totalCount - errors) / totalCount) * 100;

      return Math.max(0, Math.min(100, validity));
    } catch (error) {
      console.error('[FeedQualityControl] Validity check error:', error);
      return 95;
    }
  }

  /**
   * Detect drift in data patterns
   */
  async detectDrift(feedId, currentDataPoints) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      // Get baseline
      let baseline = null;
      if (!this.driftMonitors.has(feedId)) {
        // Initialize baseline from historical data
        baseline = await this._getBaselineDataPoints(feedId);
        this.driftMonitors.set(feedId, baseline);
      } else {
        baseline = this.driftMonitors.get(feedId);
      }

      if (baseline === null) {
        baseline = currentDataPoints; // Set first measurement as baseline
        this.driftMonitors.set(feedId, baseline);
        return { driftDetected: false, driftPercentage: 0 };
      }

      // Calculate drift percentage
      const driftPercentage = Math.abs((currentDataPoints - baseline) / baseline) * 100;

      // Record drift
      await feed.recordDrift(currentDataPoints, driftPercentage);

      // If drift detected and threshold exceeded
      if (driftPercentage > this.config.driftThreshold) {
        await this._handleDriftDetected(feedId, driftPercentage, currentDataPoints, baseline);
      }

      return {
        success: true,
        driftDetected: driftPercentage > this.config.driftThreshold,
        driftPercentage: driftPercentage.toFixed(2),
        currentDataPoints,
        baseline,
        threshold: this.config.driftThreshold
      };

    } catch (error) {
      console.error('[FeedQualityControl] Detect drift error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get baseline data points
   */
  async _getBaselineDataPoints(feedId) {
    try {
      // Query historical data from past 7 days
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed || !feed.drift.driftHistory) {
        return null;
      }

      const oldHistory = feed.drift.driftHistory.filter(
        h =>
          new Date(h.timestamp) >
          new Date(Date.now() - this.config.driftBaselineWindow)
      );

      if (oldHistory.length === 0) {
        return null;
      }

      // Calculate average
      const sum = oldHistory.reduce((total, h) => total + h.currentDataPoints, 0);
      return sum / oldHistory.length;

    } catch (error) {
      console.error('[FeedQualityControl] Get baseline error:', error);
      return null;
    }
  }

  /**
   * Handle detected drift
   */
  async _handleDriftDetected(feedId, driftPercentage, current, baseline) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) return;

      // Add alert
      await feed.addAlert(
        'DRIFT_DETECTED',
        'WARNING',
        `Data drift detected: ${driftPercentage.toFixed(2)}% (baseline: ${baseline}, current: ${current})`
      );

      // If severe drift, consider safe mode
      if (driftPercentage > this.config.driftThreshold * 2) {
        await this._considerSafeModeActivation(feed);
      }

    } catch (error) {
      console.error('[FeedQualityControl] Handle drift error:', error);
    }
  }

  /**
   * Consider activating safe mode
   */
  async _considerSafeModeActivation(feed) {
    try {
      // Check if already in safe mode
      if (feed.safeMode.enabled) {
        return;
      }

      // Determine reason
      let reason = 'Unknown';
      if (feed.overallHealth <= this.config.safeModeActivationThreshold) {
        reason = `Feed health dropped to ${feed.overallHealth}%`;
      }

      // Get fallback provider
      const healthyProviders = await ProviderSLA.getHealthyProviders();
      const fallbackProvider = healthyProviders[0]?.providerId || 'INTERNAL';

      //Activate safe mode
      await feed.activateSafeMode(
        reason,
        fallbackProvider,
        'CONSERVATIVE'
      );

      console.log(
        `[FeedQualityControl] Safe mode activated for ${feed.feedId}: ${reason}`
      );

    } catch (error) {
      console.error('[FeedQualityControl] Activate safe mode error:', error);
    }
  }

  /**
   * Calibrate confidence based on accuracy
   */
  async calibrateConfidence(feedId, validationData) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      // Calculate accuracy from validation data
      const correctCount = validationData.filter(v => v.correct).length;
      const baselineAccuracy = (correctCount / validationData.length) * 100;

      // Calibrate
      await feed.calibrateConfidence(baselineAccuracy, validationData.length);

      return {
        success: true,
        baselineAccuracy: baselineAccuracy.toFixed(2),
        calibrationFactor: feed.confidenceCalibration.calibrationFactor.toFixed(2),
        sampleSize: validationData.length
      };

    } catch (error) {
      console.error('[FeedQualityControl] Calibrate confidence error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get quality report
   */
  async getQualityReport(feedId) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      const stats = await weightedConsensusEngine.getConsensusStatistics(feedId);

      return {
        success: true,
        feedId,
        overallHealth: feed.overallHealth,
        healthStatus: feed.healthStatus,
        quality: feed.quality,
        consensus: {
          agreementRate: feed.consensus.agreementRate,
          conflictCount: feed.consensus.conflictCount,
          trend: stats.conflictTrend || 'N/A'
        },
        drift: {
          detected: feed.drift.driftDetected,
          percentage: feed.drift.driftPercentage,
          threshold: feed.drift.driftThreshold
        },
        safeMode: {
          enabled: feed.safeMode.enabled,
          reason: feed.safeMode.reason,
          fallbackProvider: feed.safeMode.fallbackProvider
        },
        alerts: feed.activeAlerts,
        lastCheck: feed.lastHealthUpdate
      };

    } catch (error) {
      console.error('[FeedQualityControl] Get report error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new FeedQualityControlService();
