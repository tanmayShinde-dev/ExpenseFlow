/**
 * Weighted Consensus Engine
 * Resolves conflicting intel from multiple providers using weighted voting
 */

const ProviderSLA = require('../models/ProviderSLA');
const FeedHealthScore = require('../models/FeedHealthScore');

class WeightedConsensusEngine {
  constructor() {
    this.config = {
      minConsensusThreshold: 0.6, // 60% minimum agreement
      majorityThreshold: 0.5, // 50%+ for majority
      unanimousThreshold: 0.95, // 95%+ for unanimous
      conflictResolutionStrategies: {
        UNANIMOUS: 'UNANIMOUS', // All agree
        MAJORITY: 'MAJORITY', // 50%+ agree
        WEIGHTED_VOTE: 'WEIGHTED_VOTE', // Provider weight-based
        FALLBACK: 'FALLBACK' // Time-based historical winner
      }
    };
  }

  /**
   * Resolve conflict between multiple provider results
   */
  async resolveConflict(feedId, providerResults) {
    try {
      // Group results by value
      const grouped = this._groupResults(providerResults);

      // If only one result, no conflict
      if (Object.keys(grouped).length === 1) {
        return {
          consensus: true,
          resolvedValue: Object.keys(grouped)[0],
          strategy: 'UNANIMOUS',
          confidence: 1.0,
          conflictResolved: false
        };
      }

      // Get provider weights
      const weights = await this._getProviderWeights(
        providerResults.map(r => r.providerId)
      );

      // Calculate agreement percentages
      const agreementScores = this._calculateAgreementScores(grouped, weights);

      // Find best consensus
      const consensus = this._findBestConsensus(
        grouped,
        agreementScores,
        weights
      );

      // Record conflict if multiple results
      if (Object.keys(grouped).length > 1) {
        await this._recordConflict(
          feedId,
          providerResults,
          consensus,
          Object.keys(grouped).length
        );
      }

      return {
        consensus: consensus.agreementScore >= this.config.minConsensusThreshold,
        resolvedValue: consensus.value,
        strategy: consensus.strategy,
        confidence: consensus.agreementScore,
        providers: providerResults.map(r => ({
          providerId: r.providerId,
          result: r.result,
          weight: weights[r.providerId],
          contribution: (weights[r.providerId] || 1) / Object.values(weights).reduce((a, b) => a + b, 0)
        })),
        conflictResolved: Object.keys(grouped).length > 1,
        alternatives: Object.keys(grouped)
          .filter(v => v !== consensus.value)
          .slice(0, 2)
      };

    } catch (error) {
      console.error('[ConsensusEngine] Resolve conflict error:', error);
      return {
        success: false,
        error: error.message,
        consensus: false
      };
    }
  }

  /**
   * Group results by value
   */
  _groupResults(results) {
    const grouped = {};

    results.forEach(r => {
      const key = JSON.stringify(r.result);
      if (!grouped[key]) {
        grouped[key] = [];
      }
      grouped[key].push(r);
    });

    return grouped;
  }

  /**
   * Get provider weights from SLA data
   */
  async _getProviderWeights(providerIds) {
    try {
      const providers = await ProviderSLA.find(
        { providerId: { $in: providerIds } }
      );

      const weights = {};
      providers.forEach(p => {
        // Weight = base weight * health factor
        const healthScore = p.getHealthScore();
        const healthFactor = 0.5 + (healthScore / 100) * 0.5; // 0.5 to 1.0

        weights[p.providerId] =
          (p.weight || 1) * healthFactor;
      });

      // Normalize weights
      const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);
      Object.keys(weights).forEach(key => {
        weights[key] = weights[key] / totalWeight;
      });

      return weights;

    } catch (error) {
      console.error('[ConsensusEngine] Get weights error:', error);
      // Return equal weights if error
      const weights = {};
      providerIds.forEach(id => {
        weights[id] = 1 / providerIds.length;
      });
      return weights;
    }
  }

  /**
   * Calculate agreement scores
   */
  _calculateAgreementScores(grouped, weights) {
    const scores = {};

    Object.entries(grouped).forEach(([value, providers]) => {
      let score = 0;

      providers.forEach(p => {
        score += weights[p.providerId] || 1 / Object.keys(weights).length;
      });

      scores[value] = {
        score,
        providers: providers.length,
        weight: score
      };
    });

    return scores;
  }

  /**
   * Find best consensus
   */
  _findBestConsensus(grouped, agreementScores, weights) {
    // Sort by agreement score
    const sorted = Object.entries(agreementScores)
      .sort((a, b) => b[1].score - a[1].score);

    const best = sorted[0];
    const value = best[0];
    const agreementScore = best[1].score;

    // Determine strategy
    let strategy = this.config.conflictResolutionStrategies.WEIGHTED_VOTE;

    if (agreementScore >= this.config.unanimousThreshold) {
      strategy = this.config.conflictResolutionStrategies.UNANIMOUS;
    } else if (agreementScore >= this.config.majorityThreshold) {
      strategy = this.config.conflictResolutionStrategies.MAJORITY;
    }

    return {
      value: JSON.parse(value),
      agreementScore,
      strategy,
      providerCount: grouped[value].length
    };
  }

  /**
   * Record conflict for monitoring
   */
  async _recordConflict(feedId, results, consensus, conflictCount) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (feed) {
        const providers = results.map(r => r.providerId);
        const resolution = this._serializeResolution(consensus.resolvedValue);

        await feed.recordConflict(
          providers,
          `${conflictCount}_way_conflict`,
          resolution
        );
      }

    } catch (error) {
      console.error('[ConsensusEngine] Record conflict error:', error);
    }
  }

  /**
   * Serialize complex objects for storage
   */
  _serializeResolution(value) {
    return typeof value === 'string' ? value : JSON.stringify(value).substring(0, 255);
  }

  /**
   * Get consensus strategy for feed
   */
  async getConsensusStrategy(feedId, providerCount) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        // Default: use weighted voting for <= 3 providers, majority for > 3
        return providerCount <= 3
          ? this.config.conflictResolutionStrategies.WEIGHTED_VOTE
          : this.config.conflictResolutionStrategies.MAJORITY;
      }

      // If drift detected, be more conservative
      if (feed.drift.driftDetected) {
        return this.config.conflictResolutionStrategies.UNANIMOUS;
      }

      // If conflict rate is high, require stricter consensus
      if (feed.consensus.conflictCount > 100) {
        return this.config.conflictResolutionStrategies.MAJORITY;
      }

      return this.config.conflictResolutionStrategies.WEIGHTED_VOTE;

    } catch (error) {
      console.error('[ConsensusEngine] Get strategy error:', error);
      return this.config.conflictResolutionStrategies.WEIGHTED_VOTE;
    }
  }

  /**
   * Batch resolve multiple conflicts
   */
  async batchResolveConflicts(feedId, providerResultsBatch) {
    const results = [];

    for (const providerResults of providerResultsBatch) {
      const resolved = await this.resolveConflict(feedId, providerResults);
      results.push(resolved);
    }

    return {
      success: true,
      totalResolved: results.length,
      consensusRate: (results.filter(r => r.consensus).length / results.length) * 100,
      results
    };
  }

  /**
   * Get consensus statistics
   */
  async getConsensusStatistics(feedId) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      const conflictHistory = feed.consensus.conflictHistory || [];
      const recentConflicts = conflictHistory.filter(
        c => new Date(c.timestamp) > new Date(Date.now() - 86400000)
      );

      return {
        success: true,
        totalConflicts: feed.consensus.conflictCount,
        recentConflicts: recentConflicts.length,
        agreementRate: feed.consensus.agreementRate,
        averageResolutionTime: feed.consensus.averageConflictResolution,
        lastConflict: feed.consensus.lastConflict,
        conflictTrend: this._calculateTrend(conflictHistory)
      };

    } catch (error) {
      console.error('[ConsensusEngine] Get statistics error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Calculate trend
   */
  _calculateTrend(history) {
    if (history.length < 2) return 'STABLE';

    const recent = history.slice(-50);
    const mid = Math.floor(recent.length / 2);

    const recentAvg = recent.slice(-mid).length / mid;
    const olderAvg = recent.slice(0, mid).length / mid;

    if (recentAvg > olderAvg * 1.2) return 'INCREASING';
    if (recentAvg < olderAvg * 0.8) return 'DECREASING';
    return 'STABLE';
  }
}

module.exports = new WeightedConsensusEngine();
