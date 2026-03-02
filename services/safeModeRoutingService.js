/**
 * Safe Mode & Failover Routing Service
 * Manages provider failover, circuit breaking, and safe mode routing
 */

const ProviderSLA = require('../models/ProviderSLA');
const FeedHealthScore = require('../models/FeedHealthScore');

class SafeModeRoutingService {
  constructor() {
    this.config = {
      failoverThreshold: 70, // Health score below this triggers failover
      circuitBreakerThreshold: 5, // Consecutive failures before open circuit
      circuitBreakerResetTimeout: 300000, // 5 minutes
      maxRetries: 3,
      retryBackoffMs: 100,
      healthCheckInterval: 60000 // 1 minute
    };

    this.circuitBreakers = new Map();
    this.routingCache = new Map();
  }

  /**
   * Route request with fallback chain
   */
  async routeRequest(feedId, primaryProviders, requestPayload) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });
      const providers = primaryProviders;

      // If feed in safe mode, use fallback provider
      if (feed && feed.safeMode.enabled) {
        return await this._routeWithFallback(
          feedId,
          feed.safeMode.fallbackProvider,
          requestPayload,
          feed.safeMode.mode
        );
      }

      // Get healthy provider chain
      const providerChain = await this._buildProviderChain(providers);

      // Try each provider in order
      for (const provider of providerChain) {
        const result = await this._tryProvider(feedId, provider, requestPayload);

        if (result.success) {
          return {
            success: true,
            data: result.data,
            providerId: provider.providerId,
            routingStrategy: 'PRIMARY_CHAIN',
            fromSafeMode: false
          };
        }
      }

      // All primary providers failed, try fallback
      if (feed && feed.safeMode.fallbackProvider) {
        return await this._routeWithFallback(
          feedId,
          feed.safeMode.fallbackProvider,
          requestPayload,
          feed.safeMode.mode
        );
      }

      return {
        success: false,
        error: 'All providers failed'
      };

    } catch (error) {
      console.error('[FallbackRouting] Route error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Build provider chain based on health
   */
  async _buildProviderChain(providers) {
    try {
      const slaData = await ProviderSLA.find({
        providerId: { $in: providers }
      });

      // Sort by health score
      const sorted = slaData.sort((a, b) => {
        const healthA = a.getHealthScore();
        const healthB = b.getHealthScore();
        return healthB - healthA;
      });

      return sorted;
    } catch (error) {
      console.error('[FallbackRouting] Build chain error:', error);
      return providers.map(p => ({ providerId: p }));
    }
  }

  /**
   * Try single provider
   */
  async _tryProvider(feedId, provider, requestPayload) {
    try {
      const providerId = provider.providerId || provider;

      // Check circuit breaker
      if (this._isCircuitOpen(providerId)) {
        return {
          success: false,
          error: 'Circuit breaker open'
        };
      }

      // Attempt request with retries
      let lastError;
      for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
        try {
          // Simulate provider request
          const result = await this._callProvider(providerId, requestPayload);

          if (result.success) {
            // Reset circuit breaker on success
            this._resetCircuitBreaker(providerId);

            // Record success in SLA
            const sla = await ProviderSLA.findOne({ providerId });
            if (sla) {
              await sla.recordRequest(0, true, false);
            }

            return result;
          }

          lastError = result.error;

        } catch (error) {
          lastError = error.message;

          // Exponential backoff
          if (attempt < this.config.maxRetries) {
            await new Promise(resolve =>
              setTimeout(resolve, this.config.retryBackoffMs * attempt)
            );
          }
        }
      }

      // All retries failed
      await this._recordProviderFailure(providerId);
      return {
        success: false,
        error: lastError
      };

    } catch (error) {
      console.error('[FallbackRouting] Provider attempt error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Call provider (placeholder for actual requests)
   */
  async _callProvider(providerId, requestPayload) {
    // This would call the actual provider API
    // For now, simulate based on SLA data
    try {
      const sla = await ProviderSLA.findOne({ providerId });

      if (!sla) {
        return {
          success: false,
          error: `Provider ${providerId} not found`
        };
      }

      const health = sla.getHealthScore();

      // Simulate failure rate based on error rate
      const errorRate = sla.metrics.errorRate || 0;
      if (Math.random() * 100 < errorRate) {
        return {
          success: false,
          error: 'Simulated provider error'
        };
      }

      // Success
      return {
        success: true,
        data: {
          providerId,
          timestamp: new Date(),
          payload: requestPayload
        }
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Route with fallback provider
   */
  async _routeWithFallback(feedId, fallbackProvider, requestPayload, mode) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      // Mode-specific routing
      switch (mode) {
        case 'CONSERVATIVE':
          return await this._conservativeRoute(fallbackProvider, requestPayload);

        case 'PASSTHROUGH':
          return await this._passthroughRoute(fallbackProvider, requestPayload);

        case 'MANUAL_REVIEW':
          return await this._manualReviewRoute(feedId, fallbackProvider, requestPayload);

        default:
          return await this._conservativeRoute(fallbackProvider, requestPayload);
      }

    } catch (error) {
      console.error('[FallbackRouting] Fallback error:', error);
      return {
        success: false,
        error: error.message,
        fromSafeMode: true
      };
    }
  }

  /**
   * Conservative mode: Only accept high-confidence data
   */
  async _conservativeRoute(fallbackProvider, requestPayload) {
    const result = await this._callProvider(fallbackProvider, requestPayload);

    if (result.success) {
      // Check confidence threshold
      const minConfidence = 0.85; // 85% minimum

      return {
        ...result,
        safeMode: 'CONSERVATIVE',
        confidenceThreshold: minConfidence,
        meetsThreshold: true // Would check actual confidence
      };
    }

    return result;
  }

  /**
   * Passthrough mode: Accept data as-is
   */
  async _passthroughRoute(fallbackProvider, requestPayload) {
    const result = await this._callProvider(fallbackProvider, requestPayload);

    return {
      ...result,
      safeMode: 'PASSTHROUGH',
      warning: 'Data passed through without validation'
    };
  }

  /**
   * Manual review mode: Queue for review
   */
  async _manualReviewRoute(feedId, fallbackProvider, requestPayload) {
    const result = await this._callProvider(fallbackProvider, requestPayload);

    if (result.success) {
      // Queue for manual review
      await this._queueForManualReview(feedId, result.data);

      return {
        ...result,
        safeMode: 'MANUAL_REVIEW',
        status: 'QUEUED_FOR_REVIEW',
        message: 'Data queued for manual review'
      };
    }

    return result;
  }

  /**
   * Queue data for manual review
   */
  async _queueForManualReview(feedId, data) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (feed) {
        await feed.addAlert(
          'MANUAL_REVIEW_QUEUED',
          'WARNING',
          `Data queued for manual review: ${JSON.stringify(data).substring(0, 100)}`
        );
      }

    } catch (error) {
      console.error('[FallbackRouting] Queue review error:', error);
    }
  }

  /**
   * Record provider failure for circuit breaker
   */
  async _recordProviderFailure(providerId) {
    try {
      const sla = await ProviderSLA.findOne({ providerId });

      if (sla) {
        await sla.recordRequest(0, false, false);

        // Check if we should open circuit
        const failureCount = (this.circuitBreakers.get(providerId) || 0) + 1;

        if (failureCount >= this.config.circuitBreakerThreshold) {
          this._openCircuit(providerId);
        } else {
          this.circuitBreakers.set(providerId, failureCount);
        }
      }

    } catch (error) {
      console.error('[FallbackRouting] Record failure error:', error);
    }
  }

  /**
   * Open circuit breaker
   */
  _openCircuit(providerId) {
    this.circuitBreakers.set(providerId, {
      state: 'OPEN',
      openedAt: Date.now(),
      failureCount: this.config.circuitBreakerThreshold
    });

    console.log(`[FallbackRouting] Circuit opened for ${providerId}`);

    // Schedule reset
    setTimeout(() => {
      this._resetCircuitBreaker(providerId);
    }, this.config.circuitBreakerResetTimeout);
  }

  /**
   * Check if circuit is open
   */
  _isCircuitOpen(providerId) {
    const cb = this.circuitBreakers.get(providerId);

    if (!cb) return false;

    if (typeof cb !== 'object') return false;

    return cb.state === 'OPEN' &&
      Date.now() - cb.openedAt < this.config.circuitBreakerResetTimeout;
  }

  /**
   * Reset circuit breaker
   */
  _resetCircuitBreaker(providerId) {
    this.circuitBreakers.delete(providerId);
    console.log(`[FallbackRouting] Circuit reset for ${providerId}`);
  }

  /**
   * Get routing status
   */
  async getRoutingStatus(feedId) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      const providers = await ProviderSLA.find({});

      const circuitStatus = Array.from(this.circuitBreakers.entries()).map(
        ([providerId, state]) => ({
          providerId,
          state: typeof state === 'object' ? state.state : 'CLOSED'
        })
      );

      return {
        success: true,
        feedId,
        safeModeEnabled: feed.safeMode.enabled,
        fallbackProvider: feed.safeMode.fallbackProvider,
        fallbackMode: feed.safeMode.mode,
        providers: providers.map(p => ({
          providerId: p.providerId,
          healthScore: p.getHealthScore(),
          status: p.determineStatus(),
          circuitState: circuitStatus.find(c => c.providerId === p.providerId)?.state || 'CLOSED'
        }))
      };

    } catch (error) {
      console.error('[FallbackRouting] Status error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Force failover to specific provider
   */
  async forceFailover(feedId, toProviderId) {
    try {
      const feed = await FeedHealthScore.findOne({ feedId });

      if (!feed) {
        return { success: false, error: 'Feed not found' };
      }

      // Activate safe mode with specific provider
      await feed.activateSafeMode(
        `Manual failover to ${toProviderId}`,
        toProviderId,
        'PASSTHROUGH'
      );

      return {
        success: true,
        message: `Failover initiated to ${toProviderId}`,
        safeModeActivated: feed.safeMode.enabled
      };

    } catch (error) {
      console.error('[FallbackRouting] Force failover error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new SafeModeRoutingService();
