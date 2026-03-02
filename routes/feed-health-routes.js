/**
 * Feed Health & Resilience API Routes
 * Endpoints for monitoring, managing, and controlling threat feed reliability
 */

const express = require('express');
const router = express.Router();

const ProviderSLA = require('../models/ProviderSLA');
const FeedHealthScore = require('../models/FeedHealthScore');
const weightedConsensusEngine = require('../services/weightedConsensusEngine');
const feedQualityControlService = require('../services/feedQualityControlService');
const safeModeRoutingService = require('../services/safeModeRoutingService');

// ============ PROVIDER SLA ENDPOINTS ============

/**
 * GET /api/feed-health/providers
 * Get all providers with SLA data
 */
router.get('/providers', async (req, res) => {
  try {
    const providers = await ProviderSLA.find({});

    const formatted = providers.map(p => ({
      providerId: p.providerId,
      type: p.providerType,
      healthScore: p.getHealthScore(),
      status: p.determineStatus(),
      metrics: {
        latency: {
          avg: p.metrics.avgLatency,
          p95: p.metrics.p95Latency,
          p99: p.metrics.p99Latency
        },
        availability: {
          uptime: p.metrics.uptime,
          lastCheck: p.lastHealthCheck
        },
        errors: {
          rate: p.metrics.errorRate,
          timeouts: p.metrics.timeoutCount,
          incidents: p.metrics.incidentCount
        },
        accuracy: p.metrics.accuracyScore,
        freshness: p.metrics.dataFreshness
      },
      weight: p.weight,
      sla: {
        targets: p.slaTargets,
        compliant: p.determineStatus() !== 'DOWN'
      }
    }));

    res.json({
      success: true,
      count: formatted.length,
      providers: formatted
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Get providers error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/feed-health/providers/:providerId
 * Get specific provider details
 */
router.get('/providers/:providerId', async (req, res) => {
  try {
    const provider = await ProviderSLA.findOne({ providerId: req.params.providerId });

    if (!provider) {
      return res.status(404).json({
        success: false,
        error: 'Provider not found'
      });
    }

    res.json({
      success: true,
      provider: {
        providerId: provider.providerId,
        type: provider.providerType,
        healthScore: provider.getHealthScore(),
        status: provider.determineStatus(),
        metrics: provider.metrics,
        healthHistory: provider.healthHistory.slice(-50),
        weights: {
          latency: 0.20,
          availability: 0.30,
          errors: 0.20,
          accuracy: 0.20,
          freshness: 0.10
        }
      }
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Get provider error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/providers/:providerId/record-request
 * Record provider request metrics
 */
router.post('/providers/:providerId/record-request', async (req, res) => {
  try {
    const { latency, success, timeout } = req.body;

    const provider = await ProviderSLA.findOne({ providerId: req.params.providerId });

    if (!provider) {
      return res.status(404).json({
        success: false,
        error: 'Provider not found'
      });
    }

    await provider.recordRequest(latency, success, timeout);

    res.json({
      success: true,
      healthScore: provider.getHealthScore(),
      status: provider.determineStatus()
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Record request error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/providers/rank-by-health
 * Get providers ranked by health
 */
router.get('/providers/rank/by-health', async (req, res) => {
  try {
    const ranking = await ProviderSLA.getRankingsByHealth();

    res.json({
      success: true,
      ranking: ranking.map((p, index) => ({
        rank: index + 1,
        providerId: p.providerId,
        healthScore: p.getHealthScore(),
        status: p.determineStatus()
      }))
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Rank providers error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============ FEED HEALTH ENDPOINTS ============

/**
 * GET /api/feed-health/feeds
 * Get all feeds with health status
 */
router.get('/feeds', async (req, res) => {
  try {
    const feeds = await FeedHealthScore.find({});

    const formatted = feeds.map(f => ({
      feedId: f.feedId,
      overallHealth: f.overallHealth,
      healthStatus: f.healthStatus,
      consensus: {
        agreementRate: f.consensus.agreementRate,
        conflictCount: f.consensus.conflictCount,
        lastConflict: f.consensus.lastConflict
      },
      quality: f.quality,
      safeMode: {
        enabled: f.safeMode.enabled,
        reason: f.safeMode.reason,
        fallbackProvider: f.safeMode.fallbackProvider
      },
      drift: {
        detected: f.drift.driftDetected,
        percentage: f.drift.driftPercentage
      },
      alerts: f.activeAlerts.length,
      lastCheck: f.lastCheck
    }));

    res.json({
      success: true,
      count: formatted.length,
      feeds: formatted
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Get feeds error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/feed-health/feeds/:feedId
 * Get specific feed health report
 */
router.get('/feeds/:feedId', async (req, res) => {
  try {
    const report = await feedQualityControlService.getQualityReport(req.params.feedId);

    res.json(report);

  } catch (error) {
    console.error('[FeedHealthAPI] Get feed error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/feeds/:feedId/check-quality
 * Run quality check on feed
 */
router.post('/feeds/:feedId/check-quality', async (req, res) => {
  try {
    const result = await feedQualityControlService.runQualityCheck(req.params.feedId);

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Quality check error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/feeds/:feedId/detect-drift
 * Detect data drift
 */
router.post('/feeds/:feedId/detect-drift', async (req, res) => {
  try {
    const { currentDataPoints } = req.body;

    if (currentDataPoints === undefined) {
      return res.status(400).json({
        success: false,
        error: 'currentDataPoints required'
      });
    }

    const result = await feedQualityControlService.detectDrift(
      req.params.feedId,
      currentDataPoints
    );

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Detect drift error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/feeds/:feedId/calibrate-confidence
 * Calibrate feed confidence based on validation
 */
router.post('/feeds/:feedId/calibrate-confidence', async (req, res) => {
  try {
    const { validationData } = req.body;

    if (!validationData || !Array.isArray(validationData)) {
      return res.status(400).json({
        success: false,
        error: 'validationData array required'
      });
    }

    const result = await feedQualityControlService.calibrateConfidence(
      req.params.feedId,
      validationData
    );

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Calibrate confidence error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/feed-health/feeds/:feedId/consensus-stats
 * Get consensus statistics
 */
router.get('/feeds/:feedId/consensus-stats', async (req, res) => {
  try {
    const stats = await weightedConsensusEngine.getConsensusStatistics(req.params.feedId);

    res.json(stats);

  } catch (error) {
    console.error('[FeedHealthAPI] Consensus stats error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============ CONSENSUS RESOLUTION ENDPOINTS ============

/**
 * POST /api/feed-health/consensus/resolve
 * Resolve conflict between provider results
 */
router.post('/consensus/resolve', async (req, res) => {
  try {
    const { feedId, providerResults } = req.body;

    if (!feedId || !providerResults || !Array.isArray(providerResults)) {
      return res.status(400).json({
        success: false,
        error: 'feedId and providerResults[] required'
      });
    }

    const result = await weightedConsensusEngine.resolveConflict(feedId, providerResults);

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Consensus resolve error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/consensus/batch-resolve
 * Batch resolve multiple conflicts
 */
router.post('/consensus/batch-resolve', async (req, res) => {
  try {
    const { feedId, providerResultsBatch } = req.body;

    if (!feedId || !providerResultsBatch) {
      return res.status(400).json({
        success: false,
        error: 'feedId and providerResultsBatch required'
      });
    }

    const result = await weightedConsensusEngine.batchResolveConflicts(
      feedId,
      providerResultsBatch
    );

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Batch resolve error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============ SAFE MODE & FAILOVER ENDPOINTS ============

/**
 * GET /api/feed-health/routing/:feedId
 * Get routing status
 */
router.get('/routing/:feedId', async (req, res) => {
  try {
    const status = await safeModeRoutingService.getRoutingStatus(req.params.feedId);

    res.json(status);

  } catch (error) {
    console.error('[FeedHealthAPI] Routing status error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/routing/:feedId/request
 * Route request with fallback
 */
router.post('/routing/:feedId/request', async (req, res) => {
  try {
    const { primaryProviders, requestPayload } = req.body;

    if (!primaryProviders || !Array.isArray(primaryProviders)) {
      return res.status(400).json({
        success: false,
        error: 'primaryProviders array required'
      });
    }

    const result = await safeModeRoutingService.routeRequest(
      req.params.feedId,
      primaryProviders,
      requestPayload || {}
    );

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Route request error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/routing/:feedId/failover
 * Force failover to specific provider
 */
router.post('/routing/:feedId/failover', async (req, res) => {
  try {
    const { toProviderId } = req.body;

    if (!toProviderId) {
      return res.status(400).json({
        success: false,
        error: 'toProviderId required'
      });
    }

    const result = await safeModeRoutingService.forceFailover(
      req.params.feedId,
      toProviderId
    );

    res.json(result);

  } catch (error) {
    console.error('[FeedHealthAPI] Force failover error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/feeds/:feedId/safe-mode/activate
 * Manually activate safe mode
 */
router.post('/feeds/:feedId/safe-mode/activate', async (req, res) => {
  try {
    const { reason, fallbackProvider, mode } = req.body;

    const feed = await FeedHealthScore.findOne({ feedId: req.params.feedId });

    if (!feed) {
      return res.status(404).json({
        success: false,
        error: 'Feed not found'
      });
    }

    await feed.activateSafeMode(
      reason || 'Manual activation',
      fallbackProvider || 'INTERNAL',
      mode || 'CONSERVATIVE'
    );

    res.json({
      success: true,
      message: 'Safe mode activated',
      safeMode: feed.safeMode
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Activate safe mode error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/feed-health/feeds/:feedId/safe-mode/deactivate
 * Manually deactivate safe mode
 */
router.post('/feeds/:feedId/safe-mode/deactivate', async (req, res) => {
  try {
    const feed = await FeedHealthScore.findOne({ feedId: req.params.feedId });

    if (!feed) {
      return res.status(404).json({
        success: false,
        error: 'Feed not found'
      });
    }

    await feed.deactivateSafeMode();

    res.json({
      success: true,
      message: 'Safe mode deactivated',
      safeMode: feed.safeMode
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Deactivate safe mode error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============ MONITORING ENDPOINTS ============

/**
 * GET /api/feed-health/critical-feeds
 * Get feeds in critical condition
 */
router.get('/critical-feeds', async (req, res) => {
  try {
    const feeds = await FeedHealthScore.getCriticalFeeds();

    res.json({
      success: true,
      count: feeds.length,
      feeds: feeds.map(f => ({
        feedId: f.feedId,
        overallHealth: f.overallHealth,
        healthStatus: f.healthStatus,
        safeMode: f.safeMode.enabled,
        alerts: f.activeAlerts.length
      }))
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Critical feeds error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/feed-health/safe-mode-feeds
 * Get feeds in safe mode
 */
router.get('/safe-mode-feeds', async (req, res) => {
  try {
    const feeds = await FeedHealthScore.getFeedsInSafeMode();

    res.json({
      success: true,
      count: feeds.length,
      feeds: feeds.map(f => ({
        feedId: f.feedId,
        reason: f.safeMode.reason,
        fallbackProvider: f.safeMode.fallbackProvider,
        mode: f.safeMode.mode,
        activatedAt: f.safeMode.activatedAt
      }))
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Safe mode feeds error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/feed-health/drift-detected-feeds
 * Get feeds with detected drift
 */
router.get('/drift-detected-feeds', async (req, res) => {
  try {
    const feeds = await FeedHealthScore.getFeedsWithDrift();

    res.json({
      success: true,
      count: feeds.length,
      feeds: feeds.map(f => ({
        feedId: f.feedId,
        driftPercentage: f.drift.driftPercentage,
        threshold: f.drift.driftThreshold,
        lastDetected: f.drift.lastDriftCheck,
        safeMode: f.safeMode.enabled
      }))
    });

  } catch (error) {
    console.error('[FeedHealthAPI] Drift feeds error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
