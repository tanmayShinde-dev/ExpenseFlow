/**
 * Continuous Session Trust Re-Scoring API Routes
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Complete API for real-time session trust evaluation, signal management,
 * challenge handling, and adaptive threshold configuration.
 */

const express = require('express');
const router = express.Router();

const ContinuousSessionTrustService = require('../services/continuousSessionTrustService');
const BehaviorSignalAnalysisEngine = require('../services/behaviorSignalAnalysisEngine');
const ChallengeOrchestrationService = require('../services/challengeOrchestrationService');
const AdaptiveThresholdEngine = require('../services/adaptiveThresholdEngine');
const ThreatIntelIntegrationService = require('../services/threatIntelIntegrationService');

const SessionTrustScore = require('../models/SessionTrustScore');
const SessionBehaviorSignal = require('../models/SessionBehaviorSignal');
const SessionChallenge = require('../models/SessionChallenge');
const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');

const authMiddleware = require('../middleware/auth');

// Apply authentication to all routes
router.use(authMiddleware);

// ========================================
// SESSION TRUST SCORE MANAGEMENT
// ========================================

/**
 * GET /api/session-trust/threat-intel/status
 * Get threat intelligence provider and cache status
 */
router.get('/threat-intel/status', async (req, res) => {
  try {
    const status = await ThreatIntelIntegrationService.getStatus();

    res.json({
      success: true,
      data: status
    });
  } catch (error) {
    console.error('Error getting threat intel status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get threat intel status',
      message: error.message
    });
  }
});

/**
 * POST /api/session-trust/threat-intel/assess
 * Assess provided indicators via configured providers
 */
router.post('/threat-intel/assess', async (req, res) => {
  try {
    const {
      ipAddress,
      malwareChecksum,
      c2CallbackUrl,
      forceRefresh = false
    } = req.body || {};

    const assessment = await ThreatIntelIntegrationService.getThreatAssessment({
      ipAddress,
      malwareChecksum,
      c2CallbackUrl,
      forceRefresh,
      requestContext: {
        userId: req.user?._id,
        sessionId: req.sessionId
      }
    });

    res.json({
      success: true,
      data: assessment
    });
  } catch (error) {
    console.error('Error assessing threat intel:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assess threat intel',
      message: error.message
    });
  }
});

/**
 * POST /api/session-trust/threat-intel/ingest
 * Ingest external feed updates and immediately propagate to active sessions
 */
router.post('/threat-intel/ingest', async (req, res) => {
  try {
    const feedToken = req.headers['x-threat-intel-token'];
    const configuredFeedToken = process.env.THREAT_INTEL_INGEST_TOKEN;

    if (configuredFeedToken && feedToken !== configuredFeedToken) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized feed token'
      });
    }

    const {
      indicatorType,
      indicatorValue,
      source = 'EXTERNAL_FEED',
      ttlSeconds
    } = req.body || {};

    const ingested = await ThreatIntelIntegrationService.ingestIndicator({
      indicatorType,
      indicatorValue,
      source,
      ttlSeconds
    });

    const propagation = await ContinuousSessionTrustService.propagateThreatIntelUpdate({
      indicatorType,
      indicatorValue
    });

    res.json({
      success: true,
      data: {
        ingested,
        propagation
      }
    });
  } catch (error) {
    console.error('Error ingesting threat intel feed:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to ingest threat intel feed',
      message: error.message
    });
  }
});

/**
 * GET /api/session-trust/current
 * Get current session's trust score
 */
router.get('/current', async (req, res) => {
  try {
    const { sessionId, userId } = req.session;

    const trustScore = await SessionTrustScore.findOne({ sessionId })
      .populate('activeChallengeId');

    if (!trustScore) {
      // Initialize new trust score
      const newTrust = await ContinuousSessionTrustService.initializeSessionTrust(
        sessionId,
        userId
      );

      return res.json({
        success: true,
        data: newTrust,
      });
    }

    res.json({
      success: true,
      data: trustScore,
    });
  } catch (error) {
    console.error('Error getting current trust score:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get trust score',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/evaluate
 * Trigger trust evaluation for current session
 */
router.post('/evaluate', async (req, res) => {
  try {
    const { sessionId, userId } = req.session;
    const requestContext = {
      endpoint: req.body.endpoint || req.path,
      method: req.method,
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
      location: req.body.location, // Client can provide location
      deviceFingerprint: req.body.deviceFingerprint,
      requiredRole: req.body.requiredRole,
      recentRequestCount: req.body.recentRequestCount,
      ...req.body.context,
    };

    const result = await ContinuousSessionTrustService.evaluateSessionTrust(
      sessionId,
      userId,
      requestContext
    );

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error evaluating trust:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to evaluate trust',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/rescore
 * Force immediate trust re-scoring
 */
router.post('/rescore', async (req, res) => {
  try {
    const { sessionId, userId } = req.session;
    const requestContext = req.body.context || {};

    const result = await ContinuousSessionTrustService.performTrustReScoring(
      sessionId,
      userId,
      requestContext
    );

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error re-scoring trust:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to re-score trust',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/metrics
 * Get user's trust metrics across all sessions
 */
router.get('/metrics', async (req, res) => {
  try {
    const { userId } = req.session;

    const metrics = await ContinuousSessionTrustService.getUserTrustMetrics(userId);

    res.json({
      success: true,
      data: metrics,
    });
  } catch (error) {
    console.error('Error getting trust metrics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get metrics',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/history
 * Get session trust score history
 */
router.get('/history', async (req, res) => {
  try {
    const { userId } = req.session;
    const { sessionId, limit = 50, offset = 0 } = req.query;

    const query = { userId };
    if (sessionId) query.sessionId = sessionId;

    const history = await SessionTrustScore
      .find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(offset))
      .populate('activeChallengeId');

    const total = await SessionTrustScore.countDocuments(query);

    res.json({
      success: true,
      data: history,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
      },
    });
  } catch (error) {
    console.error('Error getting trust history:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get history',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/terminate
 * Terminate current session due to security concerns
 */
router.post('/terminate', async (req, res) => {
  try {
    const { sessionId, userId } = req.session;
    const { reason = 'MANUAL_TERMINATION' } = req.body;

    const result = await ContinuousSessionTrustService.terminateSession(
      sessionId,
      userId,
      reason
    );

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error terminating session:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to terminate session',
      message: error.message,
    });
  }
});

// ========================================
// BEHAVIOR SIGNAL MANAGEMENT
// ========================================

/**
 * POST /api/session-trust/signals/record
 * Record a new behavior signal
 */
router.post('/signals/record', async (req, res) => {
  try {
    const { sessionId, userId } = req.session;
    const { signalType, details, severity = 'MEDIUM' } = req.body;

    if (!signalType) {
      return res.status(400).json({
        success: false,
        error: 'signalType is required',
      });
    }

    const signal = await ContinuousSessionTrustService.recordBehaviorSignal(
      sessionId,
      userId,
      signalType,
      details,
      severity
    );

    res.json({
      success: true,
      data: signal,
    });
  } catch (error) {
    console.error('Error recording signal:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to record signal',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/signals
 * Get behavior signals for current session or user
 */
router.get('/signals', async (req, res) => {
  try {
    const { userId } = req.session;
    const {
      sessionId,
      signalType,
      severity,
      limit = 100,
      offset = 0,
      hoursBack = 24,
    } = req.query;

    const query = { userId };
    if (sessionId) query.sessionId = sessionId;
    if (signalType) query.signalType = signalType;
    if (severity) query.severity = severity;

    // Filter by time range
    const since = new Date(Date.now() - (parseInt(hoursBack) * 60 * 60 * 1000));
    query.detectedAt = { $gte: since };

    const signals = await SessionBehaviorSignal
      .find(query)
      .sort({ detectedAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(offset));

    const total = await SessionBehaviorSignal.countDocuments(query);

    res.json({
      success: true,
      data: signals,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
      },
    });
  } catch (error) {
    console.error('Error getting signals:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get signals',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/signals/:signalId
 * Get specific signal details
 */
router.get('/signals/:signalId', async (req, res) => {
  try {
    const { signalId } = req.params;

    const signal = await SessionBehaviorSignal.findById(signalId)
      .populate('userId', 'email name')
      .populate('sessionId', 'ipAddress userAgent');

    if (!signal) {
      return res.status(404).json({
        success: false,
        error: 'Signal not found',
      });
    }

    res.json({
      success: true,
      data: signal,
    });
  } catch (error) {
    console.error('Error getting signal:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get signal',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/signals/:signalId/false-positive
 * Mark signal as false positive
 */
router.post('/signals/:signalId/false-positive', async (req, res) => {
  try {
    const { userId } = req.session;
    const { signalId } = req.params;

    const result = await AdaptiveThresholdEngine.recordFalsePositive(signalId, userId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error marking false positive:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark false positive',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/signals/analyze
 * Analyze recent signals for patterns
 */
router.get('/signals/analyze', async (req, res) => {
  try {
    const { userId } = req.session;
    const { hoursBack = 24 } = req.query;

    const signals = await BehaviorSignalAnalysisEngine.getSignalHistory(
      userId,
      parseInt(hoursBack)
    );

    const analysis = await BehaviorSignalAnalysisEngine.analyzeSignals(signals, userId);

    res.json({
      success: true,
      data: {
        signals: signals.length,
        analysis,
      },
    });
  } catch (error) {
    console.error('Error analyzing signals:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to analyze signals',
      message: error.message,
    });
  }
});

// ========================================
// CHALLENGE MANAGEMENT
// ========================================

/**
 * GET /api/session-trust/challenges/pending
 * Get pending challenges for current user
 */
router.get('/challenges/pending', async (req, res) => {
  try {
    const { userId } = req.session;

    const challenges = await ChallengeOrchestrationService.getPendingChallenges(userId);

    res.json({
      success: true,
      data: challenges,
    });
  } catch (error) {
    console.error('Error getting pending challenges:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get challenges',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/challenges/:challengeId
 * Get challenge status
 */
router.get('/challenges/:challengeId', async (req, res) => {
  try {
    const { challengeId } = req.params;

    const status = await ChallengeOrchestrationService.getChallengeStatus(challengeId);

    res.json({
      success: true,
      data: status,
    });
  } catch (error) {
    console.error('Error getting challenge status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get challenge status',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/challenges/:challengeId/respond
 * Respond to a challenge
 */
router.post('/challenges/:challengeId/respond', async (req, res) => {
  try {
    const { challengeId } = req.params;
    const { response, responseTimeMs } = req.body;

    if (!response) {
      return res.status(400).json({
        success: false,
        error: 'response is required',
      });
    }

    const result = await ChallengeOrchestrationService.processChallengeResponse(
      challengeId,
      response,
      responseTimeMs || 0
    );

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error responding to challenge:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process response',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/challenges/:challengeId/cancel
 * Cancel a challenge (admin only)
 */
router.post('/challenges/:challengeId/cancel', async (req, res) => {
  try {
    const { challengeId } = req.params;
    const { reason = 'Cancelled by user' } = req.body;

    const result = await ChallengeOrchestrationService.cancelChallenge(challengeId, reason);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error cancelling challenge:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to cancel challenge',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/challenges/history
 * Get challenge history
 */
router.get('/challenges/history', async (req, res) => {
  try {
    const { userId } = req.session;
    const { sessionId, status, limit = 50, offset = 0 } = req.query;

    const query = { userId };
    if (sessionId) query.sessionId = sessionId;
    if (status) query.status = status;

    const challenges = await SessionChallenge
      .find(query)
      .sort({ issuedAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(offset));

    const total = await SessionChallenge.countDocuments(query);

    res.json({
      success: true,
      data: challenges,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
      },
    });
  } catch (error) {
    console.error('Error getting challenge history:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get history',
      message: error.message,
    });
  }
});

// ========================================
// ADAPTIVE THRESHOLD MANAGEMENT
// ========================================

/**
 * GET /api/session-trust/policy
 * Get user's adaptive threshold policy
 */
router.get('/policy', async (req, res) => {
  try {
    const { userId } = req.session;

    const policy = await AdaptiveThresholdEngine.getOrCreatePolicy(userId);

    res.json({
      success: true,
      data: policy,
    });
  } catch (error) {
    console.error('Error getting policy:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get policy',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/policy/update
 * Update adaptive threshold policy
 */
router.post('/policy/update', async (req, res) => {
  try {
    const { userId } = req.session;
    const updates = req.body;

    let policy = await AdaptiveThresholdPolicy.findOne({ userId });

    if (!policy) {
      policy = await AdaptiveThresholdEngine.getOrCreatePolicy(userId);
    }

    // Update allowed fields
    if (updates.componentThresholds) {
      Object.assign(policy.componentThresholds, updates.componentThresholds);
    }

    if (updates.challengeStrategy) {
      Object.assign(policy.challengeStrategy, updates.challengeStrategy);
    }

    if (updates.autoAdjustment !== undefined) {
      policy.autoAdjustment.enabled = updates.autoAdjustment;
    }

    policy.lastUpdatedAt = new Date();
    await policy.save();

    res.json({
      success: true,
      data: policy,
    });
  } catch (error) {
    console.error('Error updating policy:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update policy',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/policy/baseline/update
 * Update user baseline from recent behavior
 */
router.post('/policy/baseline/update', async (req, res) => {
  try {
    const { userId } = req.session;

    const result = await AdaptiveThresholdEngine.updateUserBaseline(userId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error updating baseline:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update baseline',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/policy/baseline/train
 * Train baseline model from historical data
 */
router.post('/policy/baseline/train', async (req, res) => {
  try {
    const { userId } = req.session;

    const result = await AdaptiveThresholdEngine.trainBaselineModel(userId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error training baseline:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to train baseline',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/policy/sensitivity
 * Get current sensitivity level
 */
router.get('/policy/sensitivity', async (req, res) => {
  try {
    const { userId } = req.session;

    const sensitivity = await AdaptiveThresholdEngine.getCurrentSensitivity(userId);

    res.json({
      success: true,
      data: sensitivity,
    });
  } catch (error) {
    console.error('Error getting sensitivity:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get sensitivity',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/policy/recommendations
 * Get policy recommendations
 */
router.get('/policy/recommendations', async (req, res) => {
  try {
    const { userId } = req.session;

    const recommendations = await AdaptiveThresholdEngine.getPolicyRecommendations(userId);

    res.json({
      success: true,
      data: recommendations,
    });
  } catch (error) {
    console.error('Error getting recommendations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get recommendations',
      message: error.message,
    });
  }
});

/**
 * POST /api/session-trust/policy/exceptions
 * Add temporary threshold exception
 */
router.post('/policy/exceptions', async (req, res) => {
  try {
    const { userId } = req.session;
    const { exceptionType, durationDays, component } = req.body;

    if (!exceptionType || !durationDays) {
      return res.status(400).json({
        success: false,
        error: 'exceptionType and durationDays are required',
      });
    }

    const result = await AdaptiveThresholdEngine.addTemporaryException(
      userId,
      exceptionType,
      durationDays,
      component
    );

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error adding exception:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add exception',
      message: error.message,
    });
  }
});

// ========================================
// MONITORING & ANALYTICS
// ========================================

/**
 * GET /api/session-trust/monitoring/dashboard
 * Get trust monitoring dashboard data
 */
router.get('/monitoring/dashboard', async (req, res) => {
  try {
    const { userId } = req.session;

    // Get active sessions with trust scores
    const activeSessions = await SessionTrustScore.find({
      userId,
      terminatedAt: { $exists: false },
    });

    // Get recent signals
    const recentSignals = await SessionBehaviorSignal.find({
      userId,
      detectedAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    }).sort({ detectedAt: -1 }).limit(10);

    // Get pending challenges
    const pendingChallenges = await SessionChallenge.find({
      userId,
      status: 'PENDING',
    });

    // Calculate aggregate metrics
    const avgTrustScore = activeSessions.length > 0
      ? Math.round(activeSessions.reduce((sum, s) => sum + s.currentTrustScore, 0) / activeSessions.length)
      : 100;

    const tierDistribution = {
      NORMAL: activeSessions.filter(s => s.currentEnforcementTier === 'NORMAL').length,
      MONITORED: activeSessions.filter(s => s.currentEnforcementTier === 'MONITORED').length,
      CHALLENGED: activeSessions.filter(s => s.currentEnforcementTier === 'CHALLENGED').length,
      TERMINATED: 0,
    };

    res.json({
      success: true,
      data: {
        overview: {
          activeSessions: activeSessions.length,
          averageTrustScore: avgTrustScore,
          pendingChallenges: pendingChallenges.length,
          recentSignals: recentSignals.length,
        },
        tierDistribution,
        recentSignals,
        sessions: activeSessions,
      },
    });
  } catch (error) {
    console.error('Error getting dashboard data:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get dashboard data',
      message: error.message,
    });
  }
});

/**
 * GET /api/session-trust/monitoring/analytics
 * Get trust analytics over time
 */
router.get('/monitoring/analytics', async (req, res) => {
  try {
    const { userId } = req.session;
    const { daysBack = 7 } = req.query;

    const since = new Date(Date.now() - (parseInt(daysBack) * 24 * 60 * 60 * 1000));

    // Aggregate trust scores over time
    const trustScores = await SessionTrustScore.find({
      userId,
      createdAt: { $gte: since },
    }).sort({ createdAt: -1 });

    // Aggregate signals over time
    const signals = await SessionBehaviorSignal.find({
      userId,
      detectedAt: { $gte: since },
    });

    // Challenges over time
    const challenges = await SessionChallenge.find({
      userId,
      issuedAt: { $gte: since },
    });

    res.json({
      success: true,
      data: {
        trustScores: trustScores.map(s => ({
          date: s.createdAt,
          score: s.currentTrustScore,
          tier: s.currentEnforcementTier,
        })),
        signalsByType: this.aggregateByType(signals, 'signalType'),
        challengesByType: this.aggregateByType(challenges, 'challengeType'),
        successRate: this.calculateSuccessRate(challenges),
      },
    });
  } catch (error) {
    console.error('Error getting analytics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get analytics',
      message: error.message,
    });
  }
});

/**
 * Helper: Aggregate by type
 */
router.aggregateByType = function(items, field) {
  const counts = {};
  items.forEach(item => {
    const type = item[field];
    counts[type] = (counts[type] || 0) + 1;
  });
  return counts;
};

/**
 * Helper: Calculate challenge success rate
 */
router.calculateSuccessRate = function(challenges) {
  if (challenges.length === 0) return 100;

  const completed = challenges.filter(c => c.status === 'COMPLETED' && c.result?.success).length;
  return Math.round((completed / challenges.length) * 100);
};

module.exports = router;
