/**
 * Continuous Session Trust Re-Scoring Service
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Main orchestrator for real-time session trust evaluation.
 * Manages periodic re-scoring, signal collection, and enforcement tier transitions.
 */

const SessionTrustScore = require('../models/SessionTrustScore');
const SessionBehaviorSignal = require('../models/SessionBehaviorSignal');
const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');
const SessionChallenge = require('../models/SessionChallenge');
const Session = require('../models/Session');
const User = require('../models/User');

const BehaviorSignalAnalysisEngine = require('./behaviorSignalAnalysisEngine');
const TrustScoringEngine = require('./trustScoringEngine');
const ChallengeOrchestrationService = require('./challengeOrchestrationService');
const AdaptiveThresholdEngine = require('./adaptiveThresholdEngine');
const ThreatIntelIntegrationService = require('./threatIntelIntegrationService');

class ContinuousSessionTrustService {
  /**
   * Initialize or update trust score for a session
   */
  async initializeSessionTrust(sessionId, userId) {
    try {
      let trustScore = await SessionTrustScore.findOne({ sessionId });

      if (!trustScore) {
        // Create new trust score record
        const session = await Session.findById(sessionId);
        
        trustScore = new SessionTrustScore({
          sessionId,
          userId,
          sessionInitiatedAt: session?.createdAt || new Date(),
          currentTrustScore: 100,
          currentEnforcementTier: 'NORMAL',
          confidenceLevel: 'LOW',
          dataPointCount: 0,
        });

        await trustScore.save();
        
        // Start continuous monitoring
        this.scheduleNextScoring(trustScore);
      }

      return trustScore;
    } catch (error) {
      console.error('Error initializing session trust:', error);
      throw error;
    }
  }

  /**
   * Evaluate session trust in real-time (called on each request)
   */
  async evaluateSessionTrust(sessionId, userId, requestContext = {}) {
    try {
      const trustScore = await SessionTrustScore.findOne({ sessionId });
      
      if (!trustScore) {
        return await this.initializeSessionTrust(sessionId, userId);
      }

      // Check if session should be re-scored (based on schedule)
      if (this.shouldReScore(trustScore)) {
        return await this.performTrustReScoring(sessionId, userId, requestContext);
      }

      // Check current enforcement tier
      const tier = trustScore.currentEnforcementTier;
      
      return {
        trustScore: trustScore.currentTrustScore,
        enforcementTier: tier,
        action: this.getEnforcementAction(tier),
        detail: trustScore.getTrustExplanation(),
      };
    } catch (error) {
      console.error('Error evaluating session trust:', error);
      // Safe failure: allow session but flag for review
      return {
        trustScore: 50,
        enforcementTier: 'MONITORED',
        action: 'ALLOW_WITH_MONITORING',
        error: error.message,
      };
    }
  }

  /**
   * Perform continuous trust re-scoring
   */
  async performTrustReScoring(sessionId, userId, requestContext = {}) {
    try {
      const trustScore = await SessionTrustScore.findOne({ sessionId });
      
      if (!trustScore) {
        throw new Error('Trust score record not found');
      }

      // Enrich with external threat intelligence before signal collection
      const threatIntel = await ThreatIntelIntegrationService.getThreatAssessment({
        ipAddress: requestContext.ipAddress,
        malwareChecksum: requestContext.malwareChecksum,
        c2CallbackUrl: requestContext.c2CallbackUrl,
        requestContext
      });

      const scoringContext = {
        ...requestContext,
        threatIntel,
        knownThreats: [
          ...(requestContext.knownThreats || []),
          ...(threatIntel.overallRiskScore >= 80 && requestContext.ipAddress ? [requestContext.ipAddress] : [])
        ]
      };

      // Collect behavioral signals
      const signals = await BehaviorSignalAnalysisEngine.collectSignals(
        sessionId,
        userId,
        scoringContext
      );

      // Analyze signals for anomalies
      const analysis = await BehaviorSignalAnalysisEngine.analyzeSignals(
        signals,
        userId
      );

      // Get adaptive thresholds for this user
      const thresholdPolicy = await AdaptiveThresholdEngine.getOrCreatePolicy(userId);

      // Calculate new trust score
      const newComponentScores = await TrustScoringEngine.calculateComponentScores(
        signals,
        analysis,
        thresholdPolicy
      );

      // Update trust score with new components
      trustScore.updateScore(newComponentScores, analysis.anomalies);

      // Update confidence based on data points
      trustScore.confidenceLevel = this.calculateConfidenceLevel(signals.length);
      trustScore.dataPointCount = signals.length;

      // Check for tier transitions
      const oldTier = trustScore.currentEnforcementTier;
      const newTier = trustScore.getEnforcementTier(trustScore.currentTrustScore);

      if (oldTier !== newTier) {
        await this.handleTierTransition(
          trustScore,
          oldTier,
          newTier,
          analysis
        );
      }

      // Persist updated trust score
      await trustScore.save();

      // Schedule next scoring
      this.scheduleNextScoring(trustScore);

      return {
        trustScore: trustScore.currentTrustScore,
        enforcementTier: trustScore.currentEnforcementTier,
        action: this.getEnforcementAction(trustScore.currentEnforcementTier),
        detail: trustScore.getTrustExplanation(),
        threatIntel,
        signals: signals.length,
        componentsUpdated: Object.keys(newComponentScores),
      };
    } catch (error) {
      console.error('Error during trust re-scoring:', error);
      throw error;
    }
  }

  /**
   * Handle tier transition with appropriate actions
   */
  async handleTierTransition(trustScore, oldTier, newTier, analysis) {
    try {
      console.log(`Tier transition: ${oldTier} → ${newTier}`);

      // Downgrade transitions need more action
      if (this.isTierDowngrade(oldTier, newTier)) {
        if (newTier === 'CHALLENGED') {
          // Issue challenge
          await ChallengeOrchestrationService.selectAndIssueChallenge(
            trustScore.sessionId,
            trustScore.userId,
            'trust_score_below_threshold',
            trustScore.currentTrustScore
          );
        } else if (newTier === 'TERMINATED') {
          // Terminate session
          trustScore.terminatedAt = new Date();
          trustScore.terminationReason = 'TRUST_SCORE_BELOW_THRESHOLD';
          
          // Kill the session
          await Session.findByIdAndUpdate(
            trustScore.sessionId,
            { active: false, terminatedAt: new Date() }
          );

          // Notify user
          const user = await User.findById(trustScore.userId);
          // This would trigger notification service
          console.log(`Session terminated for user ${user.email}`);
        }
      }

      // Upgrade transitions can reduce friction
      if (this.isTierUpgrade(oldTier, newTier)) {
        // Cancel pending challenges if moving to NORMAL
        if (newTier === 'NORMAL') {
          await SessionChallenge.updateMany(
            { sessionId: trustScore.sessionId, status: 'PENDING' },
            { status: 'CANCELLED', 'result.reason': 'Session trust improved' }
          );
        }
      }
    } catch (error) {
      console.error('Error handling tier transition:', error);
      // Don't fail entire re-score on transition error
    }
  }

  /**
   * Collect and store a behavior signal
   */
  async recordBehaviorSignal(sessionId, userId, signalType, details = {}, severity = 'MEDIUM') {
    try {
      const signal = new SessionBehaviorSignal({
        sessionId,
        userId,
        signalType,
        severity,
        details,
        detectedAt: new Date(),
        trustImpact: this.calculateTrustImpact(signalType, severity),
      });

      // Get anomaly score
      signal.anomalyScore = await BehaviorSignalAnalysisEngine.scoreAnomalyProbability(
        signal,
        userId
      );

      // Determine action
      signal.actionTaken = this.determineActionForSignal(signal);

      await signal.save();

      // If critical, trigger immediate re-score
      if (signal.isCritical()) {
        await this.performTrustReScoring(sessionId, userId);
      }

      return signal;
    } catch (error) {
      console.error('Error recording behavior signal:', error);
      throw error;
    }
  }

  /**
   * Get enforcement action based on tier
   */
  getEnforcementAction(tier) {
    const actions = {
      'NORMAL': 'ALLOW',
      'MONITORED': 'ALLOW_WITH_MONITORING',
      'CHALLENGED': 'CHALLENGE_REQUIRED',
      'TERMINATED': 'SESSION_TERMINATED',
    };

    return actions[tier] || 'ALLOW_WITH_MONITORING';
  }

  /**
   * Check if session should be re-scored now
   */
  shouldReScore(trustScore) {
    // Re-score if:
    // 1. Next scoring time has passed
    // 2. Trust score is in CHALLENGED tier (more frequent)
    // 3. Confidence is low

    if (trustScore.currentEnforcementTier === 'CHALLENGED') {
      // Frequent re-scoring when challenged
      return Date.now() - trustScore.lastScoringAt > 30000; // 30 seconds
    }

    if (trustScore.confidenceLevel === 'LOW') {
      // Frequent re-scoring when low confidence
      return Date.now() - trustScore.lastScoringAt > 60000; // 1 minute
    }

    // Normal re-scoring
    return Date.now() - trustScore.nextScoringScheduledAt > 0;
  }

  /**
   * Schedule next trust evaluation
   */
  scheduleNextScoring(trustScore) {
    // Schedule re-scoring based on confidence and tier
    let delayMs = 300000; // Default: 5 minutes

    if (trustScore.currentEnforcementTier === 'CHALLENGED') {
      delayMs = 30000; // 30 seconds for challenged sessions
    } else if (trustScore.currentEnforcementTier === 'MONITORED') {
      delayMs = 120000; // 2 minutes for monitored sessions
    } else if (trustScore.confidenceLevel === 'LOW') {
      delayMs = 60000; // 1 minute for low confidence
    }

    trustScore.nextScoringScheduledAt = new Date(Date.now() + delayMs);
  }

  /**
   * Calculate trust impact for a signal
   */
  calculateTrustImpact(signalType, severity) {
    const impactMap = {
      // Critical impacts
      'IMPOSSIBLE_TRAVEL': -50,
      'KNOWN_THREAT': -60,
      
      // High impacts
      'GEO_DRIFT': -30,
      'PRIVILEGE_ESCALATION': -35,
      'USER_AGENT_CHANGE': -25,
      'IP_CHANGE': -20,
      
      // Medium impacts
      'REQUEST_CADENCE': -15,
      'ENDPOINT_ACCESS': -20,
      'DEVICE_MISMATCH': -18,
      
      // Low impacts
      'TOKEN_AGE': -10,
      'BOT_DETECTION': -15,
      
      // Recovery impacts
      'SUCCESSFUL_REAUTH': +15,
      'PRIVILEGE_REVOCATION': +5,
    };

    let impact = impactMap[signalType] || -10;

    // Adjust for severity
    if (severity === 'CRITICAL') impact *= 1.5;
    else if (severity === 'LOW') impact *= 0.5;

    return Math.round(impact);
  }

  /**
   * Determine action for signal
   */
  determineActionForSignal(signal) {
    if (signal.isCritical()) {
      return 'SESSION_TERMINATED';
    }

    if (signal.severity === 'HIGH') {
      return 'CHALLENGE_ISSUED';
    }

    if (signal.severity === 'MEDIUM') {
      return 'INCREASED_MONITORING';
    }

    return 'LOGGED_ONLY';
  }

  /**
   * Calculate confidence level (HIGH when >10 signals, MEDIUM when 3-10, LOW when <3)
   */
  calculateConfidenceLevel(dataPointCount) {
    if (dataPointCount >= 10) return 'HIGH';
    if (dataPointCount >= 3) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Check if this is a downgrade transition
   */
  isTierDowngrade(oldTier, newTier) {
    const tierOrder = { 'NORMAL': 0, 'MONITORED': 1, 'CHALLENGED': 2, 'TERMINATED': 3 };
    return tierOrder[newTier] > tierOrder[oldTier];
  }

  /**
   * Check if this is an upgrade transition
   */
  isTierUpgrade(oldTier, newTier) {
    const tierOrder = { 'NORMAL': 0, 'MONITORED': 1, 'CHALLENGED': 2, 'TERMINATED': 3 };
    return tierOrder[newTier] < tierOrder[oldTier];
  }

  /**
   * Get all active trust scores (for monitoring)
   */
  async getActiveTrustScores(filters = {}) {
    try {
      const query = { terminatedAt: { $exists: false } };

      if (filters.tier) query.currentEnforcementTier = filters.tier;
      if (filters.userId) query.userId = filters.userId;
      if (filters.anomalous) query.flaggedAsAnomalous = true;

      return await SessionTrustScore
        .find(query)
        .populate('userId', 'email')
        .populate('sessionId', 'ipAddress userAgent')
        .sort({ currentTrustScore: 1 })
        .limit(filters.limit || 100);
    } catch (error) {
      console.error('Error getting active trust scores:', error);
      throw error;
    }
  }

  /**
   * Terminate session due to security concern
   */
  async terminateSession(sessionId, userId, reason = 'UNRECOVERABLE_COMPROMISE') {
    try {
      const trustScore = await SessionTrustScore.findOne({ sessionId });

      if (trustScore) {
        trustScore.terminatedAt = new Date();
        trustScore.terminationReason = reason;
        trustScore.currentEnforcementTier = 'TERMINATED';
        await trustScore.save();
      }

      // Kill the actual session
      await Session.findByIdAndUpdate(
        sessionId,
        { active: false, terminatedAt: new Date() }
      );

      // Notify user/admin
      console.log(`Session ${sessionId} terminated: ${reason}`);

      return {
        success: true,
        sessionId,
        reason,
      };
    } catch (error) {
      console.error('Error terminating session:', error);
      throw error;
    }
  }

  /**
   * Get trust metrics for a user
   */
  async getUserTrustMetrics(userId) {
    try {
      const activeSessions = await SessionTrustScore.find({
        userId,
        terminatedAt: { $exists: false },
      });

      const avgTrust = activeSessions.length > 0
        ? Math.round(activeSessions.reduce((sum, s) => sum + s.currentTrustScore, 0) / activeSessions.length)
        : 100;

      const challengedCount = activeSessions.filter(s => s.currentEnforcementTier === 'CHALLENGED').length;

      const recentSignals = await SessionBehaviorSignal
        .find({ userId })
        .sort({ detectedAt: -1 })
        .limit(20);

      return {
        activeSessions: activeSessions.length,
        averageTrustScore: avgTrust,
        challengedSessions: challengedCount,
        recentSignals: recentSignals.length,
        anomalousCount: activeSessions.filter(s => s.flaggedAsAnomalous).length,
        lastUpdated: new Date(),
      };
    } catch (error) {
      console.error('Error getting user trust metrics:', error);
      throw error;
    }
  }

  /**
   * Propagate realtime threat intel updates to active sessions immediately
   */
  async propagateThreatIntelUpdate(indicatorPayload = {}) {
    try {
      const { indicatorType, indicatorValue } = indicatorPayload;

      if (!indicatorType || !indicatorValue) {
        return { processed: 0, affectedSessions: 0, errors: [] };
      }

      const sessionQuery = {
        status: 'active',
        expiresAt: { $gt: new Date() }
      };

      if (indicatorType === 'IP' || indicatorType === 'BOTNET_IP') {
        sessionQuery['location.ipAddress'] = indicatorValue;
      } else if (indicatorType === 'CALLBACK_URL' || indicatorType === 'C2_CALLBACK_URL') {
        sessionQuery['activity.lastEndpoint'] = { $regex: indicatorValue, $options: 'i' };
      }

      const sessions = await Session.find(sessionQuery)
        .select('_id userId location activity userAgent')
        .limit(Number(process.env.THREAT_INTEL_MAX_IMMEDIATE_RESCORING || 200));

      let processed = 0;
      const errors = [];

      for (const session of sessions) {
        try {
          await this.performTrustReScoring(session._id, session.userId, {
            endpoint: session.activity?.lastEndpoint || '/api/session-trust/realtime-threat-intel',
            method: 'SYSTEM',
            ipAddress: session.location?.ipAddress,
            userAgent: session.userAgent,
            malwareChecksum: indicatorType === 'CHECKSUM' ? indicatorValue : undefined,
            c2CallbackUrl: (indicatorType === 'CALLBACK_URL' || indicatorType === 'C2_CALLBACK_URL') ? indicatorValue : undefined,
            knownThreats: (indicatorType === 'IP' || indicatorType === 'BOTNET_IP') ? [indicatorValue] : [],
            triggerReason: 'REALTIME_THREAT_INTEL_CALLBACK'
          });

          processed += 1;
        } catch (error) {
          errors.push({ sessionId: session._id, error: error.message });
        }
      }

      return {
        processed,
        affectedSessions: sessions.length,
        errors
      };
    } catch (error) {
      console.error('Error propagating threat intel update:', error);
      throw error;
    }
  }
}

module.exports = new ContinuousSessionTrustService();
