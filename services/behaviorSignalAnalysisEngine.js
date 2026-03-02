/**
 * Behavior Signal Analysis Engine
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Collects, analyzes, and scores behavioral signals in real-time.
 * Detects anomalies and evaluates signal impact on trust.
 */

const SessionBehaviorSignal = require('../models/SessionBehaviorSignal');
const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');
const Session = require('../models/Session');
const User = require('../models/User');
const TrustedDevice = require('../models/TrustedDevice');
const TwoFactorAuth = require('../models/TwoFactorAuth');

const geolib = require('geolib');

class BehaviorSignalAnalysisEngine {
  /**
   * Collect behavioral signals from current request
   */
  async collectSignals(sessionId, userId, requestContext = {}) {
    try {
      const signals = [];

      // Get session and user data
      const session = await Session.findById(sessionId);
      const user = await User.findById(userId);
      const thresholdPolicy = await AdaptiveThresholdPolicy.findOne({ userId });

      if (!session || !user) {
        console.warn(`Session or user not found: ${sessionId}, ${userId}`);
        return signals;
      }

      // Collect endpoint sensitivity signal
      if (requestContext.endpoint) {
        signals.push(
          await this.collectEndpointSensitivitySignal(
            sessionId,
            userId,
            requestContext,
            thresholdPolicy
          )
        );
      }

      // Collect request cadence signal
      signals.push(
        await this.collectRequestCadenceSignal(
          sessionId,
          userId,
          requestContext,
          thresholdPolicy
        )
      );

      // Collect geo/location signal
      if (requestContext.location) {
        signals.push(
          await this.collectGeoContextSignal(
            sessionId,
            userId,
            requestContext,
            thresholdPolicy
          )
        );
      }

      // Collect user agent signal
      if (requestContext.userAgent) {
        signals.push(
          await this.collectUserAgentSignal(
            sessionId,
            userId,
            requestContext,
            session
          )
        );
      }

      // Collect IP change signal
      if (requestContext.ipAddress && session.location?.ipAddress) {
        signals.push(
          await this.collectIPChangeSignal(
            sessionId,
            userId,
            requestContext,
            session
          )
        );
      }

      // Collect privilege escalation signal
      if (requestContext.requiredRole) {
        signals.push(
          await this.collectPrivilegeTransitionSignal(
            sessionId,
            userId,
            requestContext,
            user
          )
        );
      }

      // Collect device trust signal
      if (requestContext.deviceFingerprint) {
        signals.push(
          await this.collectDeviceTrustSignal(
            sessionId,
            userId,
            requestContext
          )
        );
      }

      // Check for known threats
      signals.push(
        await this.collectThreatIndicatorSignal(
          sessionId,
          userId,
          requestContext
        )
      );

      // Filter out null signals
      return signals.filter(s => s !== null);
    } catch (error) {
      console.error('Error collecting behavioral signals:', error);
      return [];
    }
  }

  /**
   * Collect endpoint sensitivity signal
   */
  async collectEndpointSensitivitySignal(sessionId, userId, requestContext, policy) {
    try {
      const { endpoint, method } = requestContext;

      // Define endpoint sensitivities
      const criticalEndpoints = [
        '/api/admin/',
        '/api/users/*/permissions',
        '/api/financial/export',
        '/api/security/',
        '/api/accounts/*/delete',
      ];

      const isCritical = criticalEndpoints.some(e =>
        endpoint.match(e.replace('*', '.*'))
      );

      if (!isCritical && policy?.baselineProfile?.usualEndpoints?.includes(endpoint)) {
        return null; // No signal for normal endpoint access
      }

      return new SessionBehaviorSignal({
        sessionId,
        userId,
        signalType: 'ENDPOINT_ACCESS',
        severity: isCritical ? 'HIGH' : 'MEDIUM',
        trustImpact: isCritical ? -25 : -15,
        confidence: 85,
        details: {
          endpoint,
          method,
          sensitivity: isCritical ? 'CRITICAL' : 'HIGH',
        },
        detectedAt: new Date(),
      });
    } catch (error) {
      console.error('Error collecting endpoint sensitivity signal:', error);
      return null;
    }
  }

  /**
   * Collect request cadence signal
   */
  async collectRequestCadenceSignal(sessionId, userId, requestContext, policy) {
    try {
      const baseline = policy?.baselineProfile?.averageRequestsPerMinute || 5;

      // Count requests in last minute
      const oneMinuteAgo = new Date(Date.now() - 60000);
      
      // This would query from request logs (simplified here)
      const recentRequestCount = requestContext.recentRequestCount || baseline;

      const deviation = Math.abs(recentRequestCount - baseline) / baseline;

      if (deviation > (policy?.componentThresholds?.requestCadence?.deviationThreshold || 0.5)) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'REQUEST_CADENCE',
          severity: deviation > 1.5 ? 'HIGH' : 'MEDIUM',
          trustImpact: Math.round(-15 * Math.min(deviation, 3)),
          confidence: 75,
          details: {
            requestsPerMinute: recentRequestCount,
            previousAverageRequestsPerMinute: baseline,
            deviationPercentage: Math.round(deviation * 100),
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting request cadence signal:', error);
      return null;
    }
  }

  /**
   * Collect geographic context signal (impossible travel)
   */
  async collectGeoContextSignal(sessionId, userId, requestContext, policy) {
    try {
      const currentLocation = requestContext.location;
      const previousLocationData = requestContext.previousLocation;

      if (!previousLocationData) return null;

      // Calculate distance
      const distance = geolib.getDistance(
        { latitude: previousLocationData.latitude, longitude: previousLocationData.longitude },
        { latitude: currentLocation.latitude, longitude: currentLocation.longitude }
      );

      const distanceKm = distance / 1000;
      const timeDifferenceSeconds = requestContext.timeSinceLastRequest || 0;
      const maxPossibleKmh = 900; // Commercial flight max
      const maxPossibleDistance = (maxPossibleKmh * timeDifferenceSeconds) / 3600;

      if (distanceKm > maxPossibleDistance) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'GEO_DRIFT',
          severity: 'CRITICAL',
          trustImpact: -50,
          confidence: 90,
          details: {
            previousLocation: previousLocationData,
            currentLocation,
            distanceKm: Math.round(distanceKm),
            timeDifferenceSeconds,
            maxPossibleDistanceKm: Math.round(maxPossibleDistance),
          },
          detectedAt: new Date(),
        });
      }

      // Check for significant distance even if not impossible
      if (distanceKm > (policy?.componentThresholds?.geoContext?.newCountryPenalty ? 5000 : 1000)) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'GEO_DRIFT',
          severity: 'MEDIUM',
          trustImpact: -25,
          confidence: 80,
          details: {
            previousLocation: previousLocationData,
            currentLocation,
            distanceKm: Math.round(distanceKm),
            timeDifferenceSeconds,
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting geo context signal:', error);
      return null;
    }
  }

  /**
   * Collect user agent consistency signal
   */
  async collectUserAgentSignal(sessionId, userId, requestContext, session) {
    try {
      const currentUA = requestContext.userAgent;
      const previousUA = session?.userAgent;

      if (!previousUA || currentUA === previousUA) {
        return null;
      }

      // Parse browser/OS info (simplified)
      const browserMatch = (ua) => {
        if (ua.includes('Chrome')) return 'Chrome';
        if (ua.includes('Firefox')) return 'Firefox';
        if (ua.includes('Safari')) return 'Safari';
        return 'Unknown';
      };

      const previousBrowser = browserMatch(previousUA);
      const currentBrowser = browserMatch(currentUA);

      if (previousBrowser !== currentBrowser) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'USER_AGENT_CHANGE',
          severity: 'MEDIUM',
          trustImpact: -20,
          confidence: 80,
          details: {
            previousUserAgent: previousUA,
            currentUserAgent: currentUA,
            previousBrowser,
            currentBrowser,
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting user agent signal:', error);
      return null;
    }
  }

  /**
   * Collect IP address change signal
   */
  async collectIPChangeSignal(sessionId, userId, requestContext, session) {
    try {
      const currentIP = requestContext.ipAddress;
      const previousIP = session?.ipAddress;

      if (previousIP === currentIP) return null;

      return new SessionBehaviorSignal({
        sessionId,
        userId,
        signalType: 'IP_CHANGE',
        severity: 'MEDIUM',
        trustImpact: -18,
        confidence: 90,
        details: {
          previousIP,
          currentIP,
          geoLocation: requestContext.location?.city || 'Unknown',
        },
        detectedAt: new Date(),
      });
    } catch (error) {
      console.error('Error collecting IP change signal:', error);
      return null;
    }
  }

  /**
   * Collect privilege escalation signal
   */
  async collectPrivilegeTransitionSignal(sessionId, userId, requestContext, user) {
    try {
      const requiredRole = requestContext.requiredRole;
      const userRole = user?.role || 'USER';

      // Check if this is unusual privilege access
      const sensitiveRoles = ['ADMIN', 'SECURITY_ADMIN', 'ANALYST'];

      if (sensitiveRoles.includes(requiredRole) && userRole !== 'ADMIN') {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'PRIVILEGE_ESCALATION',
          severity: 'HIGH',
          trustImpact: -35,
          confidence: 90,
          details: {
            previousRole: userRole,
            currentRole: requiredRole,
            escalationLevel: sensitiveRoles.indexOf(requiredRole) + 1,
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting privilege transition signal:', error);
      return null;
    }
  }

  /**
   * Collect device trust signal
   */
  async collectDeviceTrustSignal(sessionId, userId, requestContext) {
    try {
      const deviceFingerprint = requestContext.deviceFingerprint;

      if (!deviceFingerprint) return null;

      // Check if device is trusted
      const trustedDevice = await TrustedDevice.findOne({
        userId,
        fingerprint: deviceFingerprint,
        active: true,
      });

      if (!trustedDevice) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'DEVICE_MISMATCH',
          severity: 'MEDIUM',
          trustImpact: -18,
          confidence: 85,
          details: {
            deviceFingerprint,
            isTrusted: false,
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting device trust signal:', error);
      return null;
    }
  }

  /**
   * Collect threat indicator signal
   */
  async collectThreatIndicatorSignal(sessionId, userId, requestContext) {
    try {
      const ipAddress = requestContext.ipAddress;
      const threatIntel = requestContext.threatIntel;
      const intelThreshold = Number(process.env.THREAT_INTEL_SIGNAL_THRESHOLD || 60);
      
      // Check IP against blacklist (simplified)
      const knownThreats = requestContext.knownThreats || [];

      if (threatIntel && Number(threatIntel.overallRiskScore || 0) >= intelThreshold) {
        const topIndicator = threatIntel.indicators?.[0] || 'EXTERNAL_THREAT_INTEL';
        const confidence = Math.min(100, Math.round(Number(threatIntel.confidence || 0.8) * 100));

        let severity = 'MEDIUM';
        if (threatIntel.overallRiskScore >= 85) severity = 'CRITICAL';
        else if (threatIntel.overallRiskScore >= 70) severity = 'HIGH';

        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'KNOWN_THREAT',
          severity,
          trustImpact: severity === 'CRITICAL' ? -60 : -45,
          confidence,
          details: {
            threatType: topIndicator,
            threatSource: 'THREAT_INTEL_INTEGRATION',
            threatConfidence: confidence,
            context: {
              overallRiskScore: threatIntel.overallRiskScore,
              indicators: threatIntel.indicators,
              providers: threatIntel.byIndicator?.map(item => item.indicatorType)
            }
          },
          detectedAt: new Date(),
        });
      }

      if (knownThreats.includes(ipAddress)) {
        return new SessionBehaviorSignal({
          sessionId,
          userId,
          signalType: 'KNOWN_THREAT',
          severity: 'CRITICAL',
          trustImpact: -60,
          confidence: 95,
          details: {
            threatType: 'IP_BLACKLIST',
            threatSource: 'GLOBAL_THREAT_DB',
            threatConfidence: 95,
          },
          detectedAt: new Date(),
        });
      }

      return null;
    } catch (error) {
      console.error('Error collecting threat indicator signal:', error);
      return null;
    }
  }

  /**
   * Analyze signals for anomalies and patterns
   */
  async analyzeSignals(signals, userId) {
    try {
      const analysis = {
        signalCount: signals.length,
        anomalies: [],
        riskFactors: [],
        totalTrustImpact: 0,
        criticalSignals: [],
      };

      if (!signals || signals.length === 0) {
        return analysis;
      }

      // Sum trust impacts
      analysis.totalTrustImpact = signals.reduce((sum, s) => sum + (s.trustImpact || 0), 0);

      // Identify critical signals
      analysis.criticalSignals = signals.filter(s => s.severity === 'CRITICAL');

      // Detect anomalous patterns
      const highSeverityCount = signals.filter(s => s.severity === 'HIGH' || s.severity === 'CRITICAL').length;

      if (signals.length > 5) {
        analysis.anomalies.push('MULTIPLE_SIGNALS_DETECTED');
      }

      if (highSeverityCount > 2) {
        analysis.anomalies.push('MULTIPLE_HIGH_SEVERITY_SIGNALS');
      }

      // Check for impossible travel
      const geoSignals = signals.filter(s => s.signalType === 'GEO_DRIFT' && s.details?.maxPossibleDistanceKm);
      if (geoSignals.length > 0) {
        analysis.anomalies.push('IMPOSSIBLE_TRAVEL_DETECTED');
        analysis.riskFactors.push('GEOGRAPHIC_ANOMALY');
      }

      // Check for coordinated attack patterns
      if (signals.some(s => s.signalType === 'KNOWN_THREAT') &&
          signals.some(s => s.signalType === 'USER_AGENT_CHANGE') &&
          signals.some(s => s.signalType === 'PRIVILEGE_ESCALATION')) {
        analysis.anomalies.push('POTENTIAL_COORDINATED_ATTACK');
        analysis.riskFactors.push('ATTACK_PATTERN_DETECTED');
      }

      return analysis;
    } catch (error) {
      console.error('Error analyzing signals:', error);
      return {
        signalCount: 0,
        anomalies: [],
        riskFactors: [],
        totalTrustImpact: 0,
        criticalSignals: [],
      };
    }
  }

  /**
   * Calculate anomaly score for a signal
   */
  async scoreAnomalyProbability(signal, userId) {
    try {
      // Default scoring based on signal type
      const baseScores = {
        'IMPOSSIBLE_TRAVEL': 95,
        'KNOWN_THREAT': 90,
        'PRIVILEGE_ESCALATION': 75,
        'GEO_DRIFT': 70,
        'USER_AGENT_CHANGE': 50,
        'IP_CHANGE': 45,
        'ENDPOINT_ACCESS': 40,
        'REQUEST_CADENCE': 35,
        'DEVICE_MISMATCH': 55,
      };

      let score = baseScores[signal.signalType] || 50;

      // Adjust based on confidence
      score *= (signal.confidence / 100);

      // Adjust based on severity
      const severityMultiplier = {
        'CRITICAL': 1.3,
        'HIGH': 1.1,
        'MEDIUM': 0.9,
        'LOW': 0.7,
      };

      score *= (severityMultiplier[signal.severity] || 1.0);

      return Math.min(100, Math.round(score));
    } catch (error) {
      console.error('Error scoring anomaly probability:', error);
      return 50;
    }
  }

  /**
   * Get signal history for user
   */
  async getSignalHistory(userId, hoursBack = 24, limit = 100) {
    try {
      const since = new Date(Date.now() - (hoursBack * 60 * 60 * 1000));

      return await SessionBehaviorSignal
        .find({
          userId,
          detectedAt: { $gte: since },
        })
        .sort({ detectedAt: -1 })
        .limit(limit);
    } catch (error) {
      console.error('Error getting signal history:', error);
      return [];
    }
  }
}

module.exports = new BehaviorSignalAnalysisEngine();
