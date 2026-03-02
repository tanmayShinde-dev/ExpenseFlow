/**
 * Trust Scoring Engine
 * Issue #852: Continuous Session Trust Re-Scoring
 * 
 * Calculates component trust scores from behavior signals.
 * Applies adaptive thresholds to reduce false positives.
 */

const AdaptiveThresholdPolicy = require('../models/AdaptiveThresholdPolicy');

class TrustScoringEngine {
  /**
   * Calculate component trust scores from signals
   */
  async calculateComponentScores(signals, analysis, thresholdPolicy) {
    try {
      const components = {
        endpointSensitivityScore: 100,
        requestCadenceScore: 100,
        geoContextScore: 100,
        userAgentConsistencyScore: 100,
        tokenAgeScore: 100,
        privilegeTransitionScore: 100,
        reAuthScore: 100,
        threatIndicatorScore: 100,
      };

      if (!signals || signals.length === 0) {
        return components;
      }

      // Get relaxation factors from policy
      const getRelaxation = (component) => {
        return thresholdPolicy?.getRelaxationFactor(component) || 1.0;
      };

      // Process endpoint access signals
      const endpointSignals = signals.filter(s => s.signalType === 'ENDPOINT_ACCESS');
      if (endpointSignals.length > 0) {
        components.endpointSensitivityScore = this.calculateEndpointScore(
          endpointSignals,
          getRelaxation('endpointSensitivity')
        );
      }

      // Process request cadence signals
      const cadenceSignals = signals.filter(s => s.signalType === 'REQUEST_CADENCE');
      if (cadenceSignals.length > 0) {
        components.requestCadenceScore = this.calculateCadenceScore(
          cadenceSignals,
          getRelaxation('requestCadence')
        );
      }

      // Process geo context signals
      const geoSignals = signals.filter(s => s.signalType === 'GEO_DRIFT');
      if (geoSignals.length > 0) {
        components.geoContextScore = this.calculateGeoScore(
          geoSignals,
          getRelaxation('geoContext')
        );
      }

      // Process user agent signals
      const uaSignals = signals.filter(s => s.signalType === 'USER_AGENT_CHANGE');
      if (uaSignals.length > 0) {
        components.userAgentConsistencyScore = this.calculateUAScore(
          uaSignals,
          getRelaxation('userAgentConsistency')
        );
      }

      // Process IP change signals
      const ipSignals = signals.filter(s => s.signalType === 'IP_CHANGE');
      if (ipSignals.length > 0) {
        components.geoContextScore = Math.min(
          components.geoContextScore,
          this.calculateIPScore(ipSignals, getRelaxation('geoContext'))
        );
      }

      // Process privilege signals
      const privSignals = signals.filter(s => s.signalType === 'PRIVILEGE_ESCALATION' || s.signalType === 'PRIVILEGE_REVOCATION');
      if (privSignals.length > 0) {
        components.privilegeTransitionScore = this.calculatePrivilegeScore(
          privSignals,
          getRelaxation('privilegeTransition')
        );
      }

      // Process reauth signals
      const reauthSignals = signals.filter(s => 
        s.signalType === 'FAILED_REAUTH' || s.signalType === 'SUCCESSFUL_REAUTH'
      );
      if (reauthSignals.length > 0) {
        components.reAuthScore = this.calculateReAuthScore(
          reauthSignals,
          getRelaxation('reAuth')
        );
      }

      // Process threat indicators
      const threatSignals = signals.filter(s => s.signalType === 'KNOWN_THREAT');
      if (threatSignals.length > 0) {
        components.threatIndicatorScore = this.calculateThreatScore(
          threatSignals,
          getRelaxation('threatIndicator')
        );
      }

      // Process device trust signals
      const deviceSignals = signals.filter(s => s.signalType === 'DEVICE_MISMATCH');
      if (deviceSignals.length > 0) {
        components.userAgentConsistencyScore = Math.min(
          components.userAgentConsistencyScore,
          this.calculateDeviceScore(deviceSignals, getRelaxation('userAgentConsistency'))
        );
      }

      // Token age is typically time-based, not signal-based
      components.tokenAgeScore = this.calculateTokenAgeScore(
        signals,
        getRelaxation('tokenAge')
      );

      return components;
    } catch (error) {
      console.error('Error calculating component scores:', error);
      // Return all 100s on error
      return {
        endpointSensitivityScore: 100,
        requestCadenceScore: 100,
        geoContextScore: 100,
        userAgentConsistencyScore: 100,
        tokenAgeScore: 100,
        privilegeTransitionScore: 100,
        reAuthScore: 100,
        threatIndicatorScore: 100,
      };
    }
  }

  /**
   * Calculate endpoint sensitivity score
   */
  calculateEndpointScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      if (signal.details?.sensitivity === 'CRITICAL') {
        penalty += 25;
      } else if (signal.details?.sensitivity === 'HIGH') {
        penalty += 15;
      }

      // Multiple critical accesses compounds penalty
      if (signals.filter(s => s.details?.sensitivity === 'CRITICAL').length > 2) {
        penalty += 10;
      }
    }

    // Apply relaxation
    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate request cadence score
   */
  calculateCadenceScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      const deviation = signal.details?.deviationPercentage || 0;

      // Scale penalty with deviation
      // 50% deviation = -10 points
      // 100% deviation = -25 points
      // >150% deviation = -40 points
      penalty += Math.min(40, (deviation / 5));
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate geographic context score
   */
  calculateGeoScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      const severity = signal.severity;

      if (severity === 'CRITICAL') {
        // Impossible travel
        penalty = 50;
        break;
      } else if (severity === 'HIGH') {
        penalty = Math.max(penalty, 35);
      } else if (severity === 'MEDIUM') {
        penalty = Math.max(penalty, 20);
      }
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate user agent consistency score
   */
  calculateUAScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      const { previousBrowser, currentBrowser } = signal.details;

      // Major browser change
      if (previousBrowser !== currentBrowser) {
        penalty += 20;
      }
    }

    // Multiple UA changes in short time
    if (signals.length > 2) {
      penalty += 15;
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate IP change score
   */
  calculateIPScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    // Single IP change is moderate penalty
    if (signals.length === 1) {
      penalty = 15;
    }

    // Multiple IP changes are suspicious
    if (signals.length > 2) {
      penalty = 35;
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate privilege transition score
   */
  calculatePrivilegeScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      if (signal.signalType === 'PRIVILEGE_ESCALATION') {
        const level = signal.details?.escalationLevel || 1;

        // Each escalation level costs points
        penalty += (10 * level);

        // Escalation to ADMIN is expensive
        if (signal.details?.currentRole === 'ADMIN') {
          penalty += 25;
        }
      } else if (signal.signalType === 'PRIVILEGE_REVOCATION') {
        // Privilege revocation actually helps (restore trust)
        penalty = Math.max(0, penalty - 5);
      }
    }

    // Multiple privilege escalations
    const escalations = signals.filter(s => s.signalType === 'PRIVILEGE_ESCALATION');
    if (escalations.length > 2) {
      penalty += 20;
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate re-authentication score
   */
  calculateReAuthScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;
    let bonus = 0;

    for (const signal of signals) {
      if (signal.signalType === 'FAILED_REAUTH') {
        penalty += 15;
      } else if (signal.signalType === 'SUCCESSFUL_REAUTH') {
        bonus += 10;
      }
    }

    // Multiple failed reauth attempts
    const failedCount = signals.filter(s => s.signalType === 'FAILED_REAUTH').length;
    if (failedCount > 3) {
      penalty += 25;
    } else if (failedCount > 0) {
      penalty += (5 * failedCount);
    }

    // Apply bonus for successful reauth
    penalty = Math.max(0, penalty - bonus);
    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate threat indicator score
   */
  calculateThreatScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    for (const signal of signals) {
      const threatType = signal.details?.threatType || 'UNKNOWN';
      const intelRiskScore = Number(signal.details?.context?.overallRiskScore || 0);

      if (intelRiskScore > 0) {
        penalty = Math.max(penalty, intelRiskScore);
      }

      if (threatType === 'IP_BLACKLIST') {
        penalty = 50;
      } else if (threatType === 'MALWARE') {
        penalty = 60;
      } else if (threatType === 'BOTNET') {
        penalty = 55;
      } else if (threatType === 'KNOWN_BOTNET_IP') {
        penalty = 65;
      } else if (threatType === 'MALWARE_CHECKSUM') {
        penalty = 70;
      } else if (threatType === 'C2_CALLBACK') {
        penalty = 75;
      } else if (threatType === 'KNOWN_ATTACKER') {
        penalty = 70;
      } else {
        penalty = 40;
      }

      // Any critical threat is high penalty
      if (signal.severity === 'CRITICAL') {
        penalty = Math.max(penalty, 60);
      }

      // Don't reduce for multiple threats, take maximum
      break; // Only apply highest threat penalty
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate device trust score
   */
  calculateDeviceScore(signals, relaxationFactor = 1.0) {
    if (signals.length === 0) return 100;

    let penalty = 0;

    // Each untrusted device
    penalty = 18 * signals.length;

    // Multiple devices is more suspicious
    if (signals.length > 2) {
      penalty += 15;
    }

    penalty *= (1 / relaxationFactor);

    return Math.max(0, 100 - penalty);
  }

  /**
   * Calculate token age score
   */
  calculateTokenAgeScore(signals, relaxationFactor = 1.0) {
    try {
      // Find token age from signals or use default
      const tokenAgeSignals = signals.filter(s => s.signalType === 'TOKEN_AGE');

      let age = 0;
      if (tokenAgeSignals.length > 0) {
        age = tokenAgeSignals[0].details?.tokenAgeSeconds || 0;
      }

      // Convert seconds to hours
      const hours = age / 3600;

      // Scoring: 0 hours = 100, 12 hours = 80, 24 hours = 50, >24 = 30
      let score = 100;

      if (hours < 0.5) {
        score = 100; // Fresh session
      } else if (hours < 6) {
        score = 95; // Still fresh
      } else if (hours < 12) {
        score = 85; // Getting old
      } else if (hours < 18) {
        score = 70; // Aging
      } else if (hours < 24) {
        score = 50; // Very old
      } else {
        score = 30; // Extremely old
      }

      score *= (1 / relaxationFactor);

      return Math.max(30, Math.min(100, score));
    } catch (error) {
      console.error('Error calculating token age score:', error);
      return 100;
    }
  }

  /**
   * Calculate user baseline deviation
   */
  calculateBaselineDeviation(signals, baselineProfile) {
    try {
      if (!baselineProfile || signals.length === 0) return 100;

      let deviationScore = 100;

      // Count anomalous signals
      const anomalousSignals = signals.filter(s => s.anomalyScore > 50);

      // Deviation increases with anomalous signals
      deviationScore += (anomalousSignals.length * 15);

      return Math.min(200, deviationScore);
    } catch (error) {
      console.error('Error calculating baseline deviation:', error);
      return 100;
    }
  }
}

module.exports = new TrustScoringEngine();
