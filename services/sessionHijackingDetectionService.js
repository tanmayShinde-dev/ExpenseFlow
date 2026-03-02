const Session = require('../models/Session');
const SessionHijackingEvent = require('../models/SessionHijackingEvent');
const SessionBehaviorProfile = require('../models/SessionBehaviorProfile');
const DeviceFingerprint = require('../models/DeviceFingerprint');
const SecurityEvent = require('../models/SecurityEvent');
const geolib = require('geolib');
const axios = require('axios');

/**
 * Session Hijacking Detection Service
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Comprehensive detection system for session hijacking including:
 * - Behavioral divergence detection
 * - Impossible location detection
 * - Device fingerprint swap detection
 * - Privilege escalation detection
 * - Request pattern anomalies
 */

class SessionHijackingDetectionService {
  /**
   * Configuration
   */
  static config = {
    // Risk score thresholds
    riskThresholds: {
      low: 25,
      medium: 50,
      high: 75,
      critical: 90
    },
    // Impossible travel detection
    maxTravelSpeed: 900, // km/h (commercial flight speed)
    impossibleTravelThreshold: 60, // minutes
    // Behavioral divergence
    behavioralAnomalyThreshold: 0.6,
    // Device fingerprint
    fingerprintMatchThreshold: 0.8,
    // Simultaneous session threshold
    simultaneousSessionWindow: 300000, // 5 minutes
    minDistanceForSimultaneousCheck: 100, // km
    // Privilege escalation
    privilegeEscalationWindow: 3600000 // 1 hour
  };

  /**
   * Main detection method - analyzes request for hijacking indicators
   * @param {Object} req - Express request object
   * @param {Object} session - Current session object
   * @param {Object} user - User object
   * @returns {Promise<Object>} Detection result
   */
  static async detectHijacking(req, session, user) {
    try {
      const indicators = [];
      let totalRiskScore = 0;
      let detectionMethod = null;

      // 1. Behavioral Divergence Detection
      const behavioralCheck = await this.checkBehavioralDivergence(req, session);
      if (behavioralCheck.isDivergent) {
        indicators.push({
          type: 'BEHAVIORAL_DIVERGENCE',
          severity: behavioralCheck.severity,
          riskScore: behavioralCheck.riskScore,
          details: behavioralCheck.details,
          timestamp: new Date()
        });
        totalRiskScore += behavioralCheck.riskScore;
        detectionMethod = 'BEHAVIORAL_DIVERGENCE';
      }

      // 2. Impossible Location / Simultaneous Sessions Detection
      const locationCheck = await this.checkImpossibleLocation(req, session, user);
      if (locationCheck.isImpossible) {
        indicators.push({
          type: locationCheck.type,
          severity: locationCheck.severity,
          riskScore: locationCheck.riskScore,
          details: locationCheck.details,
          timestamp: new Date()
        });
        totalRiskScore += locationCheck.riskScore;
        if (!detectionMethod) detectionMethod = locationCheck.type;
      }

      // 3. Device Fingerprint Swap Detection
      const fingerprintCheck = await this.checkDeviceFingerprintSwap(req, session, user);
      if (fingerprintCheck.isSwap) {
        indicators.push({
          type: 'DEVICE_FINGERPRINT_SWAP',
          severity: fingerprintCheck.severity,
          riskScore: fingerprintCheck.riskScore,
          details: fingerprintCheck.details,
          timestamp: new Date()
        });
        totalRiskScore += fingerprintCheck.riskScore;
        if (!detectionMethod) detectionMethod = 'DEVICE_FINGERPRINT_SWAP';
      }

      // 4. Privilege Escalation Detection
      const privilegeCheck = await this.checkPrivilegeEscalation(req, session, user);
      if (privilegeCheck.isEscalation) {
        indicators.push({
          type: 'PRIVILEGE_ESCALATION',
          severity: privilegeCheck.severity,
          riskScore: privilegeCheck.riskScore,
          details: privilegeCheck.details,
          timestamp: new Date()
        });
        totalRiskScore += privilegeCheck.riskScore;
        if (!detectionMethod) detectionMethod = 'PRIVILEGE_ESCALATION';
      }

      // 5. Request Pattern Anomaly Detection
      const patternCheck = await this.checkRequestPatternAnomaly(req, session);
      if (patternCheck.isAnomaly) {
        indicators.push({
          type: 'REQUEST_PATTERN_ANOMALY',
          severity: patternCheck.severity,
          riskScore: patternCheck.riskScore,
          details: patternCheck.details,
          timestamp: new Date()
        });
        totalRiskScore += patternCheck.riskScore;
        if (!detectionMethod) detectionMethod = 'REQUEST_PATTERN_ANOMALY';
      }

      // Normalize risk score to 0-100
      totalRiskScore = Math.min(totalRiskScore, 100);

      // Determine if hijacking is detected
      const isHijackingDetected = totalRiskScore >= this.config.riskThresholds.high;

      // Calculate confidence level
      const confidenceLevel = this.calculateConfidence(indicators.length, totalRiskScore);

      return {
        hijackingDetected: isHijackingDetected,
        riskScore: totalRiskScore,
        confidenceLevel,
        detectionMethod: indicators.length > 1 ? 'COMBINED_SIGNALS' : detectionMethod,
        indicators,
        recommendation: this.getRecommendation(totalRiskScore),
        timestamp: new Date()
      };
    } catch (error) {
      console.error('[SessionHijackingDetection] Detection error:', error);
      throw error;
    }
  }

  /**
   * Check for behavioral divergence
   */
  static async checkBehavioralDivergence(req, session) {
    try {
      // Get or create behavior profile
      const profile = await SessionBehaviorProfile.getOrCreate(session._id, session.userId);

      // Record current request
      await profile.recordRequest(req);

      // Detect anomaly (only if baseline is established)
      const anomalyResult = profile.detectAnomaly(req);

      if (anomalyResult.isAnomaly) {
        const riskScore = anomalyResult.anomalyScore * 100;
        const severity = this.getSeverityFromScore(riskScore);

        return {
          isDivergent: true,
          severity,
          riskScore,
          details: {
            anomalyScore: anomalyResult.anomalyScore,
            anomalies: anomalyResult.anomalies,
            baselineEstablished: anomalyResult.baselineEstablished,
            totalRequests: profile.requestPatterns.totalRequests,
            activityLevel: profile.activityProfile.level
          }
        };
      }

      return { isDivergent: false };
    } catch (error) {
      console.error('[SessionHijackingDetection] Behavioral check error:', error);
      return { isDivergent: false, error: error.message };
    }
  }

  /**
   * Check for impossible location / simultaneous sessions
   */
  static async checkImpossibleLocation(req, session, user) {
    try {
      const currentIP = req.ip || req.connection?.remoteAddress;
      const currentLocation = await this.getLocationFromIP(currentIP);

      if (!currentLocation || !session.location) {
        return { isImpossible: false, reason: 'Location data unavailable' };
      }

      // Check for simultaneous sessions from impossible locations
      const recentSessions = await Session.find({
        userId: user._id,
        status: 'active',
        _id: { $ne: session._id },
        'activity.lastAccessAt': {
          $gte: new Date(Date.now() - this.config.simultaneousSessionWindow)
        }
      });

      for (const otherSession of recentSessions) {
        if (!otherSession.location?.coordinates) continue;

        const distance = geolib.getDistance(
          {
            latitude: currentLocation.lat,
            longitude: currentLocation.lon
          },
          {
            latitude: otherSession.location.coordinates.latitude,
            longitude: otherSession.location.coordinates.longitude
          }
        ) / 1000; // Convert to km

        const timeDiff = Math.abs(
          new Date() - new Date(otherSession.activity.lastAccessAt)
        );

        // Check if distance is significant and within simultaneous window
        if (distance > this.config.minDistanceForSimultaneousCheck && 
            timeDiff < this.config.simultaneousSessionWindow) {
          const requiredSpeed = (distance / (timeDiff / 3600000)); // km/h

          if (requiredSpeed > this.config.maxTravelSpeed) {
            return {
              isImpossible: true,
              type: 'IMPOSSIBLE_LOCATION',
              severity: 'critical',
              riskScore: 90,
              details: {
                distance,
                timeDiff,
                requiredSpeed,
                currentLocation,
                previousLocation: otherSession.location,
                simultaneousSessions: true
              }
            };
          }
        }
      }

      // Check impossible travel within same session
      const lastAccessTime = new Date(session.activity.lastAccessAt);
      const timeSinceLastAccess = Date.now() - lastAccessTime;

      if (session.location.coordinates && 
          timeSinceLastAccess < this.config.impossibleTravelThreshold * 60000) {
        const distance = geolib.getDistance(
          {
            latitude: currentLocation.lat,
            longitude: currentLocation.lon
          },
          {
            latitude: session.location.coordinates.latitude,
            longitude: session.location.coordinates.longitude
          }
        ) / 1000;

        const requiredSpeed = (distance / (timeSinceLastAccess / 3600000));

        if (requiredSpeed > this.config.maxTravelSpeed && distance > 50) {
          return {
            isImpossible: true,
            type: 'IMPOSSIBLE_LOCATION',
            severity: 'critical',
            riskScore: 85,
            details: {
              distance,
              timeSinceLastAccess,
              requiredSpeed,
              currentLocation,
              previousLocation: session.location
            }
          };
        }
      }

      return { isImpossible: false };
    } catch (error) {
      console.error('[SessionHijackingDetection] Location check error:', error);
      return { isImpossible: false, error: error.message };
    }
  }

  /**
   * Check for device fingerprint swap
   */
  static async checkDeviceFingerprintSwap(req, session, user) {
    try {
      const currentFingerprint = req.headers['x-device-fingerprint'];
      if (!currentFingerprint) {
        return { isSwap: false, reason: 'No fingerprint provided' };
      }

      // Get stored device fingerprint
      const storedDevice = await DeviceFingerprint.findOne({
        user: user._id,
        fingerprint: currentFingerprint
      });

      // Check if this is a known device
      if (!storedDevice) {
        // New device - check if there was a recent device for this session
        const recentDevices = await DeviceFingerprint.find({
          user: user._id,
          lastSeen: {
            $gte: new Date(Date.now() - 600000) // Last 10 minutes
          }
        }).sort({ lastSeen: -1 });

        if (recentDevices.length > 0) {
          return {
            isSwap: true,
            severity: 'high',
            riskScore: 75,
            details: {
              reason: 'Device fingerprint changed within minutes',
              previousDevice: recentDevices[0].fingerprint,
              currentDevice: currentFingerprint,
              timeSinceLastDevice: Date.now() - recentDevices[0].lastSeen
            }
          };
        }

        // New device but no recent activity - lower risk
        return {
          isSwap: false,
          reason: 'New device, first use',
          isNewDevice: true
        };
      }

      // Check for suspicious rapid device swaps
      const timeSinceLastSeen = Date.now() - storedDevice.lastSeen;
      if (timeSinceLastSeen < 180000) { // 3 minutes
        const otherRecentDevices = await DeviceFingerprint.find({
          user: user._id,
          fingerprint: { $ne: currentFingerprint },
          lastSeen: {
            $gte: new Date(Date.now() - 180000)
          }
        });

        if (otherRecentDevices.length > 0) {
          return {
            isSwap: true,
            severity: 'high',
            riskScore: 70,
            details: {
              reason: 'Rapid switching between devices',
              devices: [currentFingerprint, ...otherRecentDevices.map(d => d.fingerprint)],
              switchingPattern: 'suspicious'
            }
          };
        }
      }

      return { isSwap: false };
    } catch (error) {
      console.error('[SessionHijackingDetection] Fingerprint check error:', error);
      return { isSwap: false, error: error.message };
    }
  }

  /**
   * Check for privilege escalation
   */
  static async checkPrivilegeEscalation(req, session, user) {
    try {
      const endpoint = req.originalUrl || req.url;
      const method = req.method;

      // Define privileged endpoints
      const privilegedEndpoints = [
        /\/api\/admin\//,
        /\/api\/users\/.*\/promote/,
        /\/api\/roles\//,
        /\/api\/permissions\//,
        /\/api\/settings\/security/,
        /\/api\/audit\//,
        /\/api\/backups\//
      ];

      const isPrivilegedEndpoint = privilegedEndpoints.some(pattern => 
        pattern.test(endpoint)
      );

      if (!isPrivilegedEndpoint) {
        return { isEscalation: false };
      }

      // Check if this is during an "impossible" activity period
      const profile = await SessionBehaviorProfile.findOne({ sessionId: session._id });
      if (profile) {
        const currentHour = new Date().getHours();
        const hourlyAvg = profile.activityProfile.hourlyActivity.reduce((a, b) => a + b, 0) / 24;
        const currentHourActivity = profile.activityProfile.hourlyActivity[currentHour];

        // If accessing privileged endpoint during unusual hours
        if (currentHourActivity < hourlyAvg * 0.2 && profile.requestPatterns.totalRequests > 50) {
          await profile.recordPrivilegeEscalation(
            `${method} ${endpoint}`,
            endpoint,
            'ELEVATED'
          );

          return {
            isEscalation: true,
            severity: 'high',
            riskScore: 80,
            details: {
              endpoint,
              method,
              reason: 'Privileged access during unusual activity period',
              currentHour,
              normalActivityLevel: hourlyAvg,
              currentActivityLevel: currentHourActivity
            }
          };
        }

        // Check for rapid privilege escalation attempts
        if (profile.privilegeUsage.escalationAttempts > 0) {
          const timeSinceLastAttempt = Date.now() - profile.privilegeUsage.lastEscalationAttempt;
          
          if (timeSinceLastAttempt < 60000) { // Within 1 minute
            return {
              isEscalation: true,
              severity: 'critical',
              riskScore: 90,
              details: {
                endpoint,
                method,
                reason: 'Rapid privilege escalation attempts',
                attempts: profile.privilegeUsage.escalationAttempts + 1,
                timeSinceLastAttempt
              }
            };
          }
        }
      }

      return { isEscalation: false };
    } catch (error) {
      console.error('[SessionHijackingDetection] Privilege check error:', error);
      return { isEscalation: false, error: error.message };
    }
  }

  /**
   * Check for request pattern anomalies
   */
  static async checkRequestPatternAnomaly(req, session) {
    try {
      const profile = await SessionBehaviorProfile.findOne({ sessionId: session._id });
      
      if (!profile || !profile.baseline.established) {
        return { isAnomaly: false, reason: 'Baseline not established' };
      }

      const endpoint = req.originalUrl || req.url;
      const method = req.method;

      // Check for unusual method on endpoint
      const endpointPattern = endpoint.split('?')[0];
      const methodCount = profile.requestPatterns.methodDistribution[method] || 0;
      const totalRequests = profile.requestPatterns.totalRequests;
      const methodFrequency = methodCount / totalRequests;

      // Alert on unusual HTTP method usage
      if (methodFrequency < 0.05 && totalRequests > 100) {
        return {
          isAnomaly: true,
          severity: 'medium',
          riskScore: 40,
          details: {
            reason: 'Unusual HTTP method usage',
            method,
            endpoint: endpointPattern,
            methodFrequency,
            totalRequests
          }
        };
      }

      // Check for rapid-fire requests (potential automation/bot)
      if (profile.requestPatterns.recentRequestTimes.length >= 5) {
        const lastFive = profile.requestPatterns.recentRequestTimes.slice(-5);
        const avgInterval = (lastFive[4] - lastFive[0]) / 4;

        // If requests are coming faster than 500ms on average
        if (avgInterval < 500 && profile.requestPatterns.avgCadence > 2000) {
          return {
            isAnomaly: true,
            severity: 'high',
            riskScore: 65,
            details: {
              reason: 'Rapid-fire request pattern detected',
              currentCadence: avgInterval,
              normalCadence: profile.requestPatterns.avgCadence,
              possibleAutomation: true
            }
          };
        }
      }

      return { isAnomaly: false };
    } catch (error) {
      console.error('[SessionHijackingDetection] Pattern check error:', error);
      return { isAnomaly: false, error: error.message };
    }
  }

  /**
   * Get location from IP address
   */
  static async getLocationFromIP(ipAddress) {
    try {
      // Skip for localhost/private IPs
      if (ipAddress === '127.0.0.1' || 
          ipAddress === '::1' || 
          ipAddress?.startsWith('192.168.') ||
          ipAddress?.startsWith('10.')) {
        return null;
      }

      // Use ip-api.com for geolocation (free tier)
      const response = await axios.get(`http://ip-api.com/json/${ipAddress}`, {
        timeout: 3000
      });

      if (response.data.status === 'success') {
        return {
          country: response.data.country,
          city: response.data.city,
          lat: response.data.lat,
          lon: response.data.lon,
          timezone: response.data.timezone
        };
      }

      return null;
    } catch (error) {
      console.error('[SessionHijackingDetection] Geolocation error:', error.message);
      return null;
    }
  }

  /**
   * Calculate confidence level based on indicators
   */
  static calculateConfidence(indicatorCount, riskScore) {
    // More indicators and higher risk = higher confidence
    const indicatorFactor = Math.min(indicatorCount / 3, 1);
    const riskFactor = riskScore / 100;
    
    return (indicatorFactor * 0.4 + riskFactor * 0.6);
  }

  /**
   * Get severity level from risk score
   */
  static getSeverityFromScore(score) {
    if (score >= this.config.riskThresholds.critical) return 'critical';
    if (score >= this.config.riskThresholds.high) return 'high';
    if (score >= this.config.riskThresholds.medium) return 'medium';
    if (score >= this.config.riskThresholds.low) return 'low';
    return 'info';
  }

  /**
   * Get recommendation based on risk score
   */
  static getRecommendation(riskScore) {
    if (riskScore >= this.config.riskThresholds.critical) {
      return {
        action: 'IMMEDIATE_CONTAINMENT',
        message: 'Terminate session immediately and initiate recovery process',
        requiresAdmin: false,
        automated: true
      };
    }
    if (riskScore >= this.config.riskThresholds.high) {
      return {
        action: 'FORCE_REAUTH',
        message: 'Force re-authentication with step-up challenge',
        requiresAdmin: false,
        automated: true
      };
    }
    if (riskScore >= this.config.riskThresholds.medium) {
      return {
        action: 'CHALLENGE',
        message: 'Issue security challenge to verify user identity',
        requiresAdmin: false,
        automated: true
      };
    }
    return {
      action: 'MONITOR',
      message: 'Continue monitoring session for additional indicators',
      requiresAdmin: false,
      automated: true
    };
  }

  /**
   * Create hijacking event
   */
  static async createHijackingEvent(detectionResult, session, req) {
    try {
      const currentIP = req.ip || req.connection?.remoteAddress;
      const currentUA = req.headers['user-agent'];
      const currentFingerprint = req.headers['x-device-fingerprint'];
      const currentLocation = await this.getLocationFromIP(currentIP);

      const event = await SessionHijackingEvent.createEvent({
        userId: session.userId,
        sessionId: session._id,
        detectedAt: new Date(),
        detectionMethod: detectionResult.detectionMethod,
        indicators: detectionResult.indicators,
        riskScore: detectionResult.riskScore,
        confidenceLevel: detectionResult.confidenceLevel,
        originalSession: {
          ipAddress: session.location?.ipAddress,
          userAgent: session.userAgent,
          location: session.location,
          lastSeenAt: session.activity?.lastAccessAt
        },
        suspiciousSession: {
          ipAddress: currentIP,
          userAgent: currentUA,
          deviceFingerprint: currentFingerprint,
          location: currentLocation,
          firstSeenAt: new Date()
        }
      });

      // Log security event
      await SecurityEvent.create({
        userId: session.userId,
        eventType: 'SESSION_ANOMALY_DETECTED',
        severity: detectionResult.indicators.length > 2 ? 'critical' : 'high',
        ipAddress: currentIP,
        userAgent: currentUA,
        details: {
          riskScore: detectionResult.riskScore,
          detectionMethod: detectionResult.detectionMethod,
          indicatorCount: detectionResult.indicators.length
        },
        riskScore: detectionResult.riskScore
      });

      return event;
    } catch (error) {
      console.error('[SessionHijackingDetection] Error creating event:', error);
      throw error;
    }
  }
}

module.exports = SessionHijackingDetectionService;
