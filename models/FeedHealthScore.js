/**
 * Feed Health Score Model
 * Tracks consensus, drift, and quality metrics across feeds
 */

const mongoose = require('mongoose');

const feedHealthScoreSchema = new mongoose.Schema(
  {
    feedId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    feedName: {
      type: String,
      required: true
    },
    feedType: {
      type: String,
      enum: ['BREACH_FEED', 'THREAT_FEED', 'VULNERABILITY_FEED', 'ATTACK_PATTERN_FEED'],
      required: true
    },

    // Consensus tracking
    consensus: {
      // Provider agreement metrics
      agreementRate: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      conflictCount: {
        type: Number,
        default: 0
      },
      conflictHistory: [
        {
          timestamp: Date,
          providers: [String],
          conflictType: String,
          resolution: String
        }
      ],
      lastConflict: Date,
      averageConflictResolution: {
        type: Number,
        default: 0 // milliseconds
      }
    },

    // Drift detection
    drift: {
      detectionEnabled: {
        type: Boolean,
        default: true
      },
      baselineDataPoints: {
        type: Number,
        default: 0
      },
      currentDataPoints: {
        type: Number,
        default: 0
      },
      driftPercentage: {
        type: Number,
        default: 0
      },
      driftThreshold: {
        type: Number,
        default: 20, // Percentage
        min: 0,
        max: 100
      },
      driftDetected: {
        type: Boolean,
        default: false
      },
      lastDriftCheck: Date,
      driftHistory: [
        {
          timestamp: Date,
          driftPercentage: Number,
          detectedAt: Date,
          resolved: Boolean,
          resolution: String
        }
      ]
    },

    // Quality metrics
    quality: {
      completeness: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      consistency: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      reliability: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      timeliness: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      validity: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      }
    },

    // Confidence calibration
    confidenceCalibration: {
      calibrated: {
        type: Boolean,
        default: false
      },
      baselineAccuracy: {
        type: Number,
        default: 0
      },
      calibrationFactor: {
        type: Number,
        default: 1.0 // Multiplier for confidence scores
      },
      calibrationSampleSize: {
        type: Number,
        default: 0
      },
      lastCalibration: Date
    },

    // Safe mode status
    safeMode: {
      enabled: {
        type: Boolean,
        default: false
      },
      activatedAt: Date,
      reason: String,
      fallbackProvider: String,
      fallbackMode: {
        type: String,
        enum: ['CONSERVATIVE', 'PASSTHROUGH', 'MANUAL_REVIEW'],
        default: 'CONSERVATIVE'
      },
      alertSent: {
        type: Boolean,
        default: false
      }
    },

    // Overall health
    overallHealth: {
      type: Number,
      default: 100,
      min: 0,
      max: 100
    },
    healthStatus: {
      type: String,
      enum: ['EXCELLENT', 'GOOD', 'FAIR', 'POOR', 'CRITICAL'],
      default: 'EXCELLENT'
    },
    lastHealthUpdate: Date,

    // Monitoring
    monitoringEnabled: {
      type: Boolean,
      default: true
    },
    checkFrequency: {
      type: Number,
      default: 300000 // 5 minutes in milliseconds
    },
    lastCheck: Date,

    // Alerts
    activeAlerts: [
      {
        alertId: String,
        type: String,
        severity: {
          type: String,
          enum: ['INFO', 'WARNING', 'CRITICAL']
        },
        message: String,
        createdAt: Date,
        resolvedAt: Date
      }
    ]
  },
  { timestamps: true }
);

// Indexes
feedHealthScoreSchema.index({ feedId: 1, 'healthStatus': 1 });
feedHealthScoreSchema.index({ 'drift.driftDetected': 1 });
feedHealthScoreSchema.index({ 'overallHealth': 1 });
feedHealthScoreSchema.index({ lastCheck: -1 });

/**
 * Record a conflict between providers
 */
feedHealthScoreSchema.methods.recordConflict = async function(
  providers,
  conflictType,
  resolution
) {
  this.consensus.conflictCount += 1;
  this.consensus.lastConflict = new Date();

  this.consensus.conflictHistory.push({
    timestamp: new Date(),
    providers,
    conflictType,
    resolution
  });

  // Keep only last 100 conflicts
  if (this.consensus.conflictHistory.length > 100) {
    this.consensus.conflictHistory = this.consensus.conflictHistory.slice(-100);
  }

  // Update agreement rate
  this._recalculateAgreementRate();

  await this.save();
};

/**
 * Record drift detection
 */
feedHealthScoreSchema.methods.recordDrift = async function(
  currentDataPoints,
  driftPercentage
) {
  this.drift.currentDataPoints = currentDataPoints;
  this.drift.driftPercentage = driftPercentage;
  this.drift.lastDriftCheck = new Date();

  if (driftPercentage > this.drift.driftThreshold) {
    this.drift.driftDetected = true;

    this.drift.driftHistory.push({
      timestamp: new Date(),
      driftPercentage,
      detectedAt: new Date(),
      resolved: false
    });

    // Keep only last 100 entries
    if (this.drift.driftHistory.length > 100) {
      this.drift.driftHistory = this.drift.driftHistory.slice(-100);
    }
  } else {
    this.drift.driftDetected = false;
  }

  await this.save();
};

/**
 * Update quality metric
 */
feedHealthScoreSchema.methods.updateQualityMetric = async function(
  metricName,
  value
) {
  if (this.quality.hasOwnProperty(metricName)) {
    this.quality[metricName] = Math.max(0, Math.min(100, value));
    this._recalculateOverallHealth();
    await this.save();
  }
};

/**
 * Calibrate confidence
 */
feedHealthScoreSchema.methods.calibrateConfidence = async function(
  baselineAccuracy,
  sampleSize
) {
  this.confidenceCalibration.calibrated = true;
  this.confidenceCalibration.baselineAccuracy = baselineAccuracy;
  this.confidenceCalibration.calibrationSampleSize = sampleSize;
  this.confidenceCalibration.lastCalibration = new Date();

  // Calculate calibration factor
  // If baseline is 90%, factor is 1.0
  // If baseline is 80%, factor is 0.89 (reduce confidence claims)
  // If baseline is 95%, factor is 1.05 (increase confidence claims)
  this.confidenceCalibration.calibrationFactor = baselineAccuracy / 90;

  await this.save();
};

/**
 * Activate safe mode
 */
feedHealthScoreSchema.methods.activateSafeMode = async function(
  reason,
  fallbackProvider,
  fallbackMode = 'CONSERVATIVE'
) {
  this.safeMode.enabled = true;
  this.safeMode.activatedAt = new Date();
  this.safeMode.reason = reason;
  this.safeMode.fallbackProvider = fallbackProvider;
  this.safeMode.fallbackMode = fallbackMode;
  this.safeMode.alertSent = false;

  // Add critical alert
  this.activeAlerts.push({
    alertId: `SAFE_MODE_${Date.now()}`,
    type: 'SAFE_MODE_ACTIVATED',
    severity: 'CRITICAL',
    message: `Safe mode activated: ${reason}`,
    createdAt: new Date()
  });

  await this.save();
};

/**
 * Deactivate safe mode
 */
feedHealthScoreSchema.methods.deactivateSafeMode = async function() {
  this.safeMode.enabled = false;

  // Mark alert as resolved
  const safeModeAlert = this.activeAlerts.find(a => a.type === 'SAFE_MODE_ACTIVATED');
  if (safeModeAlert) {
    safeModeAlert.resolvedAt = new Date();
  }

  await this.save();
};

/**
 * Add alert
 */
feedHealthScoreSchema.methods.addAlert = async function(
  alertType,
  severity,
  message
) {
  this.activeAlerts.push({
    alertId: `${alertType}_${Date.now()}`,
    type: alertType,
    severity,
    message,
    createdAt: new Date()
  });

  // Keep only active alerts
  this.activeAlerts = this.activeAlerts.filter(a => !a.resolvedAt);

  await this.save();
};

/**
 * Recalculate agreement rate
 */
feedHealthScoreSchema.methods._recalculateAgreementRate = function() {
  if (this.consensus.conflictCount === 0) {
    this.consensus.agreementRate = 100;
  } else {
    // Assume average request count
    const estimatedTotalRequests = this.consensus.conflictCount * 10;
    this.consensus.agreementRate = Math.round(
      ((estimatedTotalRequests - this.consensus.conflictCount) /
        estimatedTotalRequests) *
        100
    );
  }
};

/**
 * Recalculate overall health
 */
feedHealthScoreSchema.methods._recalculateOverallHealth = function() {
  const weights = {
    completeness: 0.20,
    consistency: 0.25,
    reliability: 0.25,
    timeliness: 0.20,
    validity: 0.10
  };

  const health =
    this.quality.completeness * weights.completeness +
    this.quality.consistency * weights.consistency +
    this.quality.reliability * weights.reliability +
    this.quality.timeliness * weights.timeliness +
    this.quality.validity * weights.validity;

  this.overallHealth = Math.round(health);

  // Determine status
  if (this.overallHealth >= 90) {
    this.healthStatus = 'EXCELLENT';
  } else if (this.overallHealth >= 80) {
    this.healthStatus = 'GOOD';
  } else if (this.overallHealth >= 70) {
    this.healthStatus = 'FAIR';
  } else if (this.overallHealth >= 50) {
    this.healthStatus = 'POOR';
  } else {
    this.healthStatus = 'CRITICAL';
  }

  this.lastHealthUpdate = new Date();
};

/**
 * Static: Get feeds in safe mode
 */
feedHealthScoreSchema.statics.getFeedsInSafeMode = async function() {
  return this.find({ 'safeMode.enabled': true });
};

/**
 * Static: Get feeds with critical health
 */
feedHealthScoreSchema.statics.getCriticalFeeds = async function() {
  return this.find({ healthStatus: 'CRITICAL' }).sort({ overallHealth: 1 });
};

/**
 * Static: Get feeds with drift detected
 */
feedHealthScoreSchema.statics.getFeedsWithDrift = async function() {
  return this.find({ 'drift.driftDetected': true });
};

module.exports = mongoose.model('FeedHealthScore', feedHealthScoreSchema);
