/**
 * Provider SLA Tracking Model
 * Tracks performance metrics for threat intel providers
 */

const mongoose = require('mongoose');

const providerSLASchema = new mongoose.Schema(
  {
    providerId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    providerName: {
      type: String,
      required: true
    },
    providerType: {
      type: String,
      enum: ['HIBP', 'INTERNAL', 'HONEYPOT', 'EXTERNAL_FEED', 'THIRD_PARTY'],
      required: true
    },

    // Performance Metrics
    metrics: {
      // Latency tracking (milliseconds)
      avgLatency: {
        type: Number,
        default: 0
      },
      p95Latency: {
        type: Number,
        default: 0
      },
      p99Latency: {
        type: Number,
        default: 0
      },

      // Error tracking
      errorRate: {
        type: Number,
        default: 0, // Percentage 0-100
        min: 0,
        max: 100
      },
      timeoutRate: {
        type: Number,
        default: 0, // Percentage 0-100
        min: 0,
        max: 100
      },
      failedRequests: {
        type: Number,
        default: 0
      },
      totalRequests: {
        type: Number,
        default: 0
      },

      // Availability
      uptime: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      downtime: {
        type: Number,
        default: 0 // Milliseconds
      },

      // Data quality
      dataFreshness: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      accuracyScore: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      },
      completenessScore: {
        type: Number,
        default: 100, // Percentage
        min: 0,
        max: 100
      }
    },

    // SLA Configuration
    sla: {
      targetLatency: {
        type: Number,
        default: 500 // ms
      },
      maxErrorRate: {
        type: Number,
        default: 5 // Percentage
      },
      maxTimeoutRate: {
        type: Number,
        default: 2 // Percentage
      },
      minUptime: {
        type: Number,
        default: 99.9 // Percentage
      },
      minAccuracy: {
        type: Number,
        default: 95 // Percentage
      }
    },

    // Health History
    healthHistory: [
      {
        timestamp: Date,
        healthScore: Number,
        status: {
          type: String,
          enum: ['HEALTHY', 'DEGRADED', 'UNHEALTHY', 'DOWN']
        },
        issues: [String]
      }
    ],

    // Status tracking
    currentStatus: {
      type: String,
      enum: ['HEALTHY', 'DEGRADED', 'UNHEALTHY', 'DOWN'],
      default: 'HEALTHY'
    },
    lastHealthCheck: Date,
    lastIncident: Date,
    incidentCount: {
      type: Number,
      default: 0
    },

    // Configuration
    enabled: {
      type: Boolean,
      default: true
    },
    weight: {
      type: Number,
      default: 1,
      min: 0,
      max: 10
    },
    minWeightThreshold: {
      type: Number,
      default: 0.2, // Don't reduce weight below 20% of original
      min: 0,
      max: 1
    }
  },
  { timestamps: true }
);

// Indexes
providerSLASchema.index({ providerId: 1, 'currentStatus': 1 });
providerSLASchema.index({ 'metrics.uptime': 1 });
providerSLASchema.index({ lastHealthCheck: -1 });
providerSLASchema.index({ 'healthHistory.timestamp': -1 });

/**
 * Record a request metric
 */
providerSLASchema.methods.recordRequest = async function(
  latency,
  success = true,
  timedOut = false,
  error = null
) {
  this.metrics.totalRequests += 1;

  if (!success) {
    this.metrics.failedRequests += 1;
  }
  if (timedOut) {
    this.metrics.timeoutRate =
      ((this.metrics.timeoutRate * (this.metrics.totalRequests - 1) + 100) /
        this.metrics.totalRequests);
  }

  // Update latency
  if (!isNaN(latency)) {
    this.metrics.avgLatency =
      (this.metrics.avgLatency * (this.metrics.totalRequests - 1) + latency) /
      this.metrics.totalRequests;
  }

  // Recalculate error rate
  this.metrics.errorRate =
    (this.metrics.failedRequests / this.metrics.totalRequests) * 100;

  await this.save();
};

/**
 * Record availability
 */
providerSLASchema.methods.recordAvailability = async function(available, downTimeDuration = 0) {
  const totalTime = this.metrics.totalRequests * 100 + (downTimeDuration || 0);
  const downTime = downTimeDuration || 0;

  if (!available) {
    this.metrics.downtime += downTime;
    this.incidentCount += 1;
    this.lastIncident = new Date();
  }

  this.metrics.uptime = ((totalTime - downTime) / totalTime) * 100;
  await this.save();
};

/**
 * Update accuracy score
 */
providerSLASchema.methods.updateAccuracy = async function(accuracy) {
  this.metrics.accuracyScore = accuracy;
  await this.save();
};

/**
 * Get health score (0-100)
 */
providerSLASchema.methods.getHealthScore = function() {
  const weights = {
    latency: 0.20,
    availability: 0.30,
    errorRate: 0.20,
    accuracy: 0.20,
    freshness: 0.10
  };

  // Latency score (lower is better)
  const latencyScore =
    Math.max(0, 100 - (this.metrics.avgLatency / this.sla.targetLatency) * 100);

  // Availability score
  const availabilityScore = this.metrics.uptime;

  // Error rate score (lower is better)
  const errorScore =
    Math.max(0, 100 - (this.metrics.errorRate / this.sla.maxErrorRate) * 100);

  // Accuracy score
  const accuracyScore = this.metrics.accuracyScore;

  // Freshness score
  const freshnessScore = this.metrics.dataFreshness;

  // Weighted average
  const healthScore =
    latencyScore * weights.latency +
    availabilityScore * weights.availability +
    errorScore * weights.errorRate +
    accuracyScore * weights.accuracy +
    freshnessScore * weights.freshness;

  return Math.round(healthScore);
};

/**
 * Determine status based on health score
 */
providerSLASchema.methods.determineStatus = async function() {
  const healthScore = this.getHealthScore();

  let newStatus;
  if (healthScore >= 90) {
    newStatus = 'HEALTHY';
  } else if (healthScore >= 70) {
    newStatus = 'DEGRADED';
  } else if (healthScore >= 50) {
    newStatus = 'UNHEALTHY';
  } else {
    newStatus = 'DOWN';
  }

  if (newStatus !== this.currentStatus) {
    this.currentStatus = newStatus;
    this.lastHealthCheck = new Date();

    // Record in history
    if (!this.healthHistory) {
      this.healthHistory = [];
    }

    this.healthHistory.push({
      timestamp: new Date(),
      healthScore,
      status: newStatus,
      issues: this._getIssues(healthScore)
    });

    // Keep only last 100 entries
    if (this.healthHistory.length > 100) {
      this.healthHistory = this.healthHistory.slice(-100);
    }
  }

  await this.save();
  return newStatus;
};

/**
 * Get issues affecting health
 */
providerSLASchema.methods._getIssues = function(healthScore) {
  const issues = [];

  if (this.metrics.errorRate > this.sla.maxErrorRate) {
    issues.push(`High error rate: ${this.metrics.errorRate.toFixed(2)}%`);
  }

  if (this.metrics.timeoutRate > this.sla.maxTimeoutRate) {
    issues.push(`High timeout rate: ${this.metrics.timeoutRate.toFixed(2)}%`);
  }

  if (this.metrics.uptime < this.sla.minUptime) {
    issues.push(`Low uptime: ${this.metrics.uptime.toFixed(2)}%`);
  }

  if (this.metrics.accuracyScore < this.sla.minAccuracy) {
    issues.push(`Low accuracy: ${this.metrics.accuracyScore.toFixed(2)}%`);
  }

  if (this.metrics.avgLatency > this.sla.targetLatency * 2) {
    issues.push(`High latency: ${this.metrics.avgLatency.toFixed(0)}ms`);
  }

  if (this.metrics.dataFreshness < 80) {
    issues.push(`Data freshness low: ${this.metrics.dataFreshness.toFixed(2)}%`);
  }

  return issues;
};

/**
 * Static: Get all healthy providers
 */
providerSLASchema.statics.getHealthyProviders = async function(providers = null) {
  const query = { currentStatus: 'HEALTHY', enabled: true };
  if (providers) {
    query.providerId = { $in: providers };
  }
  return this.find(query).sort({ 'metrics.uptime': -1 });
};

/**
 * Static: Get degraded providers
 */
providerSLASchema.statics.getDegradedProviders = async function() {
  return this.find({ currentStatus: 'DEGRADED', enabled: true }).sort({
    'metrics.uptime': -1
  });
};

/**
 * Static: Get provider rankings by health
 */
providerSLASchema.statics.getRankingsByHealth = async function() {
  return this.aggregate([
    { $match: { enabled: true } },
    {
      $addFields: {
        healthScore: {
          $add: [
            { $multiply: [{ $max: [0, { $subtract: [100, { $multiply: [{ $divide: ['$metrics.avgLatency', '$sla.targetLatency'] }, 100] }] }] }, 0.2] },
            { $multiply: ['$metrics.uptime', 0.3] },
            { $multiply: [{ $max: [0, { $subtract: [100, { $multiply: [{ $divide: ['$metrics.errorRate', '$sla.maxErrorRate'] }, 100] }] }] }, 0.2] },
            { $multiply: ['$metrics.accuracyScore', 0.2] },
            { $multiply: ['$metrics.dataFreshness', 0.1] }
          ]
        }
      }
    },
    { $sort: { healthScore: -1 } },
    { $limit: 20 }
  ]);
};

module.exports = mongoose.model('ProviderSLA', providerSLASchema);
