const mongoose = require('mongoose');

/**
 * Session Behavior Profile Model
 * Issue #881: Session Hijacking Prevention & Recovery
 * 
 * Tracks behavioral patterns for each session to detect sudden divergence
 */

const sessionBehaviorProfileSchema = new mongoose.Schema({
  sessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session',
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Request pattern analysis
  requestPatterns: {
    totalRequests: {
      type: Number,
      default: 0
    },
    avgCadence: {
      type: Number, // milliseconds between requests
      default: 0
    },
    cadenceStdDev: {
      type: Number,
      default: 0
    },
    // Recent request timestamps for cadence calculation
    recentRequestTimes: [{
      type: Date
    }],
    // Endpoint usage patterns
    endpointCounts: {
      type: Map,
      of: Number,
      default: () => new Map()
    },
    topEndpoints: [{
      endpoint: String,
      count: Number,
      percentage: Number
    }],
    // HTTP methods distribution
    methodDistribution: {
      GET: { type: Number, default: 0 },
      POST: { type: Number, default: 0 },
      PUT: { type: Number, default: 0 },
      DELETE: { type: Number, default: 0 },
      PATCH: { type: Number, default: 0 }
    }
  },
  // Activity patterns
  activityProfile: {
    level: {
      type: String,
      enum: ['VERY_LOW', 'LOW', 'MODERATE', 'HIGH', 'VERY_HIGH'],
      default: 'LOW'
    },
    avgResponseTime: {
      type: Number, // milliseconds
      default: 0
    },
    // Time of day patterns (hourly buckets)
    hourlyActivity: {
      type: [Number], // 24 buckets
      default: () => new Array(24).fill(0)
    },
    // Resource access patterns
    resourceTypes: {
      type: Map,
      of: Number,
      default: () => new Map()
    },
    dataOperations: {
      reads: { type: Number, default: 0 },
      writes: { type: Number, default: 0 },
      deletes: { type: Number, default: 0 }
    }
  },
  // Privilege usage tracking
  privilegeUsage: {
    actions: [{
      action: String,
      endpoint: String,
      timestamp: Date,
      privilegeLevel: String
    }],
    escalationAttempts: {
      type: Number,
      default: 0
    },
    lastEscalationAttempt: Date,
    normalPrivilegeLevel: String
  },
  // Navigation patterns
  navigationPatterns: {
    // Sequence of endpoints (last 50)
    recentSequence: [{
      endpoint: String,
      timestamp: Date
    }],
    // Common sequences/flows
    commonFlows: [{
      sequence: [String],
      occurrences: Number
    }],
    // Entry points
    entryEndpoints: {
      type: Map,
      of: Number,
      default: () => new Map()
    }
  },
  // Baseline establishment
  baseline: {
    established: {
      type: Boolean,
      default: false
    },
    establishedAt: Date,
    requiredSamples: {
      type: Number,
      default: 50
    },
    currentSamples: {
      type: Number,
      default: 0
    }
  },
  // Anomaly tracking
  anomalies: [{
    type: {
      type: String,
      enum: [
        'CADENCE_ANOMALY',
        'ENDPOINT_ANOMALY',
        'PRIVILEGE_ANOMALY',
        'ACTIVITY_LEVEL_ANOMALY',
        'NAVIGATION_ANOMALY',
        'TIME_OF_DAY_ANOMALY'
      ]
    },
    severity: Number, // 0-1
    details: mongoose.Schema.Types.Mixed,
    timestamp: Date
  }],
  // Last analysis
  lastAnalyzedAt: Date,
  lastUpdatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes
sessionBehaviorProfileSchema.index({ sessionId: 1, userId: 1 });
sessionBehaviorProfileSchema.index({ 'baseline.established': 1 });

// Static method to create or get profile
sessionBehaviorProfileSchema.statics.getOrCreate = async function(sessionId, userId) {
  let profile = await this.findOne({ sessionId });
  if (!profile) {
    profile = new this({
      sessionId,
      userId,
      requestPatterns: {
        recentRequestTimes: []
      },
      navigationPatterns: {
        recentSequence: []
      }
    });
    await profile.save();
  }
  return profile;
};

// Instance method to record request
sessionBehaviorProfileSchema.methods.recordRequest = async function(req) {
  const now = new Date();
  const endpoint = req.originalUrl || req.url;
  const method = req.method;

  // Update total requests
  this.requestPatterns.totalRequests += 1;
  this.baseline.currentSamples += 1;

  // Update recent request times (keep last 100)
  this.requestPatterns.recentRequestTimes.push(now);
  if (this.requestPatterns.recentRequestTimes.length > 100) {
    this.requestPatterns.recentRequestTimes.shift();
  }

  // Calculate cadence if we have enough data
  if (this.requestPatterns.recentRequestTimes.length >= 2) {
    const times = this.requestPatterns.recentRequestTimes;
    const intervals = [];
    for (let i = 1; i < times.length; i++) {
      intervals.push(times[i] - times[i - 1]);
    }
    this.requestPatterns.avgCadence = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    
    // Calculate standard deviation
    const mean = this.requestPatterns.avgCadence;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / intervals.length;
    this.requestPatterns.cadenceStdDev = Math.sqrt(variance);
  }

  // Update endpoint counts
  const currentCount = this.requestPatterns.endpointCounts.get(endpoint) || 0;
  this.requestPatterns.endpointCounts.set(endpoint, currentCount + 1);

  // Update top endpoints
  this.updateTopEndpoints();

  // Update method distribution
  if (this.requestPatterns.methodDistribution[method] !== undefined) {
    this.requestPatterns.methodDistribution[method] += 1;
  }

  // Update hourly activity
  const hour = now.getHours();
  this.activityProfile.hourlyActivity[hour] += 1;

  // Update navigation sequence
  this.navigationPatterns.recentSequence.push({
    endpoint,
    timestamp: now
  });
  if (this.navigationPatterns.recentSequence.length > 50) {
    this.navigationPatterns.recentSequence.shift();
  }

  // Determine activity level
  this.updateActivityLevel();

  // Check if baseline is established
  if (!this.baseline.established && 
      this.baseline.currentSamples >= this.baseline.requiredSamples) {
    this.baseline.established = true;
    this.baseline.establishedAt = new Date();
  }

  this.lastUpdatedAt = now;
  await this.save();
  
  return this;
};

// Update top endpoints
sessionBehaviorProfileSchema.methods.updateTopEndpoints = function() {
  const endpoints = Array.from(this.requestPatterns.endpointCounts.entries())
    .map(([endpoint, count]) => ({
      endpoint,
      count,
      percentage: (count / this.requestPatterns.totalRequests) * 100
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  this.requestPatterns.topEndpoints = endpoints;
};

// Update activity level
sessionBehaviorProfileSchema.methods.updateActivityLevel = function() {
  const totalRequests = this.requestPatterns.totalRequests;
  const timeElapsed = Date.now() - this.createdAt.getTime();
  const requestsPerHour = (totalRequests / timeElapsed) * 3600000;

  if (requestsPerHour < 10) {
    this.activityProfile.level = 'VERY_LOW';
  } else if (requestsPerHour < 30) {
    this.activityProfile.level = 'LOW';
  } else if (requestsPerHour < 60) {
    this.activityProfile.level = 'MODERATE';
  } else if (requestsPerHour < 120) {
    this.activityProfile.level = 'HIGH';
  } else {
    this.activityProfile.level = 'VERY_HIGH';
  }
};

// Instance method to detect behavioral anomaly
sessionBehaviorProfileSchema.methods.detectAnomaly = function(currentRequest) {
  if (!this.baseline.established) {
    return { isAnomaly: false, reason: 'Baseline not established' };
  }

  const anomalies = [];
  let totalAnomalyScore = 0;

  // Check cadence anomaly
  if (this.requestPatterns.recentRequestTimes.length >= 3) {
    const lastTimes = this.requestPatterns.recentRequestTimes.slice(-3);
    const recentCadence = (lastTimes[2] - lastTimes[0]) / 2;
    const cadenceDeviation = Math.abs(recentCadence - this.requestPatterns.avgCadence);
    
    // Anomaly if deviation > 3 standard deviations
    if (cadenceDeviation > (3 * this.requestPatterns.cadenceStdDev)) {
      const severity = Math.min(cadenceDeviation / (4 * this.requestPatterns.cadenceStdDev), 1);
      anomalies.push({
        type: 'CADENCE_ANOMALY',
        severity,
        details: {
          expected: this.requestPatterns.avgCadence,
          actual: recentCadence,
          deviation: cadenceDeviation
        }
      });
      totalAnomalyScore += severity * 0.3; // 30% weight
    }
  }

  // Check endpoint anomaly
  const endpoint = currentRequest.originalUrl || currentRequest.url;
  const endpointCount = this.requestPatterns.endpointCounts.get(endpoint) || 0;
  const endpointFrequency = endpointCount / this.requestPatterns.totalRequests;
  
  // Anomaly if accessing rare endpoint (< 1% frequency) or completely new endpoint
  if (endpointFrequency === 0 || endpointFrequency < 0.01) {
    const severity = endpointFrequency === 0 ? 0.8 : (1 - endpointFrequency * 100);
    anomalies.push({
      type: 'ENDPOINT_ANOMALY',
      severity,
      details: {
        endpoint,
        frequency: endpointFrequency,
        isNew: endpointFrequency === 0
      }
    });
    totalAnomalyScore += severity * 0.4; // 40% weight
  }

  // Check time-of-day anomaly
  const currentHour = new Date().getHours();
  const hourlyAvg = this.activityProfile.hourlyActivity.reduce((a, b) => a + b, 0) / 24;
  const currentHourActivity = this.activityProfile.hourlyActivity[currentHour];
  
  if (currentHourActivity < hourlyAvg * 0.1 && this.requestPatterns.totalRequests > 100) {
    const severity = 1 - (currentHourActivity / hourlyAvg);
    anomalies.push({
      type: 'TIME_OF_DAY_ANOMALY',
      severity: severity * 0.5, // Reduced severity
      details: {
        hour: currentHour,
        normalActivity: hourlyAvg,
        currentHourActivity
      }
    });
    totalAnomalyScore += severity * 0.2; // 20% weight
  }

  // Determine if overall behavior is anomalous
  const isAnomaly = totalAnomalyScore > 0.5; // Threshold

  if (isAnomaly) {
    this.anomalies.push(...anomalies.map(a => ({
      ...a,
      timestamp: new Date()
    })));
  }

  return {
    isAnomaly,
    anomalyScore: totalAnomalyScore,
    anomalies,
    baselineEstablished: this.baseline.established
  };
};

// Instance method to record privilege escalation attempt
sessionBehaviorProfileSchema.methods.recordPrivilegeEscalation = async function(action, endpoint, privilegeLevel) {
  this.privilegeUsage.actions.push({
    action,
    endpoint,
    timestamp: new Date(),
    privilegeLevel
  });
  this.privilegeUsage.escalationAttempts += 1;
  this.privilegeUsage.lastEscalationAttempt = new Date();
  
  await this.save();
  return this;
};

module.exports = mongoose.model('SessionBehaviorProfile', sessionBehaviorProfileSchema);
