const mongoose = require('mongoose');

/**
 * Attack Graph Entity Model
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Represents nodes in the attack graph:
 * - IP addresses and ranges
 * - Device fingerprints
 * - ASNs (Autonomous System Numbers)
 * - User agents
 * - Geographic locations
 * - User accounts
 */

const attackGraphEntitySchema = new mongoose.Schema({
  entityType: {
    type: String,
    enum: ['IP', 'IP_RANGE', 'DEVICE_FINGERPRINT', 'ASN', 'USER_AGENT', 'LOCATION', 'USER', 'SESSION'],
    required: true,
    index: true
  },
  entityValue: {
    type: String,
    required: true,
    index: true
  },
  
  // Metadata for different entity types
  metadata: {
    // For IP/IP_RANGE
    ipVersion: { type: Number, enum: [4, 6] },
    cidr: String,
    
    // For ASN
    asnNumber: Number,
    organization: String,
    
    // For LOCATION
    country: String,
    city: String,
    latitude: Number,
    longitude: Number,
    
    // For DEVICE_FINGERPRINT
    deviceInfo: {
      userAgent: String,
      screen: String,
      timezone: String,
      language: String,
      platform: String
    },
    
    // For USER_AGENT
    browser: String,
    browserVersion: String,
    os: String,
    osVersion: String,
    
    // For USER
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    accountCreatedAt: Date,
    
    // For SESSION
    sessionId: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  
  // Risk scoring
  riskScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
    index: true
  },
  
  // Statistical tracking
  stats: {
    totalEvents: { type: Number, default: 0 },
    failedLoginAttempts: { type: Number, default: 0 },
    successfulLogins: { type: Number, default: 0 },
    uniqueUsersTargeted: { type: Number, default: 0 },
    uniqueAccountsCompromised: { type: Number, default: 0 },
    timeWindowStart: Date,
    timeWindowEnd: Date,
    avgTimeBetweenEvents: Number, // milliseconds
    eventVelocity: Number // events per hour
  },
  
  // Classification
  classification: {
    type: String,
    enum: ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'COMPROMISED', 'UNKNOWN'],
    default: 'UNKNOWN',
    index: true
  },
  
  // Connected components analysis
  graphMetrics: {
    connectedComponentId: { type: mongoose.Schema.Types.ObjectId, index: true },
    componentSize: Number,
    componentRiskScore: Number,
    degreeCount: { type: Number, default: 0 }, // Number of connections
    centralityScore: Number, // How central this entity is in the graph
    clusteringCoefficient: Number // How clustered this entity's connections are
  },
  
  // Detection metadata
  firstSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  // Analyst notes and flags
  analystFlags: [{
    flag: String,
    reason: String,
    analyst: String,
    timestamp: { type: Date, default: Date.now }
  }],
  
  // Blocklist status
  isBlocklisted: {
    type: Boolean,
    default: false,
    index: true
  },
  blocklistedAt: Date,
  blocklistReason: String,
  blocklistExpiresAt: Date,
  
  // Associated incidents
  incidents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SecurityIncident'
  }],
  
  // Enrichment data (from threat intelligence, OSINT, etc.)
  enrichmentData: {
    isProxy: Boolean,
    isVpn: Boolean,
    isTor: Boolean,
    isHosting: Boolean,
    threatIntelligence: {
      isMalicious: Boolean,
      sources: [String],
      lastChecked: Date
    },
    geoDistance: Number // km from expected location for user entities
  }
}, {
  timestamps: true,
  indexes: [
    { entityType: 1, entityValue: 1 }, // Compound index for fast lookups
    { riskScore: -1, lastSeen: -1 }, // For prioritizing high-risk recent entities
    { 'graphMetrics.connectedComponentId': 1, riskScore: -1 }
  ]
});

// Static methods for entity creation and updates
attackGraphEntitySchema.statics = {
  /**
   * Find or create an entity
   */
  async findOrCreate(entityData) {
    const { entityType, entityValue } = entityData;
    let entity = await this.findOne({ entityType, entityValue });
    
    if (!entity) {
      entity = await this.create(entityData);
    } else {
      entity.lastSeen = new Date();
      entity.stats.totalEvents += 1;
      await entity.save();
    }
    
    return entity;
  },
  
  /**
   * Update entity risk score
   */
  async updateRiskScore(entityId, newRiskScore, reason) {
    const entity = await this.findById(entityId);
    if (!entity) return null;
    
    entity.riskScore = Math.min(100, Math.max(0, newRiskScore));
    
    // Auto-classify based on risk score
    if (entity.riskScore >= 80) {
      entity.classification = 'MALICIOUS';
    } else if (entity.riskScore >= 60) {
      entity.classification = 'SUSPICIOUS';
    } else if (entity.riskScore >= 30) {
      entity.classification = 'UNKNOWN';
    } else {
      entity.classification = 'BENIGN';
    }
    
    await entity.save();
    return entity;
  },
  
  /**
   * Get high-risk entities
   */
  async getHighRiskEntities(limit = 100, minRiskScore = 70) {
    return this.find({
      riskScore: { $gte: minRiskScore },
      classification: { $in: ['SUSPICIOUS', 'MALICIOUS', 'COMPROMISED'] }
    })
    .sort({ riskScore: -1, lastSeen: -1 })
    .limit(limit);
  }
};

// Instance methods
attackGraphEntitySchema.methods = {
  /**
   * Add analyst flag
   */
  async addAnalystFlag(flag, reason, analyst) {
    this.analystFlags.push({
      flag,
      reason,
      analyst,
      timestamp: new Date()
    });
    await this.save();
  },
  
  /**
   * Blocklist this entity
   */
  async blocklist(reason, expiresInMs = null) {
    this.isBlocklisted = true;
    this.blocklistedAt = new Date();
    this.blocklistReason = reason;
    if (expiresInMs) {
      this.blocklistExpiresAt = new Date(Date.now() + expiresInMs);
    }
    await this.save();
  },
  
  /**
   * Remove from blocklist
   */
  async unBlocklist() {
    this.isBlocklisted = false;
    this.blocklistExpiresAt = null;
    await this.save();
  }
};

module.exports = mongoose.model('AttackGraphEntity', attackGraphEntitySchema);
