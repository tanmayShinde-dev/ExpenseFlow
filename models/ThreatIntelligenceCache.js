const mongoose = require('mongoose');

/**
 * Threat Intelligence Cache Model
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Stores enrichment data with staleness tracking and source metadata
 */

const threatIntelligenceCacheSchema = new mongoose.Schema({
  // Entity being enriched
  entityType: {
    type: String,
    enum: ['IP', 'EMAIL', 'DOMAIN', 'ASN', 'USER_AGENT'],
    required: true,
    index: true
  },
  
  entityValue: {
    type: String,
    required: true,
    index: true
  },
  
  // Enrichment data from all sources
  enrichment: {
    // IP Reputation
    ipReputation: {
      score: { type: Number, min: 0, max: 100 }, // 0 = clean, 100 = malicious
      categories: [String], // ['spam', 'abuse', 'malware', etc.]
      reportsCount: Number,
      lastReported: Date,
      isMalicious: Boolean,
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number // seconds
    },
    
    // TOR/Proxy/VPN Detection
    anonymizer: {
      isTor: Boolean,
      isProxy: Boolean,
      isVpn: Boolean,
      isHosting: Boolean,
      isRelay: Boolean,
      proxyType: String, // 'residential', 'datacenter', 'mobile'
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number
    },
    
    // Geographic Risk
    geoRisk: {
      country: String,
      countryCode: String,
      city: String,
      riskScore: { type: Number, min: 0, max: 100 },
      riskFactors: [String], // ['high_fraud_country', 'sanctioned', etc.]
      isHighRisk: Boolean,
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number
    },
    
    // ASN Trust Score
    asnTrust: {
      asn: Number,
      asnName: String,
      organization: String,
      trustScore: { type: Number, min: 0, max: 100 },
      trustFactors: [String], // ['known_hosting', 'good_reputation', etc.]
      isTrusted: Boolean,
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number
    },
    
    // Disposable Email Detection
    disposableEmail: {
      isDisposable: Boolean,
      isTemporary: Boolean,
      domain: String,
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number
    },
    
    // Leaked Credential Check
    credentialBreach: {
      isBreached: Boolean,
      breachCount: Number,
      breaches: [{
        name: String,
        date: Date,
        dataClasses: [String] // ['Passwords', 'Email addresses', etc.]
      }],
      lastBreachDate: Date,
      confidence: { type: Number, min: 0, max: 1 },
      sources: [String],
      fetchedAt: Date,
      ttl: Number
    }
  },
  
  // Aggregated risk assessment
  aggregatedRisk: {
    overallScore: { type: Number, min: 0, max: 100 },
    riskLevel: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    factors: [{
      factor: String,
      weight: Number,
      contribution: Number
    }]
  },
  
  // Cache metadata
  metadata: {
    firstFetched: { type: Date, default: Date.now },
    lastFetched: { type: Date, default: Date.now },
    fetchCount: { type: Number, default: 1 },
    lastUpdated: { type: Date, default: Date.now },
    
    // Staleness tracking
    isStale: { type: Boolean, default: false },
    staleAt: Date,
    
    // Provider status
    providers: [{
      name: String,
      status: { type: String, enum: ['success', 'failure', 'timeout', 'unavailable'] },
      lastAttempt: Date,
      latencyMs: Number,
      error: String
    }],
    
    // Cache hit tracking
    hits: { type: Number, default: 0 },
    lastHit: Date
  },
  
  // Expiration
  expiresAt: {
    type: Date,
    required: true,
    index: true
  }
}, {
  timestamps: true
});

// TTL index for automatic cleanup
threatIntelligenceCacheSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Compound indexes for fast lookups
threatIntelligenceCacheSchema.index({ entityType: 1, entityValue: 1 }, { unique: true });
threatIntelligenceCacheSchema.index({ 'metadata.isStale': 1, 'metadata.lastFetched': 1 });

// Static methods
threatIntelligenceCacheSchema.statics = {
  /**
   * Get cached enrichment data
   */
  async getCached(entityType, entityValue) {
    const cached = await this.findOne({ entityType, entityValue });
    
    if (!cached) return null;
    
    // Check if stale
    if (cached.expiresAt < new Date()) {
      cached.metadata.isStale = true;
      await cached.save();
      return null;
    }
    
    // Update hit tracking
    cached.metadata.hits += 1;
    cached.metadata.lastHit = new Date();
    await cached.save();
    
    return cached;
  },
  
  /**
   * Store enrichment data
   */
  async storeEnrichment(entityType, entityValue, enrichmentData, ttlSeconds = 3600) {
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    
    const cached = await this.findOneAndUpdate(
      { entityType, entityValue },
      {
        $set: {
          enrichment: enrichmentData,
          expiresAt,
          'metadata.lastFetched': new Date(),
          'metadata.lastUpdated': new Date(),
          'metadata.isStale': false
        },
        $inc: {
          'metadata.fetchCount': 1
        },
        $setOnInsert: {
          'metadata.firstFetched': new Date()
        }
      },
      {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true
      }
    );
    
    return cached;
  },
  
  /**
   * Get cache statistics
   */
  async getStats() {
    const total = await this.countDocuments();
    const stale = await this.countDocuments({ 'metadata.isStale': true });
    const byType = await this.aggregate([
      {
        $group: {
          _id: '$entityType',
          count: { $sum: 1 },
          avgHits: { $avg: '$metadata.hits' }
        }
      }
    ]);
    
    return {
      total,
      stale,
      fresh: total - stale,
      byType
    };
  }
};

// Instance methods
threatIntelligenceCacheSchema.methods = {
  /**
   * Check if any enrichment data is stale
   */
  isAnySourceStale() {
    const now = Date.now();
    
    if (this.enrichment.ipReputation?.fetchedAt) {
      const age = (now - this.enrichment.ipReputation.fetchedAt) / 1000;
      if (age > this.enrichment.ipReputation.ttl) return true;
    }
    
    if (this.enrichment.anonymizer?.fetchedAt) {
      const age = (now - this.enrichment.anonymizer.fetchedAt) / 1000;
      if (age > this.enrichment.anonymizer.ttl) return true;
    }
    
    // Check other sources similarly...
    
    return false;
  },
  
  /**
   * Calculate aggregated risk
   */
  calculateAggregatedRisk() {
    const factors = [];
    let totalScore = 0;
    let totalWeight = 0;
    
    // IP Reputation (weight: 0.25)
    if (this.enrichment.ipReputation?.score !== undefined) {
      const weight = 0.25;
      const contribution = this.enrichment.ipReputation.score * weight;
      factors.push({ factor: 'IP Reputation', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // Anonymizer (weight: 0.20)
    if (this.enrichment.anonymizer) {
      const weight = 0.20;
      let score = 0;
      if (this.enrichment.anonymizer.isTor) score = 80;
      else if (this.enrichment.anonymizer.isProxy) score = 60;
      else if (this.enrichment.anonymizer.isVpn) score = 40;
      
      const contribution = score * weight;
      factors.push({ factor: 'Anonymizer', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // Geo Risk (weight: 0.15)
    if (this.enrichment.geoRisk?.riskScore !== undefined) {
      const weight = 0.15;
      const contribution = this.enrichment.geoRisk.riskScore * weight;
      factors.push({ factor: 'Geographic Risk', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // ASN Trust (weight: 0.15, inverted)
    if (this.enrichment.asnTrust?.trustScore !== undefined) {
      const weight = 0.15;
      const contribution = (100 - this.enrichment.asnTrust.trustScore) * weight;
      factors.push({ factor: 'ASN Trust', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // Disposable Email (weight: 0.10)
    if (this.enrichment.disposableEmail?.isDisposable !== undefined) {
      const weight = 0.10;
      const score = this.enrichment.disposableEmail.isDisposable ? 70 : 0;
      const contribution = score * weight;
      factors.push({ factor: 'Disposable Email', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // Credential Breach (weight: 0.15)
    if (this.enrichment.credentialBreach?.isBreached !== undefined) {
      const weight = 0.15;
      const score = this.enrichment.credentialBreach.isBreached ? 
        Math.min(100, 50 + (this.enrichment.credentialBreach.breachCount * 10)) : 0;
      const contribution = score * weight;
      factors.push({ factor: 'Credential Breach', weight, contribution });
      totalScore += contribution;
      totalWeight += weight;
    }
    
    // Normalize if weights don't sum to 1
    const overallScore = totalWeight > 0 ? totalScore / totalWeight : 0;
    
    let riskLevel = 'LOW';
    if (overallScore >= 75) riskLevel = 'CRITICAL';
    else if (overallScore >= 50) riskLevel = 'HIGH';
    else if (overallScore >= 25) riskLevel = 'MEDIUM';
    
    this.aggregatedRisk = {
      overallScore,
      riskLevel,
      factors
    };
  }
};

module.exports = mongoose.model('ThreatIntelligenceCache', threatIntelligenceCacheSchema);
