const mongoose = require('mongoose');

/**
 * Attack Graph Relationship Model
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Represents edges/relationships between entities in the attack graph
 * Examples:
 * - IP used Device Fingerprint
 * - Device accessed User Account
 * - IP belongs to ASN
 * - Multiple IPs in similar time window
 */

const attackGraphRelationshipSchema = new mongoose.Schema({
  sourceEntity: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AttackGraphEntity',
    required: true,
    index: true
  },
  targetEntity: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AttackGraphEntity',
    required: true,
    index: true
  },
  
  relationshipType: {
    type: String,
    enum: [
      'IP_USED_DEVICE',
      'DEVICE_ACCESSED_USER',
      'IP_IN_ASN',
      'IP_IN_LOCATION',
      'DEVICE_USED_USER_AGENT',
      'SESSION_FROM_IP',
      'SESSION_USES_DEVICE',
      'SAME_TIME_WINDOW',
      'SIMILAR_FAILURE_PATTERN',
      'SHARED_TARGET_USER',
      'IP_RANGE_CONTAINS_IP',
      'COORDINATED_TIMING'
    ],
    required: true,
    index: true
  },
  
  // Relationship strength/confidence
  weight: {
    type: Number,
    default: 1,
    min: 0,
    max: 1
  },
  
  // Evidence for this relationship
  evidence: [{
    securityEventId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SecurityEvent'
    },
    timestamp: Date,
    eventType: String,
    details: mongoose.Schema.Types.Mixed
  }],
  
  // Timing analysis
  timing: {
    firstObserved: {
      type: Date,
      default: Date.now
    },
    lastObserved: {
      type: Date,
      default: Date.now
    },
    observationCount: {
      type: Number,
      default: 1
    },
    timeDelta: Number, // milliseconds between observations
    temporalProximity: Number // 0-1 score of how close in time events are
  },
  
  // Pattern analysis
  pattern: {
    isSequential: Boolean, // Events happen in sequence
    isConcurrent: Boolean, // Events happen simultaneously
    frequencyPerHour: Number,
    isAnomalous: Boolean,
    burstDetected: Boolean // Rapid succession of events
  },
  
  // Associated incident
  incidentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SecurityIncident',
    index: true
  },
  
  // Connected component tracking
  connectedComponentId: {
    type: mongoose.Schema.Types.ObjectId,
    index: true
  },
  
  // Risk contribution
  riskContribution: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  
  // Metadata
  metadata: {
    distance: Number, // geographic distance in km
    velocityRequired: Number, // speed needed for travel (impossible travel detection)
    sharedAttributes: [String], // Common attributes between entities
    divergenceScore: Number // How different the entities are
  }
}, {
  timestamps: true,
  indexes: [
    { sourceEntity: 1, targetEntity: 1, relationshipType: 1 },
    { connectedComponentId: 1, riskContribution: -1 },
    { incidentId: 1, 'timing.lastObserved': -1 }
  ]
});

// Static methods
attackGraphRelationshipSchema.statics = {
  /**
   * Find or create a relationship
   */
  async findOrCreate(relationshipData) {
    const { sourceEntity, targetEntity, relationshipType } = relationshipData;
    
    let relationship = await this.findOne({
      sourceEntity,
      targetEntity,
      relationshipType
    });
    
    if (!relationship) {
      relationship = await this.create(relationshipData);
    } else {
      relationship.timing.lastObserved = new Date();
      relationship.timing.observationCount += 1;
      
      // Update weight based on repeated observations
      relationship.weight = Math.min(1, relationship.weight + 0.1);
      
      await relationship.save();
    }
    
    return relationship;
  },
  
  /**
   * Get relationships for an entity
   */
  async getEntityRelationships(entityId, direction = 'both') {
    const query = {};
    
    if (direction === 'outgoing' || direction === 'both') {
      const outgoing = await this.find({ sourceEntity: entityId })
        .populate('targetEntity')
        .sort({ weight: -1, 'timing.lastObserved': -1 });
      
      if (direction === 'outgoing') return outgoing;
      
      const incoming = await this.find({ targetEntity: entityId })
        .populate('sourceEntity')
        .sort({ weight: -1, 'timing.lastObserved': -1 });
      
      return { outgoing, incoming };
    } else {
      return await this.find({ targetEntity: entityId })
        .populate('sourceEntity')
        .sort({ weight: -1, 'timing.lastObserved': -1 });
    }
  },
  
  /**
   * Find connected components (graph clustering)
   */
  async findConnectedComponent(entityId, maxDepth = 3) {
    const visited = new Set();
    const component = [];
    const queue = [{ entityId, depth: 0 }];
    
    while (queue.length > 0) {
      const { entityId: currentId, depth } = queue.shift();
      
      if (visited.has(currentId.toString()) || depth > maxDepth) continue;
      
      visited.add(currentId.toString());
      component.push(currentId);
      
      // Get all relationships
      const relationships = await this.find({
        $or: [
          { sourceEntity: currentId },
          { targetEntity: currentId }
        ]
      });
      
      for (const rel of relationships) {
        const nextId = rel.sourceEntity.equals(currentId) 
          ? rel.targetEntity 
          : rel.sourceEntity;
        
        if (!visited.has(nextId.toString())) {
          queue.push({ entityId: nextId, depth: depth + 1 });
        }
      }
    }
    
    return component;
  },
  
  /**
   * Get high-risk relationship clusters
   */
  async getHighRiskClusters(minClusterSize = 3, minAvgRiskScore = 60) {
    // This would typically use graph algorithms - simplified version here
    const highRiskRelationships = await this.find({
      riskContribution: { $gte: 50 }
    })
    .populate('sourceEntity targetEntity')
    .sort({ riskContribution: -1 })
    .limit(100);
    
    return highRiskRelationships;
  }
};

// Instance methods
attackGraphRelationshipSchema.methods = {
  /**
   * Add evidence to this relationship
   */
  async addEvidence(securityEventId, eventType, details) {
    this.evidence.push({
      securityEventId,
      timestamp: new Date(),
      eventType,
      details
    });
    
    this.timing.observationCount += 1;
    this.timing.lastObserved = new Date();
    
    await this.save();
  },
  
  /**
   * Calculate and update risk contribution
   */
  async calculateRiskContribution(sourceRisk, targetRisk) {
    // Risk contribution is based on:
    // 1. Risk of connected entities
    // 2. Relationship weight (strength)
    // 3. Pattern anomalies
    
    const baseRisk = (sourceRisk + targetRisk) / 2;
    const weightMultiplier = this.weight;
    const patternMultiplier = this.pattern.isAnomalous ? 1.5 : 1;
    const burstMultiplier = this.pattern.burstDetected ? 1.3 : 1;
    
    this.riskContribution = Math.min(100, 
      baseRisk * weightMultiplier * patternMultiplier * burstMultiplier
    );
    
    await this.save();
    return this.riskContribution;
  }
};

module.exports = mongoose.model('AttackGraphRelationship', attackGraphRelationshipSchema);
