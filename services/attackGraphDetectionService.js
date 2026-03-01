const AttackGraphEntity = require('../models/AttackGraphEntity');
const AttackGraphRelationship = require('../models/AttackGraphRelationship');
const SecurityIncident = require('../models/SecurityIncident');
const SecurityEvent = require('../models/SecurityEvent');
const geolib = require('geolib');
const dns = require('dns').promises;

/**
 * Attack Graph Detection Service
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Implements graph-based detection to identify coordinated account takeover campaigns
 * Features:
 * - Entity and relationship tracking
 * - Connected component analysis
 * - Low-and-slow vs. burst attack detection
 * - Incident grouping with evidence chains
 * - Analyst reasoning ("why clustered")
 */

class AttackGraphDetectionService {
  constructor() {
    // Configuration
    this.config = {
      // Time windows for analysis
      lowAndSlowWindowMs: 24 * 60 * 60 * 1000, // 24 hours
      burstWindowMs: 5 * 60 * 1000, // 5 minutes
      
      // Thresholds
      minEventsForIncident: 3,
      minEntitiesForCampaign: 2,
      minConfidenceScore: 50,
      
      // Graph analysis
      maxGraphDepth: 4,
      minClusterSize: 2,
      
      // Risk scoring
      ipReuseWeight: 0.3,
      deviceReuseWeight: 0.4,
      timingCorrelationWeight: 0.3,
      
      // Attack pattern thresholds
      burstThreshold: 10, // events per 5 minutes
      lowAndSlowThreshold: 50, // events per 24 hours
      distributedIpThreshold: 5, // unique IPs for distributed attack
      
      // Impossible travel
      impossibleTravelSpeedKmh: 900 // ~speed of commercial flight
    };
    
    // Cache for ASN lookups
    this.asnCache = new Map();
  }
  
  /**
   * Process a security event and update the attack graph
   */
  async processSecurityEvent(securityEvent) {
    try {
      // Extract entities from the event
      const entities = await this.extractEntities(securityEvent);
      
      // Create or update entities in the graph
      const graphEntities = await Promise.all(
        entities.map(entity => this.upsertEntity(entity, securityEvent))
      );
      
      // Create relationships between entities
      const relationships = await this.createRelationships(graphEntities, securityEvent);
      
      // Analyze for attack patterns
      await this.analyzeAttackPatterns(graphEntities, relationships, securityEvent);
      
      return {
        entities: graphEntities,
        relationships,
        processed: true
      };
    } catch (error) {
      console.error('Error processing security event:', error);
      throw error;
    }
  }
  
  /**
   * Extract entities from a security event
   */
  async extractEntities(securityEvent) {
    const entities = [];
    
    // IP Address entity
    if (securityEvent.ipAddress) {
      entities.push({
        entityType: 'IP',
        entityValue: securityEvent.ipAddress,
        metadata: {
          ipVersion: securityEvent.ipAddress.includes(':') ? 6 : 4
        }
      });
      
      // ASN entity (if we can determine it)
      const asn = await this.getASN(securityEvent.ipAddress);
      if (asn) {
        entities.push({
          entityType: 'ASN',
          entityValue: asn.number.toString(),
          metadata: {
            asnNumber: asn.number,
            organization: asn.organization
          }
        });
      }
    }
    
    // Device Fingerprint entity
    if (securityEvent.deviceFingerprint) {
      entities.push({
        entityType: 'DEVICE_FINGERPRINT',
        entityValue: securityEvent.deviceFingerprint,
        metadata: {
          deviceInfo: {
            userAgent: securityEvent.userAgent
          }
        }
      });
    }
    
    // User Agent entity
    if (securityEvent.userAgent) {
      entities.push({
        entityType: 'USER_AGENT',
        entityValue: securityEvent.userAgent,
        metadata: this.parseUserAgent(securityEvent.userAgent)
      });
    }
    
    // Location entity
    if (securityEvent.location && securityEvent.location.country) {
      const locationKey = `${securityEvent.location.country}:${securityEvent.location.city || 'UNKNOWN'}`;
      entities.push({
        entityType: 'LOCATION',
        entityValue: locationKey,
        metadata: {
          country: securityEvent.location.country,
          city: securityEvent.location.city,
          latitude: securityEvent.location.latitude,
          longitude: securityEvent.location.longitude
        }
      });
    }
    
    // User entity
    if (securityEvent.userId) {
      entities.push({
        entityType: 'USER',
        entityValue: securityEvent.userId.toString(),
        metadata: {
          userId: securityEvent.userId
        }
      });
    }
    
    // Session entity (if applicable)
    if (securityEvent.details?.sessionId) {
      entities.push({
        entityType: 'SESSION',
        entityValue: securityEvent.details.sessionId,
        metadata: {
          sessionId: securityEvent.details.sessionId,
          userId: securityEvent.userId
        }
      });
    }
    
    return entities;
  }
  
  /**
   * Create or update an entity in the graph
   */
  async upsertEntity(entityData, securityEvent) {
    const entity = await AttackGraphEntity.findOrCreate(entityData);
    
    // Update statistics
    if (securityEvent.eventType.includes('FAILURE') || 
        securityEvent.eventType.includes('SUSPICIOUS')) {
      entity.stats.failedLoginAttempts += 1;
    } else if (securityEvent.eventType.includes('SUCCESS')) {
      entity.stats.successfulLogins += 1;
    }
    
    // Update time window
    if (!entity.stats.timeWindowStart || securityEvent.createdAt < entity.stats.timeWindowStart) {
      entity.stats.timeWindowStart = securityEvent.createdAt;
    }
    if (!entity.stats.timeWindowEnd || securityEvent.createdAt > entity.stats.timeWindowEnd) {
      entity.stats.timeWindowEnd = securityEvent.createdAt;
    }
    
    // Calculate event velocity
    if (entity.stats.timeWindowStart && entity.stats.timeWindowEnd) {
      const durationHours = (entity.stats.timeWindowEnd - entity.stats.timeWindowStart) / (1000 * 60 * 60);
      entity.stats.eventVelocity = durationHours > 0 ? entity.stats.totalEvents / durationHours : 0;
    }
    
    // Enrich with threat intelligence (simplified - would call external APIs)
    if (entityData.entityType === 'IP') {
      await this.enrichIpEntity(entity);
    }
    
    await entity.save();
    return entity;
  }
  
  /**
   * Create relationships between entities
   */
  async createRelationships(entities, securityEvent) {
    const relationships = [];
    
    // Find entity pairs and create relationships
    for (let i = 0; i < entities.length; i++) {
      for (let j = i + 1; j < entities.length; j++) {
        const source = entities[i];
        const target = entities[j];
        
        // Determine relationship type
        const relType = this.determineRelationshipType(source, target);
        if (!relType) continue;
        
        // Create or update relationship
        const relationship = await AttackGraphRelationship.findOrCreate({
          sourceEntity: source._id,
          targetEntity: target._id,
          relationshipType: relType,
          timing: {
            firstObserved: securityEvent.createdAt,
            lastObserved: securityEvent.createdAt
          }
        });
        
        // Add evidence
        await relationship.addEvidence(
          securityEvent._id,
          securityEvent.eventType,
          {
            riskScore: securityEvent.riskScore,
            severity: securityEvent.severity
          }
        );
        
        // Analyze timing patterns
        await this.analyzeRelationshipTiming(relationship, securityEvent);
        
        relationships.push(relationship);
      }
    }
    
    return relationships;
  }
  
  /**
   * Determine relationship type between two entities
   */
  determineRelationshipType(sourceEntity, targetEntity) {
    const typeMap = {
      'IP:DEVICE_FINGERPRINT': 'IP_USED_DEVICE',
      'IP:ASN': 'IP_IN_ASN',
      'IP:LOCATION': 'IP_IN_LOCATION',
      'DEVICE_FINGERPRINT:USER': 'DEVICE_ACCESSED_USER',
      'DEVICE_FINGERPRINT:USER_AGENT': 'DEVICE_USED_USER_AGENT',
      'IP:SESSION': 'SESSION_FROM_IP',
      'DEVICE_FINGERPRINT:SESSION': 'SESSION_USES_DEVICE',
      'USER:SESSION': 'SESSION_FROM_IP'
    };
    
    const key = `${sourceEntity.entityType}:${targetEntity.entityType}`;
    const reverseKey = `${targetEntity.entityType}:${sourceEntity.entityType}`;
    
    return typeMap[key] || typeMap[reverseKey];
  }
  
  /**
   * Analyze timing patterns in relationships
   */
  async analyzeRelationshipTiming(relationship, currentEvent) {
    const evidence = relationship.evidence;
    if (evidence.length < 2) return;
    
    // Calculate time deltas
    const timestamps = evidence.map(e => e.timestamp).sort((a, b) => a - b);
    const deltas = [];
    for (let i = 1; i < timestamps.length; i++) {
      deltas.push(timestamps[i] - timestamps[i - 1]);
    }
    
    const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    relationship.timing.timeDelta = avgDelta;
    
    // Detect burst pattern (rapid succession)
    const recentEvents = evidence.filter(e => 
      (Date.now() - e.timestamp) < this.config.burstWindowMs
    );
    
    if (recentEvents.length >= this.config.burstThreshold) {
      relationship.pattern.burstDetected = true;
      relationship.pattern.isConcurrent = true;
    }
    
    // Calculate frequency
    const timeSpanHours = (timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60 * 60);
    relationship.pattern.frequencyPerHour = timeSpanHours > 0 ? evidence.length / timeSpanHours : 0;
    
    // Detect anomalous frequency
    if (relationship.pattern.frequencyPerHour > 10) { // More than 10 per hour
      relationship.pattern.isAnomalous = true;
    }
    
    await relationship.save();
  }
  
  /**
   * Analyze attack patterns across the graph
   */
  async analyzeAttackPatterns(entities, relationships, securityEvent) {
    // Get recent events for pattern analysis
    const recentEvents = await SecurityEvent.find({
      createdAt: {
        $gte: new Date(Date.now() - this.config.lowAndSlowWindowMs)
      },
      eventType: {
        $in: [
          'LOGIN_ATTEMPT',
          '2FA_FAILURE',
          'SUSPICIOUS_LOGIN',
          'BRUTE_FORCE_ATTEMPT'
        ]
      }
    }).sort({ createdAt: 1 });
    
    // Detect distributed credential stuffing
    await this.detectDistributedCredentialStuffing(recentEvents);
    
    // Detect burst attacks
    await this.detectBurstAttacks(recentEvents);
    
    // Detect low-and-slow attacks
    await this.detectLowAndSlowAttacks(recentEvents);
    
    // Detect coordinated attacks via graph clustering
    await this.detectCoordinatedAttacks();
  }
  
  /**
   * Detect distributed credential stuffing attacks
   */
  async detectDistributedCredentialStuffing(events) {
    // Group by user
    const userGroups = {};
    for (const event of events) {
      const userId = event.userId.toString();
      if (!userGroups[userId]) {
        userGroups[userId] = [];
      }
      userGroups[userId].push(event);
    }
    
    // Analyze each user's events
    for (const [userId, userEvents] of Object.entries(userGroups)) {
      if (userEvents.length < this.config.minEventsForIncident) continue;
      
      // Count unique IPs
      const uniqueIps = new Set(userEvents.map(e => e.ipAddress));
      
      // If same user targeted from many IPs - distributed attack
      if (uniqueIps.size >= this.config.distributedIpThreshold) {
        await this.createOrUpdateIncident({
          userId,
          events: userEvents,
          incidentType: 'DISTRIBUTED_CREDENTIAL_STUFFING',
          severity: 'high',
          reason: `Same user targeted from ${uniqueIps.size} different IPs`,
          attackVelocity: 'LOW_AND_SLOW'
        });
      }
    }
  }
  
  /**
   * Detect rapid burst attacks
   */
  async detectBurstAttacks(events) {
    // Group events in burst window
    const now = Date.now();
    const burstEvents = events.filter(e => 
      (now - e.createdAt) < this.config.burstWindowMs
    );
    
    if (burstEvents.length >= this.config.burstThreshold) {
      // Check if from coordinated sources
      const uniqueIps = new Set(burstEvents.map(e => e.ipAddress));
      const uniqueDevices = new Set(burstEvents.map(e => e.deviceFingerprint).filter(Boolean));
      
      await this.createOrUpdateIncident({
        events: burstEvents,
        incidentType: 'RAPID_BURST_ATTACK',
        severity: 'critical',
        reason: `${burstEvents.length} events in ${this.config.burstWindowMs / 1000}s from ${uniqueIps.size} IPs`,
        attackVelocity: 'BURST'
      });
    }
  }
  
  /**
   * Detect low-and-slow attacks
   */
  async detectLowAndSlowAttacks(events) {
    // Analyze events over 24-hour window
    const ipGroups = {};
    
    for (const event of events) {
      if (!ipGroups[event.ipAddress]) {
        ipGroups[event.ipAddress] = [];
      }
      ipGroups[event.ipAddress].push(event);
    }
    
    // Find IPs with sustained activity
    for (const [ip, ipEvents] of Object.entries(ipGroups)) {
      if (ipEvents.length < this.config.lowAndSlowThreshold) continue;
      
      // Check if spread over time (not burst)
      const timeSpan = ipEvents[ipEvents.length - 1].createdAt - ipEvents[0].createdAt;
      const eventsPerHour = (ipEvents.length / (timeSpan / (1000 * 60 * 60)));
      
      // Low and slow: sustained but not burst
      if (eventsPerHour < 20 && eventsPerHour > 2) {
        const uniqueUsers = new Set(ipEvents.map(e => e.userId.toString()));
        
        await this.createOrUpdateIncident({
          events: ipEvents,
          incidentType: 'LOW_AND_SLOW_ABUSE',
          severity: 'medium',
          reason: `IP ${ip} with ${ipEvents.length} events targeting ${uniqueUsers.size} users over ${Math.round(timeSpan / (1000 * 60 * 60))} hours`,
          attackVelocity: 'LOW_AND_SLOW'
        });
      }
    }
  }
  
  /**
   * Detect coordinated attacks via graph clustering
   */
  async detectCoordinatedAttacks() {
    // Find high-risk entities
    const highRiskEntities = await AttackGraphEntity.find({
      riskScore: { $gte: 60 },
      lastSeen: {
        $gte: new Date(Date.now() - this.config.lowAndSlowWindowMs)
      }
    }).limit(100);
    
    const processedComponents = new Set();
    
    for (const entity of highRiskEntities) {
      // Skip if already processed
      if (entity.graphMetrics.connectedComponentId && 
          processedComponents.has(entity.graphMetrics.connectedComponentId.toString())) {
        continue;
      }
      
      // Find connected component
      const component = await AttackGraphRelationship.findConnectedComponent(
        entity._id,
        this.config.maxGraphDepth
      );
      
      if (component.length >= this.config.minClusterSize) {
        // Analyze this cluster
        await this.analyzeCluster(component);
        
        // Mark as processed
        const componentId = new mongoose.Types.ObjectId();
        processedComponents.add(componentId.toString());
        
        // Update all entities in component
        await AttackGraphEntity.updateMany(
          { _id: { $in: component } },
          { 
            $set: { 
              'graphMetrics.connectedComponentId': componentId,
              'graphMetrics.componentSize': component.length
            }
          }
        );
      }
    }
  }
  
  /**
   * Analyze a cluster of connected entities
   */
  async analyzeCluster(entityIds) {
    // Load full entities
    const entities = await AttackGraphEntity.find({
      _id: { $in: entityIds }
    });
    
    // Load relationships
    const relationships = await AttackGraphRelationship.find({
      $or: [
        { sourceEntity: { $in: entityIds } },
        { targetEntity: { $in: entityIds } }
      ]
    });
    
    // Calculate cluster metrics
    const metrics = this.calculateClusterMetrics(entities, relationships);
    
    // Score the cluster
    const clusterScore = this.scoreCluster(entities, relationships, metrics);
    
    // If high confidence, create incident
    if (clusterScore.confidenceScore >= this.config.minConfidenceScore) {
      // Get associated security events
      const userIds = entities
        .filter(e => e.entityType === 'USER')
        .map(e => e.metadata.userId);
      
      const ipAddresses = entities
        .filter(e => e.entityType === 'IP')
        .map(e => e.entityValue);
      
      const events = await SecurityEvent.find({
        $or: [
          { userId: { $in: userIds } },
          { ipAddress: { $in: ipAddresses } }
        ],
        createdAt: {
          $gte: new Date(Date.now() - this.config.lowAndSlowWindowMs)
        }
      });
      
      await this.createOrUpdateIncident({
        events,
        entities: entityIds,
        relationships: relationships.map(r => r._id),
        incidentType: 'COORDINATED_ATTACK',
        severity: clusterScore.severity,
        confidenceScore: clusterScore.confidenceScore,
        reason: clusterScore.reasoning,
        clusteringReasoning: clusterScore.clusteringReasoning,
        graphMetrics: metrics,
        attackVelocity: metrics.attackVelocity
      });
    }
  }
  
  /**
   * Calculate cluster metrics
   */
  calculateClusterMetrics(entities, relationships) {
    const uniqueIPs = entities.filter(e => e.entityType === 'IP').length;
    const uniqueDevices = entities.filter(e => e.entityType === 'DEVICE_FINGERPRINT').length;
    const uniqueUsers = entities.filter(e => e.entityType === 'USER').length;
    const uniqueLocations = entities.filter(e => e.entityType === 'LOCATION').length;
    
    // Calculate graph density
    const possibleEdges = (entities.length * (entities.length - 1)) / 2;
    const graphDensity = possibleEdges > 0 ? relationships.length / possibleEdges : 0;
    
    // Calculate average risk score
    const avgRiskScore = entities.reduce((sum, e) => sum + e.riskScore, 0) / entities.length;
    
    // Calculate time span
    const timestamps = [];
    entities.forEach(e => {
      if (e.stats.timeWindowStart) timestamps.push(e.stats.timeWindowStart);
      if (e.stats.timeWindowEnd) timestamps.push(e.stats.timeWindowEnd);
    });
    
    timestamps.sort((a, b) => a - b);
    const attackDurationMs = timestamps.length > 0 
      ? timestamps[timestamps.length - 1] - timestamps[0] 
      : 0;
    
    // Determine attack velocity
    const totalEvents = entities.reduce((sum, e) => sum + e.stats.totalEvents, 0);
    const durationHours = attackDurationMs / (1000 * 60 * 60);
    const eventsPerHour = durationHours > 0 ? totalEvents / durationHours : 0;
    
    let attackVelocity = 'SUSTAINED';
    if (eventsPerHour > 50) {
      attackVelocity = 'BURST';
    } else if (eventsPerHour < 10) {
      attackVelocity = 'LOW_AND_SLOW';
    }
    
    return {
      componentSize: entities.length,
      uniqueIPs,
      uniqueDevices,
      uniqueUsers,
      uniqueLocations,
      totalRelationships: relationships.length,
      graphDensity,
      avgRiskScore,
      attackDurationMs,
      eventsPerHour,
      attackVelocity,
      totalEvents
    };
  }
  
  /**
   * Score a cluster for campaign probability
   */
  scoreCluster(entities, relationships, metrics) {
    let confidenceScore = 0;
    const reasoning = [];
    const clusteringReasoning = [];
    
    // Factor 1: Multiple IPs targeting same users (30 points)
    if (metrics.uniqueIPs >= 3 && metrics.uniqueUsers >= 1) {
      const weight = Math.min(30, metrics.uniqueIPs * 5);
      confidenceScore += weight;
      reasoning.push(`${metrics.uniqueIPs} different IPs targeting ${metrics.uniqueUsers} users`);
      clusteringReasoning.push({
        reason: 'Multiple source IPs targeting same user accounts',
        weight: weight / 100,
        supportingEvidence: [`${metrics.uniqueIPs} unique IPs`, `${metrics.uniqueUsers} targeted users`]
      });
    }
    
    // Factor 2: Shared device fingerprints (25 points)
    if (metrics.uniqueDevices >= 2) {
      const weight = Math.min(25, metrics.uniqueDevices * 8);
      confidenceScore += weight;
      reasoning.push(`${metrics.uniqueDevices} compromised or spoofed devices`);
      clusteringReasoning.push({
        reason: 'Multiple devices involved in coordinated activity',
        weight: weight / 100,
        supportingEvidence: [`${metrics.uniqueDevices} unique devices`]
      });
    }
    
    // Factor 3: High graph density (20 points)
    if (metrics.graphDensity > 0.5) {
      const weight = Math.min(20, metrics.graphDensity * 40);
      confidenceScore += weight;
      reasoning.push(`High interconnection (${(metrics.graphDensity * 100).toFixed(1)}% density)`);
      clusteringReasoning.push({
        reason: 'Entities are highly interconnected',
        weight: weight / 100,
        supportingEvidence: [`Graph density: ${(metrics.graphDensity * 100).toFixed(1)}%`]
      });
    }
    
    // Factor 4: Average risk score of entities (15 points)
    if (metrics.avgRiskScore > 50) {
      const weight = Math.min(15, (metrics.avgRiskScore - 50) / 50 * 15);
      confidenceScore += weight;
      reasoning.push(`High average risk score (${metrics.avgRiskScore.toFixed(1)})`);
      clusteringReasoning.push({
        reason: 'Entities have elevated risk scores',
        weight: weight / 100,
        supportingEvidence: [`Average risk: ${metrics.avgRiskScore.toFixed(1)}/100`]
      });
    }
    
    // Factor 5: Temporal correlation (10 points)
    const isBurst = metrics.attackVelocity === 'BURST';
    const isLowAndSlow = metrics.attackVelocity === 'LOW_AND_SLOW';
    
    if (isBurst || isLowAndSlow) {
      const weight = isBurst ? 10 : 8;
      confidenceScore += weight;
      reasoning.push(`${metrics.attackVelocity} attack pattern detected`);
      clusteringReasoning.push({
        reason: `Temporal pattern indicates ${metrics.attackVelocity} attack`,
        weight: weight / 100,
        supportingEvidence: [
          `Events per hour: ${metrics.eventsPerHour.toFixed(1)}`,
          `Duration: ${(metrics.attackDurationMs / (1000 * 60 * 60)).toFixed(1)} hours`
        ]
      });
    }
    
    // Determine severity
    let severity = 'low';
    if (confidenceScore >= 80) severity = 'critical';
    else if (confidenceScore >= 60) severity = 'high';
    else if (confidenceScore >= 40) severity = 'medium';
    
    return {
      confidenceScore: Math.min(100, confidenceScore),
      severity,
      reasoning: reasoning.join('; '),
      clusteringReasoning
    };
  }
  
  /**
   * Create or update an incident
   */
  async createOrUpdateIncident(incidentData) {
    const {
      events,
      entities,
      relationships,
      incidentType,
      severity,
      confidenceScore = 70,
      reason,
      attackVelocity,
      clusteringReasoning,
      graphMetrics
    } = incidentData;
    
    // Check if similar incident already exists
    const recentIncident = await SecurityIncident.findOne({
      incidentType,
      status: { $in: ['NEW', 'INVESTIGATING', 'CONFIRMED'] },
      createdAt: {
        $gte: new Date(Date.now() - this.config.lowAndSlowWindowMs)
      }
    }).sort({ createdAt: -1 });
    
    if (recentIncident) {
      // Update existing incident
      if (events) {
        const newEventIds = events.map(e => e._id);
        recentIncident.evidence.securityEvents = [
          ...new Set([...recentIncident.evidence.securityEvents, ...newEventIds])
        ];
      }
      
      if (entities) {
        recentIncident.evidence.entities = [
          ...new Set([...recentIncident.evidence.entities, ...entities])
        ];
      }
      
      if (relationships) {
        recentIncident.evidence.relationships = [
          ...new Set([...recentIncident.evidence.relationships, ...relationships])
        ];
      }
      
      // Update metrics
      recentIncident.campaignMetrics.totalEvents = recentIncident.evidence.securityEvents.length;
      recentIncident.campaignMetrics.totalEntities = recentIncident.evidence.entities.length;
      recentIncident.campaignMetrics.totalRelationships = recentIncident.evidence.relationships.length;
      
      if (attackVelocity) {
        recentIncident.campaignMetrics.attackVelocity = attackVelocity;
      }
      
      // Update confidence if higher
      if (confidenceScore > recentIncident.confidenceScore) {
        recentIncident.confidenceScore = confidenceScore;
      }
      
      await recentIncident.save();
      return recentIncident;
    }
    
    // Create new incident
    const campaignMetrics = {
      totalEvents: events ? events.length : 0,
      totalEntities: entities ? entities.length : 0,
      totalRelationships: relationships ? relationships.length : 0,
      attackVelocity: attackVelocity || 'SUSTAINED'
    };
    
    if (events && events.length > 0) {
      const uniqueIPs = new Set(events.map(e => e.ipAddress));
      const uniqueDevices = new Set(events.map(e => e.deviceFingerprint).filter(Boolean));
      const uniqueUsers = new Set(events.map(e => e.userId.toString()));
      const uniqueCountries = new Set(events.map(e => e.location?.country).filter(Boolean));
      
      campaignMetrics.uniqueIPs = uniqueIPs.size;
      campaignMetrics.uniqueDevices = uniqueDevices.size;
      campaignMetrics.uniqueUsers = uniqueUsers.size;
      campaignMetrics.geographicSpread = uniqueCountries.size;
      campaignMetrics.targetedAccounts = Array.from(uniqueUsers);
      
      const timeSpan = events[events.length - 1].createdAt - events[0].createdAt;
      campaignMetrics.attackDurationMs = timeSpan;
      campaignMetrics.eventsPerHour = (events.length / (timeSpan / (1000 * 60 * 60))) || 0;
      campaignMetrics.peakActivityTime = events[Math.floor(events.length / 2)].createdAt;
    }
    
    const incident = await SecurityIncident.create({
      title: `${incidentType} - ${reason}`,
      description: reason,
      incidentType,
      severity,
      confidenceScore,
      campaignMetrics,
      'evidence.securityEvents': events ? events.map(e => e._id) : [],
      'evidence.entities': entities || [],
      'evidence.relationships': relationships || [],
      graphAnalysis: graphMetrics,
      clusteringReasoning: clusteringReasoning || [],
      detectionVersion: '1.0.0'
    });
    
    // Update entities to reference this incident
    if (entities) {
      await AttackGraphEntity.updateMany(
        { _id: { $in: entities } },
        { $addToSet: { incidents: incident._id } }
      );
    }
    
    return incident;
  }
  
  /**
   * Get ASN for an IP address
   */
  async getASN(ipAddress) {
    // Check cache
    if (this.asnCache.has(ipAddress)) {
      return this.asnCache.get(ipAddress);
    }
    
    try {
      // This is a simplified version - in production, use proper ASN lookup service
      // For now, return null
      // In production: use services like ipapi.co, ipinfo.io, or MaxMind
      return null;
    } catch (error) {
      console.error('ASN lookup error:', error);
      return null;
    }
  }
  
  /**
   * Parse User Agent string
   */
  parseUserAgent(userAgent) {
    // Simplified parser - in production use ua-parser-js or similar
    const metadata = {
      browser: 'Unknown',
      os: 'Unknown'
    };
    
    if (userAgent.includes('Chrome')) metadata.browser = 'Chrome';
    else if (userAgent.includes('Firefox')) metadata.browser = 'Firefox';
    else if (userAgent.includes('Safari')) metadata.browser = 'Safari';
    else if (userAgent.includes('Edge')) metadata.browser = 'Edge';
    
    if (userAgent.includes('Windows')) metadata.os = 'Windows';
    else if (userAgent.includes('Mac')) metadata.os = 'MacOS';
    else if (userAgent.includes('Linux')) metadata.os = 'Linux';
    else if (userAgent.includes('Android')) metadata.os = 'Android';
    else if (userAgent.includes('iOS')) metadata.os = 'iOS';
    
    return metadata;
  }
  
  /**
   * Enrich IP entity with threat intelligence
   */
  async enrichIpEntity(entity) {
    // This would call external threat intelligence APIs
    // Simplified version here
    entity.enrichmentData = entity.enrichmentData || {};
    
    // In production, check against:
    // - AbuseIPDB
    // - VirusTotal
    // - IPVoid
    // - Tor exit node lists
    // - VPN/Proxy databases
    
    return entity;
  }
  
  /**
   * Run full graph analysis (batch job)
   */
  async runFullGraphAnalysis() {
    console.log('Starting full graph analysis...');
    
    const startTime = Date.now();
    
    // Re-analyze all recent events
    const recentEvents = await SecurityEvent.find({
      createdAt: {
        $gte: new Date(Date.now() - this.config.lowAndSlowWindowMs)
      }
    }).sort({ createdAt: 1 });
    
    console.log(`Analyzing ${recentEvents.length} recent events...`);
    
    // Process in batches
    const batchSize = 100;
    for (let i = 0; i < recentEvents.length; i += batchSize) {
      const batch = recentEvents.slice(i, i + batchSize);
      await Promise.all(batch.map(event => this.processSecurityEvent(event)));
    }
    
    // Detect coordinated attacks
    await this.detectCoordinatedAttacks();
    
    const duration = Date.now() - startTime;
    console.log(`Full graph analysis completed in ${duration}ms`);
    
    return {
      eventsAnalyzed: recentEvents.length,
      durationMs: duration
    };
  }
}

module.exports = new AttackGraphDetectionService();
