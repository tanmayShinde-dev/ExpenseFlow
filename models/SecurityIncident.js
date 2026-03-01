const mongoose = require('mongoose');

/**
 * Security Incident Model
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Groups related security events into incidents
 * Represents coordinated attack campaigns
 */

const securityIncidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  
  title: {
    type: String,
    required: true
  },
  
  description: String,
  
  // Incident classification
  incidentType: {
    type: String,
    enum: [
      'CREDENTIAL_STUFFING',
      'DISTRIBUTED_CREDENTIAL_STUFFING',
      'BRUTE_FORCE_CAMPAIGN',
      'ACCOUNT_TAKEOVER_CAMPAIGN',
      'COORDINATED_ATTACK',
      'LOW_AND_SLOW_ABUSE',
      'RAPID_BURST_ATTACK',
      'IMPOSSIBLE_TRAVEL_CLUSTER',
      'DEVICE_FINGERPRINT_SPOOFING',
      'BOTNET_ACTIVITY',
      'INSIDER_THREAT',
      'PRIVILEGE_ESCALATION',
      'DATA_EXFILTRATION',
      'OTHER'
    ],
    required: true,
    index: true
  },
  
  // Severity and priority
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    required: true,
    index: true
  },
  
  priority: {
    type: Number,
    min: 1,
    max: 5,
    default: 3
  },
  
  // Status tracking
  status: {
    type: String,
    enum: ['NEW', 'INVESTIGATING', 'CONFIRMED', 'MITIGATED', 'RESOLVED', 'FALSE_POSITIVE'],
    default: 'NEW',
    index: true
  },
  
  // Confidence scoring
  confidenceScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true,
    index: true
  },
  
  // Campaign detection metrics
  campaignMetrics: {
    totalEvents: { type: Number, default: 0 },
    totalEntities: { type: Number, default: 0 },
    totalRelationships: { type: Number, default: 0 },
    uniqueIPs: { type: Number, default: 0 },
    uniqueDevices: { type: Number, default: 0 },
    uniqueUsers: { type: Number, default: 0 },
    targetedAccounts: [{ 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    }],
    compromisedAccounts: [{ 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    }],
    attackDurationMs: Number,
    eventsPerHour: Number,
    peakActivityTime: Date,
    geographicSpread: Number, // Number of unique countries/cities
    attackVelocity: String, // 'LOW_AND_SLOW', 'BURST', 'SUSTAINED'
  },
  
  // Graph analysis
  graphAnalysis: {
    connectedComponentId: mongoose.Schema.Types.ObjectId,
    componentSize: Number,
    graphDensity: Number, // How interconnected the entities are
    centralNodes: [{
      entityId: { type: mongoose.Schema.Types.ObjectId, ref: 'AttackGraphEntity' },
      centralityScore: Number,
      entityType: String,
      entityValue: String
    }],
    clusteringCoefficient: Number,
    averagePathLength: Number
  },
  
  // Attack patterns detected
  attackPatterns: [{
    patternType: String,
    confidence: Number,
    evidence: [String],
    detectedAt: { type: Date, default: Date.now }
  }],
  
  // Evidence chain
  evidence: {
    securityEvents: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SecurityEvent'
    }],
    entities: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'AttackGraphEntity'
    }],
    relationships: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'AttackGraphRelationship'
    }],
    evidenceChain: [{
      timestamp: Date,
      description: String,
      eventId: mongoose.Schema.Types.ObjectId,
      entityIds: [mongoose.Schema.Types.ObjectId],
      anomalyScore: Number
    }]
  },
  
  // Analyst tracking
  assignedTo: {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    assignedAt: Date
  },
  
  analystNotes: [{
    analyst: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    note: String,
    timestamp: { type: Date, default: Date.now },
    noteType: { 
      type: String, 
      enum: ['OBSERVATION', 'HYPOTHESIS', 'ACTION_TAKEN', 'CONCLUSION'] 
    }
  }],
  
  // Actions taken
  responseActions: [{
    actionType: {
      type: String,
      enum: [
        'BLOCKED_IP',
        'BLOCKED_IP_RANGE',
        'BLOCKED_DEVICE',
        'REVOKED_SESSION',
        'MASS_REVOKED_SESSIONS',
        'FORCED_REAUTH',
        'DISABLED_ACCOUNT',
        'ALERTED_USER',
        'ESCALATED',
        'INVESTIGATED',
        'CLEARED'
      ]
    },
    targetEntityId: mongoose.Schema.Types.ObjectId,
    targetEntityType: String,
    performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    performedAt: { type: Date, default: Date.now },
    reason: String,
    details: mongoose.Schema.Types.Mixed
  }],
  
  // "Why clustered" reasoning for analysts
  clusteringReasoning: [{
    reason: String,
    weight: Number,
    supportingEvidence: [String],
    visualizationData: mongoose.Schema.Types.Mixed
  }],
  
  // Precision/Recall tracking
  validationMetrics: {
    isTruePositive: Boolean,
    isFalsePositive: Boolean,
    validatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    validatedAt: Date,
    validationNotes: String
  },
  
  // Detection metadata
  detectedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  detectedBy: {
    type: String,
    default: 'ATTACK_GRAPH_DETECTION_SERVICE'
  },
  
  detectionVersion: String,
  
  // Time tracking
  timeToDetection: Number, // ms from first event to detection
  timeToMitigation: Number, // ms from detection to mitigation
  timeToResolution: Number, // ms from detection to resolution
  
  resolvedAt: Date,
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  resolutionNotes: String,
  
  // Related incidents
  relatedIncidents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SecurityIncident'
  }],
  
  // External tracking
  externalTicketId: String,
  externalTicketUrl: String,
  
  // Tags for categorization
  tags: [String]
}, {
  timestamps: true,
  indexes: [
    { status: 1, severity: -1, detectedAt: -1 },
    { incidentType: 1, status: 1 },
    { confidenceScore: -1, detectedAt: -1 },
    { 'campaignMetrics.attackVelocity': 1, status: 1 }
  ]
});

// Pre-save hook to generate incident ID
securityIncidentSchema.pre('save', async function(next) {
  if (this.isNew && !this.incidentId) {
    const date = new Date();
    const dateStr = date.toISOString().split('T')[0].replace(/-/g, '');
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    this.incidentId = `INC-${dateStr}-${random}`;
  }
  next();
});

// Static methods
securityIncidentSchema.statics = {
  /**
   * Create new incident from graph analysis
   */
  async createFromGraphAnalysis(analysisData) {
    const {
      incidentType,
      severity,
      confidenceScore,
      entities,
      relationships,
      events,
      graphMetrics,
      campaignMetrics,
      attackPatterns,
      clusteringReasoning
    } = analysisData;
    
    const incident = await this.create({
      title: `${incidentType} - ${new Date().toISOString()}`,
      description: `Detected ${incidentType} with ${entities.length} entities and ${relationships.length} relationships`,
      incidentType,
      severity,
      confidenceScore,
      'evidence.entities': entities,
      'evidence.relationships': relationships,
      'evidence.securityEvents': events,
      graphAnalysis: graphMetrics,
      campaignMetrics,
      attackPatterns,
      clusteringReasoning
    });
    
    return incident;
  },
  
  /**
   * Get active incidents
   */
  async getActiveIncidents(limit = 50) {
    return this.find({
      status: { $in: ['NEW', 'INVESTIGATING', 'CONFIRMED'] }
    })
    .sort({ priority: 1, severity: -1, detectedAt: -1 })
    .limit(limit)
    .populate('assignedTo.userId', 'username email');
  },
  
  /**
   * Get high-confidence incidents
   */
  async getHighConfidenceIncidents(minConfidence = 70, limit = 50) {
    return this.find({
      confidenceScore: { $gte: minConfidence },
      status: { $nin: ['RESOLVED', 'FALSE_POSITIVE'] }
    })
    .sort({ confidenceScore: -1, detectedAt: -1 })
    .limit(limit);
  },
  
  /**
   * Calculate precision/recall metrics
   */
  async calculatePrecisionRecall() {
    const validatedIncidents = await this.find({
      'validationMetrics.validatedBy': { $exists: true }
    });
    
    const truePositives = validatedIncidents.filter(i => i.validationMetrics.isTruePositive).length;
    const falsePositives = validatedIncidents.filter(i => i.validationMetrics.isFalsePositive).length;
    
    const precision = truePositives / (truePositives + falsePositives);
    
    return {
      precision: precision || 0,
      truePositives,
      falsePositives,
      totalValidated: validatedIncidents.length
    };
  }
};

// Instance methods
securityIncidentSchema.methods = {
  /**
   * Add analyst note
   */
  async addAnalystNote(analyst, note, noteType = 'OBSERVATION') {
    this.analystNotes.push({
      analyst,
      note,
      noteType,
      timestamp: new Date()
    });
    await this.save();
  },
  
  /**
   * Record response action
   */
  async recordAction(actionType, performedBy, targetEntityId, targetEntityType, reason, details = {}) {
    this.responseActions.push({
      actionType,
      targetEntityId,
      targetEntityType,
      performedBy,
      performedAt: new Date(),
      reason,
      details
    });
    await this.save();
  },
  
  /**
   * Update status
   */
  async updateStatus(newStatus, userId, notes = '') {
    this.status = newStatus;
    
    if (newStatus === 'RESOLVED') {
      this.resolvedAt = new Date();
      this.resolvedBy = userId;
      this.resolutionNotes = notes;
      this.timeToResolution = this.resolvedAt - this.detectedAt;
    }
    
    await this.save();
  },
  
  /**
   * Assign to analyst
   */
  async assignTo(userId) {
    this.assignedTo = {
      userId,
      assignedAt: new Date()
    };
    
    if (this.status === 'NEW') {
      this.status = 'INVESTIGATING';
    }
    
    await this.save();
  },
  
  /**
   * Validate incident (for precision/recall tracking)
   */
  async validate(userId, isTruePositive, notes = '') {
    this.validationMetrics = {
      isTruePositive,
      isFalsePositive: !isTruePositive,
      validatedBy: userId,
      validatedAt: new Date(),
      validationNotes: notes
    };
    
    await this.save();
  },
  
  /**
   * Get evidence summary for analyst
   */
  getEvidenceSummary() {
    return {
      totalEvents: this.evidence.securityEvents.length,
      totalEntities: this.evidence.entities.length,
      totalRelationships: this.evidence.relationships.length,
      evidenceChain: this.evidence.evidenceChain,
      clusteringReasons: this.clusteringReasoning.map(r => ({
        reason: r.reason,
        weight: r.weight
      }))
    };
  }
};

module.exports = mongoose.model('SecurityIncident', securityIncidentSchema);
