const mongoose = require('mongoose');

const riskFactorSchema = new mongoose.Schema({
  key: { type: String, required: true },
  description: { type: String },
  value: { type: Number, default: 0 },
  weight: { type: Number, default: 0 },
  contribution: { type: Number, default: 0 },
  source: { type: String, enum: ['rule', 'ml', 'calibration'], default: 'rule' }
}, { _id: false });

const riskDecisionLogSchema = new mongoose.Schema({
  tenantId: { type: String, required: true, index: true, default: 'global' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sessionId: { type: String },
  requestId: { type: String },
  policyVersion: { type: Number, required: true },
  modelVersion: { type: String, required: true },
  policyChecksum: { type: String, required: true },
  reproducibilityKey: { type: String, required: true, index: true },
  inputHash: { type: String, required: true },
  features: { type: mongoose.Schema.Types.Mixed, default: {} },
  scores: {
    ruleScore: { type: Number, default: 0 },
    mlScore: { type: Number, default: 0 },
    calibratedScore: { type: Number, default: 0 },
    finalRiskScore: { type: Number, default: 0 }
  },
  thresholds: {
    suspicious: { type: Number, default: 65 },
    challenge: { type: Number, default: 82 },
    block: { type: Number, default: 95 }
  },
  action: {
    type: String,
    enum: ['allowed', 'monitor', 'challenged', 'blocked'],
    default: 'allowed'
  },
  explainability: {
    factors: { type: [riskFactorSchema], default: [] },
    topFactors: { type: [riskFactorSchema], default: [] }
  },
  meta: {
    ipAddress: String,
    userAgent: String,
    location: mongoose.Schema.Types.Mixed,
    deviceFingerprint: String
  }
}, {
  timestamps: true
});

riskDecisionLogSchema.index({ tenantId: 1, createdAt: -1 });
riskDecisionLogSchema.index({ userId: 1, createdAt: -1 });
riskDecisionLogSchema.index({ tenantId: 1, policyVersion: 1, createdAt: -1 });

module.exports = mongoose.model('RiskDecisionLog', riskDecisionLogSchema);
