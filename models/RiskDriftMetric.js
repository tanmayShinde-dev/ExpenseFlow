const mongoose = require('mongoose');

const riskDriftMetricSchema = new mongoose.Schema({
  tenantId: { type: String, required: true, default: 'global', index: true },
  modelVersion: { type: String, required: true, default: 'ensemble-v2', index: true },
  policyVersion: { type: Number, required: true, default: 1 },
  sampleCount: { type: Number, default: 0 },
  baseline: { type: mongoose.Schema.Types.Mixed, default: {} },
  current: { type: mongoose.Schema.Types.Mixed, default: {} },
  driftScore: { type: Number, default: 0 },
  driftStatus: { type: String, enum: ['stable', 'watch', 'alert'], default: 'stable' },
  alertThreshold: { type: Number, default: 0.25 },
  windowSize: { type: Number, default: 500 },
  lastDecisionAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

riskDriftMetricSchema.index({ tenantId: 1, modelVersion: 1 }, { unique: true });

module.exports = mongoose.model('RiskDriftMetric', riskDriftMetricSchema);
