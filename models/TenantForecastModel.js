const mongoose = require('mongoose');

const tenantForecastModelSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  workspace: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Workspace',
    default: null,
    index: true
  },
  tenantType: {
    type: String,
    enum: ['personal', 'workspace'],
    default: 'personal'
  },
  modelType: {
    type: String,
    enum: ['budgeting', 'cash_flow', 'investment', 'ensemble'],
    default: 'ensemble'
  },
  algorithm: {
    type: String,
    enum: ['ensemble', 'linear_regression', 'weighted_moving_average', 'exponential_smoothing'],
    default: 'ensemble'
  },
  version: {
    type: String,
    default: '1.0.0'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  customWeights: {
    movingAverage: { type: Number, default: 0.35 },
    exponentialSmoothing: { type: Number, default: 0.35 },
    linearRegression: { type: Number, default: 0.30 }
  },
  hyperparameters: {
    movingAverageWindow: { type: Number, default: 3, min: 2, max: 12 },
    smoothingAlpha: { type: Number, default: 0.3, min: 0.05, max: 0.95 },
    confidenceLevel: { type: Number, default: 95, min: 70, max: 99 },
    horizonMonths: { type: Number, default: 6, min: 1, max: 24 }
  },
  features: {
    includeSeasonality: { type: Boolean, default: true },
    includeRecurringExpenses: { type: Boolean, default: true },
    includeAnomalySignal: { type: Boolean, default: true },
    includeGoalPressure: { type: Boolean, default: true },
    includeInvestmentSignal: { type: Boolean, default: true }
  },
  training: {
    trainingWindowMonths: { type: Number, default: 12 },
    minSamples: { type: Number, default: 24 },
    dataPoints: { type: Number, default: 0 },
    lastTrainedAt: { type: Date, default: null },
    retrainCount: { type: Number, default: 0 },
    mae: { type: Number, default: null },
    rmse: { type: Number, default: null },
    mape: { type: Number, default: null }
  },
  realtimeRetraining: {
    enabled: { type: Boolean, default: true },
    retrainOnDrift: { type: Boolean, default: true },
    driftThreshold: { type: Number, default: 0.15, min: 0.01, max: 1 },
    minHoursBetweenRetrains: { type: Number, default: 6, min: 1, max: 168 },
    latestDataHash: { type: String, default: null }
  },
  metadata: {
    notes: { type: String, default: '' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
  }
}, {
  timestamps: true
});

tenantForecastModelSchema.index({ user: 1, workspace: 1, modelType: 1 }, { unique: true });
tenantForecastModelSchema.index({ tenantType: 1, isActive: 1 });

tenantForecastModelSchema.methods.shouldRetrain = function(latestDataHash) {
  if (!this.realtimeRetraining.enabled) return false;

  const now = Date.now();
  const lastTrainedAt = this.training.lastTrainedAt ? this.training.lastTrainedAt.getTime() : 0;
  const minGapMs = this.realtimeRetraining.minHoursBetweenRetrains * 60 * 60 * 1000;

  if (now - lastTrainedAt < minGapMs) {
    return false;
  }

  if (!this.realtimeRetraining.retrainOnDrift) {
    return true;
  }

  if (!this.realtimeRetraining.latestDataHash || !latestDataHash) {
    return true;
  }

  return this.realtimeRetraining.latestDataHash !== latestDataHash;
};

tenantForecastModelSchema.statics.getTenantModel = async function(userId, workspaceId, modelType = 'ensemble') {
  return this.findOne({
    user: userId,
    workspace: workspaceId || null,
    modelType,
    isActive: true
  });
};

module.exports = mongoose.model('TenantForecastModel', tenantForecastModelSchema);
