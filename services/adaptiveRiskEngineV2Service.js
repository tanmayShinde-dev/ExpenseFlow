const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const RiskPolicyVersion = require('../models/RiskPolicyVersion');
const RiskDecisionLog = require('../models/RiskDecisionLog');
const RiskDriftMetric = require('../models/RiskDriftMetric');

class AdaptiveRiskEngineV2Service {
  constructor() {
    this.defaultPolicyPath = path.join(__dirname, '..', 'config', 'adaptiveRiskPolicy.v2.json');
  }

  clamp(value, min = 0, max = 100) {
    return Math.max(min, Math.min(max, value));
  }

  sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  toFixed(value, digits = 4) {
    return Number(Number(value).toFixed(digits));
  }

  checksum(payload) {
    return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  }

  async ensureGlobalBootstrapPolicy() {
    const activeGlobal = await RiskPolicyVersion.getActivePolicy('global');
    if (activeGlobal) {
      return activeGlobal;
    }

    const fileContent = fs.readFileSync(this.defaultPolicyPath, 'utf8');
    const parsed = JSON.parse(fileContent);

    return RiskPolicyVersion.publishPolicy({
      tenantId: 'global',
      policy: parsed,
      modelVersion: parsed.modelVersion || 'ensemble-v2.0.0',
      checksum: this.checksum(parsed)
    });
  }

  async getActivePolicy(tenantId = 'global') {
    await this.ensureGlobalBootstrapPolicy();
    const policyRecord = await RiskPolicyVersion.getActivePolicy(tenantId || 'global');
    if (!policyRecord) {
      throw new Error('Active risk policy not found');
    }
    return policyRecord;
  }

  normalizeFeatures(raw = {}) {
    const features = {
      newDevice: raw.newDevice ? 1 : 0,
      suspiciousDevice: raw.suspiciousDevice ? 1 : 0,
      blockedDevice: raw.blockedDevice ? 1 : 0,
      geoAnomaly: raw.geoAnomaly ? 1 : 0,
      impossibleTravel: raw.impossibleTravel ? 1 : 0,
      velocityAnomaly: raw.velocityAnomaly ? 1 : 0,
      failedAttemptsRatio: this.clamp(raw.failedAttemptsRatio || 0, 0, 1),
      newNetwork: raw.newNetwork ? 1 : 0,
      deviceTrustRisk: this.clamp(raw.deviceTrustRisk || 0, 0, 1)
    };

    return features;
  }

  buildRuleFactors(policy, features, signalContext = {}) {
    const weights = policy.ruleWeights || {};
    const factors = [];

    const pushFactor = (key, active, value = active ? 1 : 0, description = key) => {
      if (!active) {
        return;
      }
      const weight = Number(weights[key] || 0);
      factors.push({
        key,
        source: 'rule',
        description,
        value: this.toFixed(value),
        weight: this.toFixed(weight),
        contribution: this.toFixed(weight * value)
      });
    };

    pushFactor('NEW_DEVICE', features.newDevice === 1, 1, 'New or unseen device fingerprint');
    pushFactor('SUSPICIOUS_DEVICE', features.suspiciousDevice === 1, 1, 'Device previously marked suspicious');
    pushFactor('BLOCKED_DEVICE', features.blockedDevice === 1, 1, 'Device currently blocked');
    pushFactor('GEOGRAPHIC_ANOMALY', features.geoAnomaly === 1, 1, 'Geographic anomaly detected');
    pushFactor('IMPOSSIBLE_TRAVEL', features.impossibleTravel === 1, 1, 'Impossible travel speed inferred');
    pushFactor('VELOCITY_ANOMALY', features.velocityAnomaly === 1, 1, 'Login velocity anomaly detected');
    pushFactor('MULTIPLE_FAILED_ATTEMPTS', features.failedAttemptsRatio > 0, features.failedAttemptsRatio, 'Recent failed authentication attempts');
    pushFactor('NEW_NETWORK', features.newNetwork === 1, 1, 'Known device used on a new network');

    if (signalContext.deviceRiskIncrease > 0 && (weights.NEW_DEVICE || weights.SUSPICIOUS_DEVICE || weights.BLOCKED_DEVICE)) {
      factors.push({
        key: 'DEVICE_RISK_INCREASE',
        source: 'rule',
        description: 'Device risk increase from fingerprint intelligence',
        value: this.toFixed(this.clamp(signalContext.deviceRiskIncrease / 50, 0, 1)),
        weight: this.toFixed(8),
        contribution: this.toFixed(this.clamp(signalContext.deviceRiskIncrease / 50, 0, 1) * 8)
      });
    }

    return factors;
  }

  calculateRuleScore(factors = []) {
    const total = factors.reduce((sum, factor) => sum + (factor.contribution || 0), 0);
    return this.clamp(total, 0, 100);
  }

  runSingleModel(modelConfig = {}, features = {}) {
    const bias = Number(modelConfig.bias || 0);
    const coefficients = modelConfig.coefficients || {};

    let z = bias;
    const featureContributions = [];

    for (const [featureKey, coefficient] of Object.entries(coefficients)) {
      const value = Number(features[featureKey] || 0);
      const coef = Number(coefficient || 0);
      const contribution = value * coef;
      z += contribution;

      featureContributions.push({
        key: `${modelConfig.name || 'model'}:${featureKey}`,
        source: 'ml',
        description: `${modelConfig.name || 'model'} sensitivity for ${featureKey}`,
        value: this.toFixed(value),
        weight: this.toFixed(coef),
        contribution: this.toFixed(contribution * 100)
      });
    }

    const probability = this.sigmoid(z);
    const score = this.clamp(probability * 100, 0, 100);

    return {
      score,
      featureContributions
    };
  }

  runMlEnsemble(policy, features) {
    const modelConfigs = policy.mlModels || {};
    const modelScores = [];
    const factors = [];

    for (const [modelName, modelConfig] of Object.entries(modelConfigs)) {
      const runResult = this.runSingleModel({ ...modelConfig, name: modelName }, features);
      const modelWeight = Number(modelConfig.weight || 0);

      modelScores.push({
        modelName,
        score: runResult.score,
        weight: modelWeight
      });

      factors.push(...runResult.featureContributions);
      factors.push({
        key: `model:${modelName}`,
        source: 'ml',
        description: `${modelName} model output`,
        value: this.toFixed(runResult.score / 100),
        weight: this.toFixed(modelWeight),
        contribution: this.toFixed(runResult.score * modelWeight)
      });
    }

    const weightedTotal = modelScores.reduce((sum, item) => sum + (item.score * item.weight), 0);
    const weightSum = modelScores.reduce((sum, item) => sum + item.weight, 0) || 1;
    const rawEnsemble = this.clamp(weightedTotal / weightSum, 0, 100);

    const calibration = policy.calibration || {};
    const slope = Number(calibration.slope || 6);
    const intercept = Number(calibration.intercept || -3);
    const calibrated = this.clamp(this.sigmoid((rawEnsemble / 100) * slope + intercept) * 100, 0, 100);

    factors.push({
      key: 'calibration',
      source: 'calibration',
      description: 'Probability calibration on ensemble output',
      value: this.toFixed(rawEnsemble / 100),
      weight: this.toFixed(slope),
      contribution: this.toFixed(calibrated)
    });

    return {
      rawEnsemble,
      calibrated,
      factors
    };
  }

  finalDecision(policy, ruleScore, mlScore) {
    const ensembleWeights = policy.ensembleWeights || {};
    const ruleWeight = Number(ensembleWeights.ruleEngine || 0.5);
    const mlWeight = Number(ensembleWeights.mlEnsemble || 0.5);
    const normalizer = ruleWeight + mlWeight || 1;

    const finalRiskScore = this.clamp(
      ((ruleScore * ruleWeight) + (mlScore * mlWeight)) / normalizer,
      0,
      100
    );

    const thresholds = policy.thresholds || { suspicious: 65, challenge: 82, block: 95 };

    let action = 'allowed';
    if (finalRiskScore >= Number(thresholds.block || 95)) {
      action = 'blocked';
    } else if (finalRiskScore >= Number(thresholds.challenge || 82)) {
      action = 'challenged';
    } else if (finalRiskScore >= Number(thresholds.suspicious || 65)) {
      action = 'monitor';
    }

    return {
      finalRiskScore: this.toFixed(finalRiskScore, 2),
      thresholds,
      action,
      isSuspicious: finalRiskScore >= Number(thresholds.suspicious || 65),
      requiresChallenge: finalRiskScore >= Number(thresholds.challenge || 82),
      shouldBlock: finalRiskScore >= Number(thresholds.block || 95)
    };
  }

  getTopFactors(factors = [], limit = 5) {
    return [...factors]
      .sort((a, b) => Math.abs(b.contribution || 0) - Math.abs(a.contribution || 0))
      .slice(0, limit);
  }

  buildReproducibilityInput({ tenantId, userId, features, policyVersion, modelVersion, signalContext }) {
    return {
      tenantId,
      userId: String(userId),
      features,
      policyVersion,
      modelVersion,
      signalContext: {
        geoSpeedRequired: signalContext.geoSpeedRequired || 0,
        failedAttempts: signalContext.failedAttempts || 0,
        deviceRiskIncrease: signalContext.deviceRiskIncrease || 0
      }
    };
  }

  async updateDriftMetrics({ tenantId, modelVersion, policyVersion, features, driftConfig }) {
    const config = driftConfig || {};
    const alertThreshold = Number(config.alertThreshold || 0.27);
    const watchThreshold = Number(config.watchThreshold || 0.18);
    const ewmaAlpha = Number(config.ewmaAlpha || 0.08);
    const windowSize = Number(config.windowSize || 500);

    const metric = await RiskDriftMetric.findOne({ tenantId, modelVersion }) || new RiskDriftMetric({
      tenantId,
      modelVersion,
      policyVersion,
      alertThreshold,
      windowSize
    });

    metric.policyVersion = policyVersion;
    metric.alertThreshold = alertThreshold;
    metric.windowSize = windowSize;
    metric.sampleCount += 1;
    metric.lastDecisionAt = new Date();
    metric.baseline = metric.baseline || {};
    metric.current = metric.current || {};

    const featureKeys = Object.keys(features || {});

    for (const key of featureKeys) {
      const value = Number(features[key] || 0);
      if (metric.sampleCount === 1) {
        metric.baseline[key] = value;
        metric.current[key] = value;
      } else {
        if (metric.baseline[key] === undefined) {
          metric.baseline[key] = value;
        }
        const existingCurrent = Number(metric.current[key] || 0);
        metric.current[key] = (ewmaAlpha * value) + ((1 - ewmaAlpha) * existingCurrent);
      }
    }

    const driftComponents = featureKeys.map((key) => {
      const baseline = Number(metric.baseline[key] || 0);
      const current = Number(metric.current[key] || 0);
      return Math.abs(current - baseline);
    });

    const driftScore = driftComponents.length
      ? driftComponents.reduce((sum, value) => sum + value, 0) / driftComponents.length
      : 0;

    metric.driftScore = this.toFixed(driftScore, 4);
    metric.driftStatus = driftScore >= alertThreshold
      ? 'alert'
      : driftScore >= watchThreshold
        ? 'watch'
        : 'stable';

    metric.markModified('baseline');
    metric.markModified('current');
    await metric.save();

    return metric;
  }

  async evaluateLoginRisk({ userId, loginInfo = {}, signalContext = {} }) {
    const tenantId = String(loginInfo.tenantId || loginInfo.workspaceId || 'global');
    const policyRecord = await this.getActivePolicy(tenantId);
    const policy = policyRecord.policy || {};

    const rawFeatures = {
      newDevice: signalContext.deviceReason === 'NEW_DEVICE',
      suspiciousDevice: signalContext.deviceReason === 'SUSPICIOUS_DEVICE',
      blockedDevice: signalContext.deviceReason === 'BLOCKED_DEVICE',
      geoAnomaly: Boolean(signalContext.geoAnomaly),
      impossibleTravel: Boolean(signalContext.impossibleTravel),
      velocityAnomaly: Boolean(signalContext.velocityAnomaly),
      failedAttemptsRatio: this.clamp((signalContext.failedAttempts || 0) / 5, 0, 1),
      newNetwork: signalContext.deviceReason === 'NEW_NETWORK',
      deviceTrustRisk: this.clamp(1 - Number(signalContext.deviceTrustScore ?? 0.5), 0, 1)
    };

    const features = this.normalizeFeatures(rawFeatures);
    const ruleFactors = this.buildRuleFactors(policy, features, signalContext);
    const ruleScore = this.toFixed(this.calculateRuleScore(ruleFactors), 2);

    const mlResult = this.runMlEnsemble(policy, features);
    const mlScore = this.toFixed(mlResult.calibrated, 2);

    const combinedFactors = [...ruleFactors, ...mlResult.factors];
    const decision = this.finalDecision(policy, ruleScore, mlScore);

    const reproducibilityInput = this.buildReproducibilityInput({
      tenantId,
      userId,
      features,
      policyVersion: policyRecord.version,
      modelVersion: policyRecord.modelVersion,
      signalContext
    });

    const inputHash = this.checksum(reproducibilityInput);
    const reproducibilityKey = this.checksum({
      inputHash,
      policyChecksum: policyRecord.checksum,
      policyVersion: policyRecord.version,
      modelVersion: policyRecord.modelVersion
    });

    const decisionLog = await RiskDecisionLog.create({
      tenantId,
      userId,
      sessionId: loginInfo.sessionId,
      requestId: loginInfo.requestId,
      policyVersion: policyRecord.version,
      modelVersion: policyRecord.modelVersion,
      policyChecksum: policyRecord.checksum,
      reproducibilityKey,
      inputHash,
      features,
      scores: {
        ruleScore,
        mlScore: this.toFixed(mlResult.rawEnsemble, 2),
        calibratedScore: mlScore,
        finalRiskScore: decision.finalRiskScore
      },
      thresholds: decision.thresholds,
      action: decision.action,
      explainability: {
        factors: combinedFactors,
        topFactors: this.getTopFactors(combinedFactors, 5)
      },
      meta: {
        ipAddress: loginInfo.ipAddress,
        userAgent: loginInfo.userAgent,
        location: loginInfo.location,
        deviceFingerprint: loginInfo.deviceFingerprint
      }
    });

    const driftMetric = await this.updateDriftMetrics({
      tenantId,
      modelVersion: policyRecord.modelVersion,
      policyVersion: policyRecord.version,
      features,
      driftConfig: policy.drift
    });

    return {
      tenantId,
      policyVersion: policyRecord.version,
      modelVersion: policyRecord.modelVersion,
      policyChecksum: policyRecord.checksum,
      reproducibilityKey,
      decisionLogId: decisionLog._id,
      scores: {
        ruleScore,
        mlScore: this.toFixed(mlResult.rawEnsemble, 2),
        calibratedScore: mlScore,
        finalRiskScore: decision.finalRiskScore
      },
      thresholds: decision.thresholds,
      action: decision.action,
      isSuspicious: decision.isSuspicious,
      requiresChallenge: decision.requiresChallenge,
      shouldBlock: decision.shouldBlock,
      explainability: {
        factors: combinedFactors,
        topFactors: this.getTopFactors(combinedFactors, 5)
      },
      drift: {
        score: driftMetric.driftScore,
        status: driftMetric.driftStatus,
        alertThreshold: driftMetric.alertThreshold,
        sampleCount: driftMetric.sampleCount
      }
    };
  }

  async publishPolicy({ tenantId = 'global', policy, createdBy }) {
    const active = await this.getActivePolicy(tenantId);
    const nextPolicy = {
      ...(active?.policy || {}),
      ...(policy || {})
    };

    const created = await RiskPolicyVersion.publishPolicy({
      tenantId,
      policy: nextPolicy,
      modelVersion: nextPolicy.modelVersion || active.modelVersion || 'ensemble-v2.0.0',
      checksum: this.checksum(nextPolicy),
      createdBy
    });

    return created;
  }

  async rollbackPolicy({ tenantId = 'global', targetVersion, createdBy }) {
    const target = await RiskPolicyVersion.findOne({ tenantId, version: Number(targetVersion) });
    if (!target) {
      throw new Error('Target policy version not found for rollback');
    }

    const rolledBack = await RiskPolicyVersion.publishPolicy({
      tenantId,
      policy: target.policy,
      modelVersion: target.modelVersion,
      checksum: this.checksum(target.policy),
      createdBy,
      rolledBackFromVersion: target.version
    });

    return rolledBack;
  }

  async getPolicyHistory(tenantId = 'global', limit = 20) {
    return RiskPolicyVersion.find({ tenantId })
      .sort({ version: -1 })
      .limit(limit)
      .lean();
  }

  async getDriftMetrics(tenantId = 'global') {
    return RiskDriftMetric.findOne({ tenantId }).lean();
  }

  async getDecisionLogs({ tenantId = 'global', userId = null, limit = 50 }) {
    const query = { tenantId };
    if (userId) {
      query.userId = userId;
    }

    return RiskDecisionLog.find(query)
      .sort({ createdAt: -1 })
      .limit(Math.min(limit, 200))
      .lean();
  }
}

module.exports = new AdaptiveRiskEngineV2Service();
