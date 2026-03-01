const express = require('express');
const auth = require('../middleware/auth');
const adaptiveRiskEngineV2Service = require('../services/adaptiveRiskEngineV2Service');

const router = express.Router();

const adminAuth = (req, res, next) => {
  const isAdminByEmail = process.env.ADMIN_EMAIL && req.user?.email === process.env.ADMIN_EMAIL;
  if (!isAdminByEmail) {
    return res.status(403).json({
      success: false,
      error: 'Admin access required for risk policy operations'
    });
  }
  next();
};

router.get('/policy', auth, adminAuth, async (req, res) => {
  try {
    const tenantId = String(req.query.tenantId || 'global');
    const active = await adaptiveRiskEngineV2Service.getActivePolicy(tenantId);

    return res.json({
      success: true,
      tenantId,
      activePolicy: {
        version: active.version,
        modelVersion: active.modelVersion,
        checksum: active.checksum,
        status: active.status,
        createdAt: active.createdAt,
        updatedAt: active.updatedAt,
        policy: active.policy
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.put('/policy', auth, adminAuth, async (req, res) => {
  try {
    const tenantId = String(req.body?.tenantId || req.query?.tenantId || 'global');
    const policy = req.body?.policy;

    if (!policy || typeof policy !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'policy object is required'
      });
    }

    const published = await adaptiveRiskEngineV2Service.publishPolicy({
      tenantId,
      policy,
      createdBy: req.user._id
    });

    return res.json({
      success: true,
      message: 'Risk policy published successfully',
      tenantId,
      policyVersion: published.version,
      modelVersion: published.modelVersion,
      checksum: published.checksum
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.post('/policy/rollback', auth, adminAuth, async (req, res) => {
  try {
    const tenantId = String(req.body?.tenantId || req.query?.tenantId || 'global');
    const targetVersion = Number(req.body?.targetVersion || req.query?.targetVersion);

    if (!targetVersion || Number.isNaN(targetVersion)) {
      return res.status(400).json({
        success: false,
        error: 'targetVersion is required'
      });
    }

    const rollbackResult = await adaptiveRiskEngineV2Service.rollbackPolicy({
      tenantId,
      targetVersion,
      createdBy: req.user._id
    });

    return res.json({
      success: true,
      message: 'Risk policy rollback completed',
      tenantId,
      policyVersion: rollbackResult.version,
      rolledBackFromVersion: rollbackResult.rolledBackFromVersion,
      checksum: rollbackResult.checksum
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/history', auth, adminAuth, async (req, res) => {
  try {
    const tenantId = String(req.query.tenantId || 'global');
    const limit = Number(req.query.limit || 20);
    const history = await adaptiveRiskEngineV2Service.getPolicyHistory(tenantId, limit);

    return res.json({
      success: true,
      tenantId,
      count: history.length,
      history
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/drift', auth, adminAuth, async (req, res) => {
  try {
    const tenantId = String(req.query.tenantId || 'global');
    const drift = await adaptiveRiskEngineV2Service.getDriftMetrics(tenantId);

    return res.json({
      success: true,
      tenantId,
      drift
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/decisions', auth, async (req, res) => {
  try {
    const isAdminByEmail = process.env.ADMIN_EMAIL && req.user?.email === process.env.ADMIN_EMAIL;
    const tenantId = String(req.query.tenantId || 'global');
    const limit = Number(req.query.limit || 50);

    const userId = isAdminByEmail
      ? (req.query.userId || req.user._id)
      : req.user._id;

    const decisions = await adaptiveRiskEngineV2Service.getDecisionLogs({
      tenantId,
      userId,
      limit
    });

    return res.json({
      success: true,
      tenantId,
      userId,
      count: decisions.length,
      decisions
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
