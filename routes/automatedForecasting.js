const express = require('express');
const { body, query, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const automatedForecastingService = require('../services/automatedForecastingService');
const TenantForecastModel = require('../models/TenantForecastModel');

const router = express.Router();

router.post('/models/configure',
  auth,
  [
    body('workspaceId').optional().isMongoId(),
    body('modelType').optional().isIn(['budgeting', 'cash_flow', 'investment', 'ensemble']),
    body('algorithm').optional().isIn(['ensemble', 'linear_regression', 'weighted_moving_average', 'exponential_smoothing']),
    body('customWeights').optional().isObject(),
    body('hyperparameters').optional().isObject(),
    body('features').optional().isObject(),
    body('realtimeRetraining').optional().isObject()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const model = await automatedForecastingService.updateTenantModelConfig(req.user.id, req.body);
      res.json({ success: true, message: 'Tenant forecasting model updated', data: model });
    } catch (error) {
      console.error('Configure model error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to configure tenant model'
      });
    }
  }
);

router.get('/models',
  auth,
  [query('workspaceId').optional().isMongoId()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const workspaceId = req.query.workspaceId || null;
      await automatedForecastingService.validateTenantAccess(req.user.id, workspaceId);

      const models = await TenantForecastModel.find({
        user: req.user.id,
        workspace: workspaceId,
        isActive: true
      }).sort({ updatedAt: -1 });

      res.json({ success: true, count: models.length, data: models });
    } catch (error) {
      console.error('List models error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to list models'
      });
    }
  }
);

router.post('/models/retrain',
  auth,
  [
    body('workspaceId').optional().isMongoId(),
    body('modelType').optional().isIn(['budgeting', 'cash_flow', 'investment', 'ensemble']),
    body('force').optional().isBoolean()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const result = await automatedForecastingService.retrainTenantModel(req.user.id, req.body);
      res.json({
        success: result.success,
        message: result.success ? 'Realtime retraining completed' : result.message,
        data: result.model
      });
    } catch (error) {
      console.error('Retrain model error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to retrain model'
      });
    }
  }
);

router.post('/predict',
  auth,
  [
    body('workspaceId').optional().isMongoId(),
    body('horizonMonths').optional().isInt({ min: 1, max: 24 }),
    body('horizonDays').optional().isInt({ min: 7, max: 365 }),
    body('riskProfile').optional().isIn(['conservative', 'moderate', 'aggressive'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const result = await automatedForecastingService.runAutomatedForecasting(req.user.id, req.body);
      res.json({ success: true, data: result });
    } catch (error) {
      console.error('Automated forecasting error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to generate automated forecasting'
      });
    }
  }
);

router.get('/insights',
  auth,
  [
    query('workspaceId').optional().isMongoId(),
    query('horizonMonths').optional().isInt({ min: 1, max: 24 }),
    query('horizonDays').optional().isInt({ min: 7, max: 365 }),
    query('riskProfile').optional().isIn(['conservative', 'moderate', 'aggressive'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const options = {
        workspaceId: req.query.workspaceId || null,
        horizonMonths: req.query.horizonMonths ? parseInt(req.query.horizonMonths, 10) : 6,
        horizonDays: req.query.horizonDays ? parseInt(req.query.horizonDays, 10) : 90,
        riskProfile: req.query.riskProfile || 'moderate'
      };

      const result = await automatedForecastingService.runAutomatedForecasting(req.user.id, options);
      res.json({ success: true, data: { insights: result.insights, generatedAt: result.generatedAt } });
    } catch (error) {
      console.error('AI insights query error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to query AI insights'
      });
    }
  }
);

router.get('/visualize',
  auth,
  [
    query('workspaceId').optional().isMongoId(),
    query('horizonMonths').optional().isInt({ min: 1, max: 24 }),
    query('horizonDays').optional().isInt({ min: 7, max: 365 }),
    query('riskProfile').optional().isIn(['conservative', 'moderate', 'aggressive'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const options = {
        workspaceId: req.query.workspaceId || null,
        horizonMonths: req.query.horizonMonths ? parseInt(req.query.horizonMonths, 10) : 6,
        horizonDays: req.query.horizonDays ? parseInt(req.query.horizonDays, 10) : 90,
        riskProfile: req.query.riskProfile || 'moderate'
      };

      const result = await automatedForecastingService.runAutomatedForecasting(req.user.id, options);
      const visual = automatedForecastingService.buildVisualizationPayload(result);

      res.json({ success: true, data: visual });
    } catch (error) {
      console.error('Visualization payload error:', error);
      res.status(error.message.includes('Access denied') ? 403 : 500).json({
        success: false,
        message: error.message || 'Failed to build visualization payload'
      });
    }
  }
);

module.exports = router;
