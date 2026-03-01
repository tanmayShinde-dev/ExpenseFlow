const crypto = require('crypto');
const statistics = require('simple-statistics');
const mongoose = require('mongoose');
const Expense = require('../models/Expense');
const Goal = require('../models/Goal');
const RecurringExpense = require('../models/RecurringExpense');
const Investment = require('../models/Investment');
const Workspace = require('../models/Workspace');
const AIPrediction = require('../models/AIPrediction');
const AITrainingData = require('../models/AITrainingData');
const TenantForecastModel = require('../models/TenantForecastModel');

class AutomatedForecastingService {
  async validateTenantAccess(userId, workspaceId = null) {
    if (!workspaceId) {
      return { tenantType: 'personal', workspace: null };
    }

    const workspace = await Workspace.findById(workspaceId);
    if (!workspace) {
      throw new Error('Workspace not found');
    }

    const isOwner = workspace.owner.toString() === userId.toString();
    const isMember = workspace.members.some((member) => member.user.toString() === userId.toString());

    if (!isOwner && !isMember) {
      throw new Error('Access denied for tenant workspace');
    }

    return { tenantType: 'workspace', workspace };
  }

  async getOrCreateTenantModel(userId, workspaceId = null, modelType = 'ensemble') {
    let model = await TenantForecastModel.getTenantModel(userId, workspaceId, modelType);
    if (model) return model;

    model = await TenantForecastModel.create({
      user: userId,
      workspace: workspaceId || null,
      tenantType: workspaceId ? 'workspace' : 'personal',
      modelType,
      metadata: { createdBy: userId, updatedBy: userId }
    });

    return model;
  }

  async updateTenantModelConfig(userId, payload = {}) {
    const {
      workspaceId = null,
      modelType = 'ensemble',
      algorithm,
      customWeights,
      hyperparameters,
      features,
      realtimeRetraining
    } = payload;

    await this.validateTenantAccess(userId, workspaceId);
    const model = await this.getOrCreateTenantModel(userId, workspaceId, modelType);

    if (algorithm) model.algorithm = algorithm;
    if (customWeights) model.customWeights = { ...model.customWeights.toObject(), ...customWeights };
    if (hyperparameters) model.hyperparameters = { ...model.hyperparameters.toObject(), ...hyperparameters };
    if (features) model.features = { ...model.features.toObject(), ...features };
    if (realtimeRetraining) {
      model.realtimeRetraining = {
        ...model.realtimeRetraining.toObject(),
        ...realtimeRetraining
      };
    }

    model.metadata.updatedBy = userId;
    await model.save();

    return model;
  }

  async ingestHistoricalFinancialData(userId, options = {}) {
    const { workspaceId = null, lookbackMonths = 18 } = options;
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - lookbackMonths);

    const match = {
      user: new mongoose.Types.ObjectId(userId),
      date: { $gte: startDate }
    };

    if (workspaceId) {
      match.workspace = new mongoose.Types.ObjectId(workspaceId);
    }

    const monthlyCashflow = await Expense.aggregate([
      { $match: match },
      {
        $group: {
          _id: {
            year: { $year: '$date' },
            month: { $month: '$date' }
          },
          income: {
            $sum: {
              $cond: [{ $eq: ['$type', 'income'] }, '$amount', 0]
            }
          },
          expense: {
            $sum: {
              $cond: [{ $eq: ['$type', 'expense'] }, '$amount', 0]
            }
          }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);

    const monthlyCategories = await Expense.aggregate([
      { $match: { ...match, type: 'expense' } },
      {
        $group: {
          _id: {
            year: { $year: '$date' },
            month: { $month: '$date' },
            category: '$category'
          },
          total: { $sum: '$amount' }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);

    return {
      startDate,
      monthlyCashflow,
      monthlyCategories,
      points: monthlyCashflow.length
    };
  }

  weightedMovingAverage(values, window = 3) {
    if (!values.length) return 0;
    const actualWindow = Math.min(window, values.length);
    const sample = values.slice(-actualWindow);
    const weights = sample.map((_, idx) => idx + 1);
    const weightedTotal = sample.reduce((sum, value, idx) => sum + (value * weights[idx]), 0);
    const totalWeights = weights.reduce((sum, value) => sum + value, 0);
    return weightedTotal / totalWeights;
  }

  exponentialSmoothing(values, alpha = 0.3) {
    if (!values.length) return 0;
    return values.reduce((smoothed, current) => (alpha * current) + ((1 - alpha) * smoothed), values[0]);
  }

  linearRegressionPredict(values, horizonIndex = 1) {
    if (values.length < 2) return values[0] || 0;
    const points = values.map((value, index) => [index, value]);
    const regression = statistics.linearRegression(points);
    return (regression.m * (values.length - 1 + horizonIndex)) + regression.b;
  }

  buildForecastValue(values, modelConfig, horizonIndex = 1) {
    const ma = this.weightedMovingAverage(values, modelConfig.hyperparameters.movingAverageWindow);
    const es = this.exponentialSmoothing(values, modelConfig.hyperparameters.smoothingAlpha);
    const lr = this.linearRegressionPredict(values, horizonIndex);

    if (modelConfig.algorithm === 'weighted_moving_average') return ma;
    if (modelConfig.algorithm === 'exponential_smoothing') return es;
    if (modelConfig.algorithm === 'linear_regression') return lr;

    const weights = modelConfig.customWeights;
    return (ma * weights.movingAverage) + (es * weights.exponentialSmoothing) + (lr * weights.linearRegression);
  }

  async generateBudgetForecast(userId, options = {}) {
    const { workspaceId = null, horizonMonths = 6, modelConfig } = options;
    const historical = await this.ingestHistoricalFinancialData(userId, { workspaceId, lookbackMonths: 18 });

    if (historical.monthlyCashflow.length < 3) {
      return { success: false, message: 'Insufficient historical data for budgeting forecast', data: [] };
    }

    const expenseSeries = historical.monthlyCashflow.map((m) => m.expense || 0);
    const baselineStd = statistics.standardDeviation(expenseSeries) || 0;

    const points = [];
    for (let i = 1; i <= horizonMonths; i++) {
      const predicted = Math.max(0, this.buildForecastValue(expenseSeries, modelConfig, i));
      const confidenceBand = baselineStd * 1.65;
      const when = new Date();
      when.setMonth(when.getMonth() + i);

      points.push({
        date: new Date(when.getFullYear(), when.getMonth(), 1),
        predictedAmount: Number(predicted.toFixed(2)),
        lowerBound: Number(Math.max(0, predicted - confidenceBand).toFixed(2)),
        upperBound: Number((predicted + confidenceBand).toFixed(2))
      });
    }

    return {
      success: true,
      horizonMonths,
      dataPoints: historical.points,
      trend: expenseSeries.length > 1 ? (expenseSeries[expenseSeries.length - 1] - expenseSeries[0]) : 0,
      points
    };
  }

  async generateCashFlowForecast(userId, options = {}) {
    const { workspaceId = null, horizonDays = 90, modelConfig } = options;
    const historical = await this.ingestHistoricalFinancialData(userId, { workspaceId, lookbackMonths: 12 });

    if (historical.monthlyCashflow.length < 3) {
      return { success: false, message: 'Insufficient historical data for cash flow forecast', projection: [] };
    }

    const netSeries = historical.monthlyCashflow.map((m) => (m.income || 0) - (m.expense || 0));
    const recurring = await RecurringExpense.find({ user: userId, isActive: true, isPaused: false });

    const currentBalance = netSeries.reduce((sum, value) => sum + value, 0);
    const avgDailyNet = this.buildForecastValue(netSeries, modelConfig, 1) / 30;

    const projection = [];
    let running = currentBalance;

    for (let i = 1; i <= horizonDays; i++) {
      const date = new Date();
      date.setDate(date.getDate() + i);

      running += avgDailyNet;

      recurring.forEach((item) => {
        const due = new Date(item.nextDueDate);
        if (due.toDateString() === date.toDateString()) {
          running += item.type === 'income' ? item.amount : -item.amount;
        }
      });

      projection.push({
        date,
        projectedBalance: Number(running.toFixed(2)),
        riskLevel: running < 0 ? 'high' : running < (currentBalance * 0.2) ? 'medium' : 'low'
      });
    }

    return {
      success: true,
      currentBalance: Number(currentBalance.toFixed(2)),
      avgDailyNet: Number(avgDailyNet.toFixed(2)),
      horizonDays,
      projection
    };
  }

  async generateInvestmentForecast(userId, options = {}) {
    const { horizonMonths = 12, riskProfile = 'moderate' } = options;
    const investments = await Investment.find({ user: userId });

    if (!investments.length) {
      return { success: false, message: 'No investment positions found', scenarios: [] };
    }

    const currentValue = investments.reduce((sum, inv) => sum + (inv.quantity * (inv.currentPrice || inv.buyPrice)), 0);
    const totalCost = investments.reduce((sum, inv) => sum + (inv.quantity * inv.buyPrice), 0);
    const realizedReturn = totalCost > 0 ? (currentValue - totalCost) / totalCost : 0;

    const profileGrowth = {
      conservative: 0.004,
      moderate: 0.007,
      aggressive: 0.012
    };

    const baseMonthlyGrowth = profileGrowth[riskProfile] || profileGrowth.moderate;
    const momentumBoost = Math.max(-0.01, Math.min(0.02, realizedReturn / 12));

    const scenarios = ['bear', 'base', 'bull'].map((scenario) => {
      const modifier = scenario === 'bear' ? -0.006 : scenario === 'bull' ? 0.008 : 0;
      const monthlyRate = baseMonthlyGrowth + momentumBoost + modifier;
      const points = [];

      for (let i = 1; i <= horizonMonths; i++) {
        const date = new Date();
        date.setMonth(date.getMonth() + i);
        const projected = currentValue * Math.pow(1 + monthlyRate, i);
        points.push({ date: new Date(date.getFullYear(), date.getMonth(), 1), value: Number(projected.toFixed(2)) });
      }

      return { scenario, monthlyRate: Number(monthlyRate.toFixed(4)), points };
    });

    return {
      success: true,
      positions: investments.length,
      currentValue: Number(currentValue.toFixed(2)),
      totalCost: Number(totalCost.toFixed(2)),
      unrealizedPnL: Number((currentValue - totalCost).toFixed(2)),
      riskProfile,
      scenarios
    };
  }

  async generateInsights(userId, forecastBundle = {}) {
    const insights = [];

    const budget = forecastBundle.budgetForecast;
    const cashFlow = forecastBundle.cashFlowForecast;
    const investment = forecastBundle.investmentForecast;

    if (budget?.success && budget.points.length) {
      const next = budget.points[0];
      const avg = budget.points.reduce((sum, point) => sum + point.predictedAmount, 0) / budget.points.length;
      insights.push({
        type: 'budgeting',
        title: 'Budget trend forecast',
        narrative: `Predicted next-month spend is ${next.predictedAmount}. Average projected spend across horizon is ${avg.toFixed(2)}.`,
        priority: next.predictedAmount > avg * 1.15 ? 'high' : 'medium'
      });
    }

    if (cashFlow?.success && cashFlow.projection.length) {
      const negativeDays = cashFlow.projection.filter((p) => p.projectedBalance < 0).length;
      insights.push({
        type: 'cash_flow',
        title: 'Cash flow stress signal',
        narrative: negativeDays > 0
          ? `Projected negative balance on ${negativeDays} day(s). Consider reducing recurring outflows or adding buffer income.`
          : 'Cash flow projection stays positive throughout the forecast window.',
        priority: negativeDays > 0 ? 'critical' : 'low'
      });
    }

    if (investment?.success) {
      const baseScenario = investment.scenarios.find((s) => s.scenario === 'base');
      const finalPoint = baseScenario?.points[baseScenario.points.length - 1];
      if (finalPoint) {
        insights.push({
          type: 'investment',
          title: 'Investment planning outlook',
          narrative: `Base scenario projects portfolio value around ${finalPoint.value} in ${baseScenario.points.length} months.`,
          priority: 'medium'
        });
      }
    }

    return insights;
  }

  async retrainTenantModel(userId, payload = {}) {
    const { workspaceId = null, modelType = 'ensemble', force = false } = payload;

    await this.validateTenantAccess(userId, workspaceId);
    const model = await this.getOrCreateTenantModel(userId, workspaceId, modelType);

    const historical = await this.ingestHistoricalFinancialData(userId, { workspaceId, lookbackMonths: model.training.trainingWindowMonths });
    if (!force && historical.points < model.training.minSamples) {
      return {
        success: false,
        message: `Insufficient samples for retraining (${historical.points}/${model.training.minSamples})`,
        model
      };
    }

    const expenseSeries = historical.monthlyCashflow.map((m) => m.expense || 0);
    const oneStepPredictions = [];

    for (let i = 3; i < expenseSeries.length; i++) {
      const history = expenseSeries.slice(0, i);
      const predicted = this.buildForecastValue(history, model, 1);
      oneStepPredictions.push({ predicted, actual: expenseSeries[i] });
    }

    if (oneStepPredictions.length) {
      const errors = oneStepPredictions.map((pair) => pair.actual - pair.predicted);
      const absErrors = errors.map((value) => Math.abs(value));
      const pctErrors = oneStepPredictions
        .filter((pair) => pair.actual !== 0)
        .map((pair) => Math.abs((pair.actual - pair.predicted) / pair.actual) * 100);

      model.training.mae = Number((statistics.mean(absErrors) || 0).toFixed(4));
      model.training.rmse = Number((Math.sqrt(statistics.mean(errors.map((value) => value * value)) || 0)).toFixed(4));
      model.training.mape = Number((statistics.mean(pctErrors) || 0).toFixed(4));
    }

    model.training.dataPoints = historical.points;
    model.training.lastTrainedAt = new Date();
    model.training.retrainCount += 1;
    model.realtimeRetraining.latestDataHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(historical.monthlyCashflow.slice(-12)))
      .digest('hex');

    model.metadata.updatedBy = userId;
    await model.save();

    await AITrainingData.create({
      userId,
      modelType: 'cash_flow_predictor',
      features: [
        { name: 'tenant_type', value: model.tenantType, type: 'categorical' },
        { name: 'model_type', value: model.modelType, type: 'categorical' },
        { name: 'data_points', value: model.training.dataPoints, type: 'numeric' },
        { name: 'mae', value: model.training.mae || 0, type: 'numeric' },
        { name: 'rmse', value: model.training.rmse || 0, type: 'numeric' }
      ],
      label: model.training.mape || 0,
      isValidated: true,
      weight: 1.0
    });

    return { success: true, model };
  }

  async runAutomatedForecasting(userId, options = {}) {
    const {
      workspaceId = null,
      horizonMonths = 6,
      horizonDays = 90,
      riskProfile = 'moderate'
    } = options;

    await this.validateTenantAccess(userId, workspaceId);

    const modelConfig = await this.getOrCreateTenantModel(userId, workspaceId, 'ensemble');

    const historical = await this.ingestHistoricalFinancialData(userId, {
      workspaceId,
      lookbackMonths: modelConfig.training.trainingWindowMonths
    });

    const latestHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(historical.monthlyCashflow.slice(-12)))
      .digest('hex');

    if (modelConfig.shouldRetrain(latestHash)) {
      await this.retrainTenantModel(userId, { workspaceId, modelType: 'ensemble', force: false });
    }

    const [budgetForecast, cashFlowForecast, investmentForecast] = await Promise.all([
      this.generateBudgetForecast(userId, { workspaceId, horizonMonths, modelConfig }),
      this.generateCashFlowForecast(userId, { workspaceId, horizonDays, modelConfig }),
      this.generateInvestmentForecast(userId, { horizonMonths, riskProfile })
    ]);

    const insights = await this.generateInsights(userId, {
      budgetForecast,
      cashFlowForecast,
      investmentForecast
    });

    await AIPrediction.create({
      userId,
      type: 'cash_flow_forecast',
      inputData: {
        workspaceId,
        horizonMonths,
        horizonDays,
        riskProfile,
        modelVersion: modelConfig.version
      },
      prediction: {
        budget: budgetForecast,
        cashFlow: cashFlowForecast,
        investment: investmentForecast,
        insights
      },
      confidence: 0.78,
      modelVersion: modelConfig.version,
      isVerified: false
    });

    return {
      success: true,
      tenant: {
        workspaceId: workspaceId || null,
        tenantType: workspaceId ? 'workspace' : 'personal'
      },
      model: {
        modelType: modelConfig.modelType,
        algorithm: modelConfig.algorithm,
        version: modelConfig.version,
        lastTrainedAt: modelConfig.training.lastTrainedAt
      },
      forecasts: {
        budgeting: budgetForecast,
        cashFlow: cashFlowForecast,
        investment: investmentForecast
      },
      insights,
      generatedAt: new Date()
    };
  }

  buildVisualizationPayload(automatedForecastResult) {
    const budgetPoints = automatedForecastResult?.forecasts?.budgeting?.points || [];
    const cashFlowPoints = automatedForecastResult?.forecasts?.cashFlow?.projection || [];
    const baseInvestmentScenario = automatedForecastResult?.forecasts?.investment?.scenarios?.find((s) => s.scenario === 'base');
    const investmentPoints = baseInvestmentScenario?.points || [];

    return {
      budgetChart: {
        labels: budgetPoints.map((point) => point.date.toISOString().slice(0, 7)),
        series: {
          predicted: budgetPoints.map((point) => point.predictedAmount),
          lower: budgetPoints.map((point) => point.lowerBound),
          upper: budgetPoints.map((point) => point.upperBound)
        }
      },
      cashFlowChart: {
        labels: cashFlowPoints.map((point) => point.date.toISOString().slice(0, 10)),
        series: {
          projectedBalance: cashFlowPoints.map((point) => point.projectedBalance)
        }
      },
      investmentChart: {
        labels: investmentPoints.map((point) => point.date.toISOString().slice(0, 7)),
        series: {
          projectedValue: investmentPoints.map((point) => point.value)
        }
      }
    };
  }
}

module.exports = new AutomatedForecastingService();
