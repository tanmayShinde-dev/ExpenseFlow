const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const forecastingEngine = require('../services/forecastingEngine');
const ForecastScenario = require('../models/ForecastScenario');

/**
 * @route   POST /api/forecasting/run
 * @desc    Run a probabilistic cash-flow simulation
 */
router.post('/run', auth, async (req, res) => {
    try {
        const { scenarioId } = req.body;
        let scenario = null;

        if (scenarioId) {
            scenario = await ForecastScenario.findOne({ _id: scenarioId, user: req.user._id });
        }

        const results = await forecastingEngine.runSimulation(req.user._id, scenario);

        // Update scenario last results if it exists
        if (scenario) {
            scenario.lastRunAt = new Date();
            scenario.lastResultSnapshot = results.summary;
            await scenario.save();
        }

        res.json({ success: true, data: results });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * @route   POST /api/forecasting/scenarios
 * @desc    Create a new what-if scenario
 */
router.post('/scenarios', auth, async (req, res) => {
    try {
        const scenario = new ForecastScenario({
            ...req.body,
            user: req.user._id
        });
        await scenario.save();
        res.status(201).json({ success: true, data: scenario });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * @route   GET /api/forecasting/scenarios
 * @desc    Get user scenarios
 */
router.get('/scenarios', auth, async (req, res) => {
    try {
        const scenarios = await ForecastScenario.find({ user: req.user._id }).sort({ createdAt: -1 });
        res.json({ success: true, data: scenarios });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
