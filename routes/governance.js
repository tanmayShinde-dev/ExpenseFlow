const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const ValidationLog = require('../models/ValidationLog');
const PolicyNode = require('../models/PolicyNode');
const policyResolver = require('../services/policyResolver');

/**
 * Data Governance Routes
 * Issue #704: API for monitoring data purity and remediation efficacy.
 */

/**
 * @route   GET /api/governance/purity-report
 * @desc    Get aggregate data quality metrics
 */
router.get('/purity-report', auth, async (req, res) => {
    try {
        const stats = await ValidationLog.aggregate([
            { $match: { userId: req.user._id } },
            {
                $group: {
                    _id: null,
                    avgPurityScore: { $avg: '$purityScore' },
                    totalRemediations: { $sum: { $size: '$remediationsApplied' } },
                    failedRecords: { $sum: { $cond: [{ $lt: ['$purityScore', 40] }, 1, 0] } },
                    totalChecks: { $sum: 1 }
                }
            }
        ]);

        res.json({ success: true, data: stats[0] || { avgPurityScore: 100, totalChecks: 0 } });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * @route   GET /api/governance/remediations
 * @desc    Get recent remediation logs
 */
router.get('/remediations', auth, async (req, res) => {
    try {
        const logs = await ValidationLog.find({
            userId: req.user._id,
            'remediationsApplied.0': { $exists: true }
        })
            .sort({ createdAt: -1 })
            .limit(20);

        res.json({ success: true, data: logs });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * @route   GET /api/governance/effective-policy/:workspaceId
 * @desc    Get the fully resolved hierarchical policy for a workspace
 */
router.get('/effective-policy/:workspaceId', auth, async (req, res) => {
    try {
        const policy = await policyResolver.resolveEffectivePolicy(req.params.workspaceId, req.headers['x-tenant-id']);
        res.json({ success: true, data: policy });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * @route   POST /api/governance/policies
 * @desc    Create or update a policy node for Circuit Breakers
 */
router.post('/policies', auth, async (req, res) => {
    try {
        const { workspaceId, name, conditions, action, targetResource, priority, isInheritable } = req.body;

        let node;
        if (workspaceId) {
            node = await PolicyNode.findOneAndUpdate(
                { workspaceId, name },
                { description: req.body.description, conditions, action, targetResource, priority, isInheritable },
                { upsert: true, new: true }
            );
        } else {
            node = await PolicyNode.findOneAndUpdate(
                { level: req.body.level, targetId: req.body.targetId },
                req.body,
                { upsert: true, new: true }
            );
        }

        res.json({ success: true, data: node });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

module.exports = router;
