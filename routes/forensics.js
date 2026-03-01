const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const forensicReplayEngine = require('../services/forensicReplayEngine');
const ledgerService = require('../services/ledgerService');
const ResponseFactory = require('../utils/responseFactory');

/**
 * Forensic & Integrity Routes
 * Issue #782: API for viewing chronological state diffs and replaying history.
 */

/**
 * @route   GET /api/forensics/replay/:entityId
 * @desc    Get the state of an entity at a specific point in time
 */
router.get('/replay/:entityId', auth, async (req, res) => {
    try {
        const { timestamp } = req.query;
        const state = await forensicReplayEngine.getPointInTimeState(
            req.params.entityId,
            timestamp || new Date()
        );

        if (!state) return ResponseFactory.error(res, 404, 'No forensic data found for this entity');

        return ResponseFactory.success(res, state);
    } catch (error) {
        return ResponseFactory.error(res, 500, error.message);
    }
});

/**
 * @route   GET /api/forensics/history/:entityId
 * @desc    Get full audit trail with semantic diffs
 */
router.get('/history/:entityId', auth, async (req, res) => {
    try {
        const history = await forensicReplayEngine.getAuditHistory(req.params.entityId);
        return ResponseFactory.success(res, history);
    } catch (error) {
        return ResponseFactory.error(res, 500, error.message);
    }
});

/**
 * @route   GET /api/forensics/verify/:entityId
 * @desc    Verify the integrity of an entire event chain
 */
router.get('/verify/:entityId', auth, async (req, res) => {
    try {
        const result = await ledgerService.auditChain(req.params.entityId);
        return ResponseFactory.success(res, result);
    } catch (error) {
        return ResponseFactory.error(res, 500, error.message);
    }
});

module.exports = router;
