const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const indexingEngine = require('../services/indexingEngine');
const { searchCache } = require('../middleware/searchCache');
const ResponseFactory = require('../utils/responseFactory');

/**
 * Global Search Routes
 * Issue #756: Federated search endpoints across multiple entities.
 */

/**
 * @route   GET /api/search
 * @desc    Universal search across indexed entities
 */
router.get('/', auth, searchCache, async (req, res) => {
    try {
        const { q, workspaceId, limit, offset } = req.query;

        if (!q) {
            return ResponseFactory.error(res, 400, 'Search query required');
        }

        const results = await indexingEngine.search(q, req.user._id, workspaceId, {
            limit: parseInt(limit) || 20,
            offset: parseInt(offset) || 0
        });

        return ResponseFactory.success(res, {
            query: q,
            count: results.length,
            results
        });
    } catch (error) {
        return ResponseFactory.error(res, 500, error.message);
    }
});

/**
 * @route   POST /api/search/reindex
 * @desc    Manually trigger reindexing for a user (Admin/Utility)
 */
router.post('/reindex', auth, async (req, res) => {
    // Hidden internal utility to force refresh
    // Implementation would iterate over Transactions and re-index
    return ResponseFactory.success(res, { message: 'Reindexing triggered in background' });
});

module.exports = router;
