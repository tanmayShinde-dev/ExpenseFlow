const BaseRepository = require('./baseRepository');
const FinancialEvent = require('../models/FinancialEvent');

/**
 * LedgerRepository
 * Issue #782: Specialized high-speed event retrieval for forensic replay.
 */
class LedgerRepository extends BaseRepository {
    constructor() {
        super(FinancialEvent);
    }

    /**
     * Get chronologically ordered event stream for an entity
     */
    async getEventStream(entityId, options = {}) {
        const { limit = 1000, endTimestamp = null } = options;
        const query = { entityId };

        if (endTimestamp) {
            query.timestamp = { $lte: new Date(endTimestamp) };
        }

        return await this.findAll(query, {
            sort: { sequence: 1 },
            limit
        });
    }

    /**
     * Get all event hashes for a workspace within a time range
     */
    async getHashesForRange(workspaceId, startSequence, endSequence) {
        return await this.model.find({
            workspaceId,
            sequence: { $gte: startSequence, $lte: endSequence }
        })
            .sort({ sequence: 1 })
            .select('currentHash')
            .lean();
    }

    /**
     * Find the last event for a workspace
     */
    async findLastEvent(workspaceId) {
        return await this.model.findOne({ workspaceId })
            .sort({ sequence: -1 })
            .lean();
    }
}

module.exports = new LedgerRepository();
