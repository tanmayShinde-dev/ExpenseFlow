const ledgerRepository = require('../repositories/ledgerRepository');
const diffReconstructor = require('../utils/diffReconstructor');
const logger = require('../utils/structuredLogger');

/**
 * Forensic Replay Engine Service
 * Issue #782: Reconstructing entity state by replaying financial events.
 * Allows "Time-Travel" debugging of any record in the system.
 */
class ForensicReplayEngine {
    /**
     * Reconstruct state of an entity at a specific point in time
     */
    async getPointInTimeState(entityId, timestamp) {
        logger.info(`[ForensicEngine] Reconstructing state for ${entityId} at ${timestamp}`);

        // 1. Fetch events up to that timestamp
        const events = await ledgerRepository.getEventStream(entityId, { endTimestamp: timestamp });

        if (events.length === 0) {
            return null;
        }

        // 2. Replay events to build state
        const state = diffReconstructor.reconstruct({}, events);

        return {
            entityId,
            timestamp,
            version: events[events.length - 1].sequence,
            state
        };
    }

    /**
     * Get a chronological diff history for an entity
     */
    async getAuditHistory(entityId) {
        const events = await ledgerRepository.getEventStream(entityId);
        const history = [];

        let lastState = {};
        for (const event of events) {
            const currentState = diffReconstructor.reconstruct(lastState, [event]);
            const diff = diffReconstructor.getDiff(lastState, currentState);

            history.push({
                sequence: event.sequence,
                timestamp: event.timestamp,
                eventType: event.eventType,
                performedBy: event.performedBy,
                changes: diff
            });

            lastState = currentState;
        }

        return history;
    }
}

module.exports = new ForensicReplayEngine();
