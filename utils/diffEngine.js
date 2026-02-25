/**
 * Diff Engine Utility
 * Issue #769: Calculating patch deltas between pending and current states.
 */
class DiffEngine {
    /**
     * Compare two objects and return only the changes
     */
    static calculateDelta(current, pending) {
        const delta = {};
        const keys = new Set([...Object.keys(current), ...Object.keys(pending)]);

        for (const key of keys) {
            // Ignore internal mongoose fields
            if (key.startsWith('_') || key === 'createdAt' || key === 'updatedAt') continue;

            const val1 = current[key];
            const val2 = pending[key];

            if (JSON.stringify(val1) !== JSON.stringify(val2)) {
                delta[key] = {
                    old: val1,
                    new: val2
                };
            }
        }
        return delta;
    }

    /**
     * Apply a delta patch to an object
     */
    static applyPatch(base, patch) {
        const result = { ...base };
        for (const [key, change] of Object.entries(patch)) {
            result[key] = change.new;
        }
        return result;
    }
}

module.exports = DiffEngine;
