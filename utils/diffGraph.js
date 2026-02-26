/**
 * DiffGraph Utility
 * Issue #781: Calculating dependency paths in workspace hierarchies.
 */
class DiffGraph {
    /**
     * Compute path of ancestors to invalidate recursively
     * E.g., Team -> Dept -> Company
     */
    static async getInvalidationPaths(startWorkspaceId) {
        if (!startWorkspaceId) return [];
        const Workspace = require('../models/Workspace');
        const paths = [startWorkspaceId.toString()];
        let currentId = startWorkspaceId;

        while (currentId) {
            const ws = await Workspace.findById(currentId).select('parentWorkspaceId');
            if (ws && ws.parentWorkspaceId) {
                paths.push(ws.parentWorkspaceId.toString());
                currentId = ws.parentWorkspaceId;
            } else {
                currentId = null;
            }
        }

        return paths;
    }
}

module.exports = DiffGraph;
