const mongoose = require('mongoose');

/**
 * PolicyNode Model
 * Issue #780: Hierarchical compliance constraints and Circuit Breakers.
 */
const policyNodeSchema = new mongoose.Schema({
    workspaceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Workspace', index: true },
    name: { type: String, required: true },
    description: String,

    // Conditions using a JSON AST for the Predicate Engine
    conditions: { type: mongoose.Schema.Types.Mixed, required: true },

    action: {
        type: String,
        enum: ['FLAG', 'FREEZE', 'DENY', 'NOTIFY'],
        required: true
    },

    targetResource: {
        type: String,
        enum: ['TRANSACTION', 'USER', 'WORKSPACE', 'TREASURY'],
        default: 'TRANSACTION'
    },

    priority: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    isInheritable: { type: Boolean, default: true }
}, {
    timestamps: true
});

module.exports = mongoose.model('PolicyNode', policyNodeSchema);
