const BaseRepository = require('./baseRepository');
const TreasuryNode = require('../models/TreasuryNode');

/**
 * TreasuryRepository
 * Issue #768: Specialized data access for virtual balances.
 */
class TreasuryRepository extends BaseRepository {
    constructor() {
        super(TreasuryNode);
    }

    /**
     * Get all nodes for a workspace
     */
    async findByWorkspace(workspaceId) {
        return await this.findAll({ workspaceId });
    }

    /**
     * Get specific node type for a workspace
     */
    async findNode(workspaceId, nodeType) {
        return await this.findOne({ workspaceId, nodeType });
    }

    /**
     * Atomic balance update
     */
    async updateBalance(nodeId, amount) {
        return await this.model.findByIdAndUpdate(
            nodeId,
            { $inc: { balance: amount } },
            { new: true }
        );
    }

    /**
     * Reserve funds for pending transaction
     */
    async reserveFunds(nodeId, amount) {
        const node = await this.model.findById(nodeId);
        if (node.balance - node.reservedAmount < amount) {
            throw new Error('Insufficient liquidity in treasury node');
        }

        return await this.model.findByIdAndUpdate(
            nodeId,
            { $inc: { reservedAmount: amount } },
            { new: true }
        );
    }
}

module.exports = new TreasuryRepository();
