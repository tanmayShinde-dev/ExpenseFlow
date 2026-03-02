const PrivacyBridge = require('../models/PrivacyBridge');
const homomorphicMath = require('../utils/homomorphicMath');
const Transaction = require('../models/Transaction');
const logger = require('../utils/structuredLogger');

/**
 * ZK Privacy Orchestrator
 * Issue #844: Aggregating cross-tenant metrics using homomorphic and differentially private noise injection.
 * This simulates the zero-knowledge orchestration logic to prevent record reconstruction.
 */
class ZKPrivacyOrchestrator {
    /**
     * Anonymize workspace metrics for aggregate industry benchmarking.
     * Injects differential privacy noise if the workspace has opted into benchmarking.
     */
    async anonymizeAndSum(workspaceId, metrics, options = {}) {
        const { epsilon = 0.5, field = 'amount' } = options;

        const bridge = await PrivacyBridge.findOne({ workspaceId });
        if (!bridge || !bridge.allowBenchmarking) {
            throw new Error('Workspace has not opted into benchmarking or privacy bridge is missing');
        }

        // Check if the privacy budget limit has been reached
        if (bridge.privacyBudgetUsed + epsilon > bridge.privacyBudgetLimit) {
            logger.warn(`Privacy budget exceeded for workspace ${workspaceId}. Skipping anonymization.`);
            return null;
        }

        // Anonymize each value by injecting noise before aggregation
        const randomizedMetrics = metrics.map(val => homomorphicMath.injectNoise(val, epsilon));

        // Use homomorphic property simulation (additive sum)
        const totalSum = homomorphicMath.additiveSum(randomizedMetrics);

        // Consume privacy budget
        bridge.privacyBudgetUsed += epsilon;
        bridge.lastRefreshAt = new Date();
        await bridge.save();

        return {
            anonymizedSum: totalSum,
            count: metrics.length,
            field: field,
            timestamp: new Date()
        };
    }

    /**
     * Compute industry-wide average by combining aggregate sums from multiple tenants.
     */
    async calculateIndustryAverage(aggregates) {
        if (!aggregates || aggregates.length === 0) return 0;

        const totalSum = aggregates.reduce((sum, agg) => sum + agg.anonymizedSum, 0);
        const totalCount = aggregates.reduce((count, agg) => count + agg.count, 0);

        return homomorphicMath.calculateEncryptedAverage(totalSum, totalCount);
    }
}

module.exports = new ZKPrivacyOrchestrator();
