const SearchIndex = require('../models/SearchIndex');
const logger = require('../utils/structuredLogger');

/**
 * Indexing Engine
 * Issue #756: The brain for tokenization and cross-entity indexing.
 * Transforms raw database objects into searchable, tenant-isolated vectors.
 */
class IndexingEngine {
    /**
     * Index a single entity
     */
    async indexEntity(entityType, entityData, userId, workspaceId = null) {
        try {
            const tokens = this._tokenize(entityData);

            const indexData = {
                entityId: entityData._id,
                entityType,
                workspaceId,
                userId,
                tokens,
                metadata: {
                    description: entityData.description || entityData.name,
                    amount: entityData.amount,
                    category: entityData.category,
                    merchant: entityData.merchant,
                    date: entityData.date
                },
                lastIndexedAt: new Date()
            };

            await SearchIndex.findOneAndUpdate(
                { entityId: entityData._id },
                indexData,
                { upsert: true, new: true }
            );

            // console.log(`[IndexingEngine] Indexed ${entityType}: ${entityData._id}`);
        } catch (error) {
            logger.error('[IndexingEngine] Error indexing entity:', {
                entityId: entityData._id,
                error: error.message
            });
        }
    }

    /**
     * Remove an entity from the search index
     */
    async deindexEntity(entityId) {
        await SearchIndex.deleteOne({ entityId });
    }

    /**
     * Core Tokenization Logic
     * Splits strings into searchable chunks, removes stop words, and normalizes casing.
     */
    _tokenize(data) {
        const fields = [
            data.description,
            data.merchant,
            data.categoryName, // Optional enrichment
            data.notes
        ].filter(Boolean);

        const rawText = fields.join(' ').toLowerCase();

        // Basic n-gram or word splitting
        const words = rawText.split(/[^a-z0-9]+/).filter(w => w.length > 2);

        // Add specific data like amount as tokens for numeric searching support
        if (data.amount) {
            words.push(`amt:${Math.floor(data.amount)}`);
        }

        return [...new Set(words)]; // Return unique tokens
    }

    /**
     * Search across the index
     */
    async search(query, userId, workspaceId = null, options = {}) {
        const { limit = 20, offset = 0 } = options;
        const tokens = query.toLowerCase().split(/\s+/).filter(t => t.length > 0);

        const filter = {
            userId: userId,
            tokens: { $all: tokens }
        };

        if (workspaceId) {
            filter.workspaceId = workspaceId;
        }

        return await SearchIndex.find(filter)
            .sort({ score: -1, lastIndexedAt: -1 })
            .skip(offset)
            .limit(limit)
            .lean();
    }
}

module.exports = new IndexingEngine();
