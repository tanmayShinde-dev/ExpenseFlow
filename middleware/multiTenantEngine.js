/**
 * Multi-Tenant Data Isolation and Customization Engine for ExpenseFlow
 *
 * Features:
 * - Strict data isolation between tenants (organizations, user groups)
 * - Tenant-aware data models and APIs
 * - Custom schemas/configurations per tenant
 * - Resource quotas and limits
 * - Tenant-specific logic (workflows, analytics)
 * - Middleware for tenant context and authorization
 * - Partitioned data storage
 * - Secure, scalable, high-performance design
 */

const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const Tenant = require('../models/Tenant');
const User = require('../models/User');
const Workspace = require('../models/Workspace');
const AuditLog = require('../models/AuditLog');

// --- Tenant Context Middleware --- //
function tenantContextMiddleware(req, res, next) {
    try {
        // Extract tenant ID from headers, JWT, or subdomain
        const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId || req.subdomain || null;
        if (!tenantId) {
            return res.status(400).json({ error: 'Tenant ID required' });
        }
        req.tenantId = tenantId;
        next();
    } catch (err) {
        console.error('[TenantContext] Error:', err);
        res.status(500).json({ error: 'Tenant context error' });
    }
}

// --- Tenant-Aware Data Models --- //
// Example: All models include tenantId field
const tenantSchemaOptions = {
    tenantId: { type: String, required: true, index: true }
};

// --- Data Partitioning Helper --- //
function withTenant(query, tenantId) {
    return { ...query, tenantId };
}

// --- Custom Schema/Config per Tenant --- //
async function getTenantConfig(tenantId) {
    const tenant = await Tenant.findOne({ tenantId });
    return tenant?.config || {};
}

// --- Resource Quota Enforcement --- //
async function checkTenantQuota(tenantId, resourceType) {
    const tenant = await Tenant.findOne({ tenantId });
    if (!tenant) throw new Error('Tenant not found');
    const quota = tenant.quotas?.[resourceType] || Infinity;
    const usage = await mongoose.model(resourceType).countDocuments({ tenantId });
    return usage < quota;
}

// --- Tenant-Specific Logic Example --- //
async function runTenantWorkflow(tenantId, workflowName, context) {
    const config = await getTenantConfig(tenantId);
    if (config.workflows && config.workflows[workflowName]) {
        // Execute custom workflow logic
        return await config.workflows[workflowName](context);
    }
    // Default workflow
    return { status: 'default', context };
}

// --- Secure Data Access API --- //
async function getTenantResource(tenantId, resourceType, query = {}) {
    return mongoose.model(resourceType).find(withTenant(query, tenantId));
}

async function createTenantResource(tenantId, resourceType, data) {
    return mongoose.model(resourceType).create({ ...data, tenantId });
}

async function updateTenantResource(tenantId, resourceType, resourceId, updates) {
    return mongoose.model(resourceType).findOneAndUpdate(
        withTenant({ _id: resourceId }, tenantId),
        updates,
        { new: true }
    );
}

async function deleteTenantResource(tenantId, resourceType, resourceId) {
    return mongoose.model(resourceType).findOneAndDelete(withTenant({ _id: resourceId }, tenantId));
}

// --- Complex Authorization Scenarios --- //
function tenantAuthorizationMiddleware(requiredRole) {
    return async (req, res, next) => {
        try {
            const userId = req.user?._id;
            const tenantId = req.tenantId;
            const user = await User.findOne({ _id: userId, tenantId });
            if (!user) return res.status(403).json({ error: 'User not found in tenant' });
            if (!user.roles?.includes(requiredRole)) {
                return res.status(403).json({ error: 'Insufficient role for tenant resource' });
            }
            next();
        } catch (err) {
            console.error('[TenantAuth] Error:', err);
            res.status(500).json({ error: 'Tenant authorization error' });
        }
    };
}

// --- Audit Logging for Isolation --- //
async function logTenantEvent(tenantId, userId, action, resourceType, resourceId, details) {
    await AuditLog.create({
        tenantId,
        user: userId,
        action,
        resourceType,
        resourceId,
        details,
        timestamp: new Date()
    });
}

// --- Exported API --- //
module.exports = {
    tenantContextMiddleware,
    tenantAuthorizationMiddleware,
    getTenantConfig,
    checkTenantQuota,
    runTenantWorkflow,
    getTenantResource,
    createTenantResource,
    updateTenantResource,
    deleteTenantResource,
    logTenantEvent
};
