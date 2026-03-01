/**
 * Advanced RBAC Middleware & Service for ExpenseFlow
 * Supports hierarchical roles, dynamic permissions, contextual access, fine-grained resource controls, custom policies, and auditing
 *
 * Features:
 * - Hierarchical roles with inheritance
 * - Dynamic permission assignment (per user, role, resource)
 * - Contextual access (time, location, device, etc.)
 * - Fine-grained resource controls
 * - Custom policy support
 * - Integration hooks for external identity providers
 * - Auditing and access logging
 * - Scalable data models
 * - Complex middleware for request validation
 */

const mongoose = require('mongoose');
const geoip = require('geoip-lite');
const AuditLog = require('../models/AuditLog');
const User = require('../models/User');
const Workspace = require('../models/Workspace');
const Permission = require('../models/Permission');
const Role = require('../models/Role');
const Policy = require('../models/Policy');

// --- Data Models --- //
// Role, Permission, Policy, AuditLog, User, Workspace
// These should be defined in ../models, but here are schemas for reference

// Role: { name, inherits: [roleIds], permissions: [permissionIds], description }
// Permission: { name, resource, actions: ["read", "write", ...], conditions }
// Policy: { name, description, rules: [{ resource, action, conditionFn }] }
// AuditLog: { user, action, resource, result, timestamp, context }

// --- Role Hierarchy & Inheritance --- //
async function getEffectiveRoles(userId, workspaceId) {
    // Get direct roles
    const user = await User.findById(userId);
    const workspace = await Workspace.findById(workspaceId);
    let roles = [];
    if (workspace) {
        const member = workspace.members.find(m => m.user.toString() === userId.toString());
        if (member) roles.push(member.role);
    }
    if (user && user.globalRoles) roles = roles.concat(user.globalRoles);
    // Expand inherited roles
    let expanded = new Set(roles);
    for (const roleName of roles) {
        const role = await Role.findOne({ name: roleName });
        if (role && role.inherits) {
            role.inherits.forEach(r => expanded.add(r));
        }
    }
    return Array.from(expanded);
}

// --- Dynamic Permission Assignment --- //
async function getEffectivePermissions(userId, workspaceId) {
    const roles = await getEffectiveRoles(userId, workspaceId);
    let permissions = [];
    for (const roleName of roles) {
        const role = await Role.findOne({ name: roleName });
        if (role && role.permissions) {
            permissions = permissions.concat(role.permissions);
        }
    }
    // Add user-specific permissions
    const user = await User.findById(userId);
    if (user && user.permissions) permissions = permissions.concat(user.permissions);
    // Add workspace-specific permissions
    const workspace = await Workspace.findById(workspaceId);
    if (workspace && workspace.permissions) permissions = permissions.concat(workspace.permissions);
    // Remove duplicates
    return Array.from(new Set(permissions));
}

// --- Contextual Access Checks --- //
function checkContextualAccess(req, permission) {
    // Example: time-based, location-based, device-based
    if (permission.conditions) {
        for (const cond of permission.conditions) {
            if (cond.type === 'time') {
                const now = new Date();
                if (now < new Date(cond.start) || now > new Date(cond.end)) return false;
            }
            if (cond.type === 'location') {
                const ip = req.ip;
                const geo = geoip.lookup(ip);
                if (!geo || !cond.allowedCountries.includes(geo.country)) return false;
            }
            if (cond.type === 'device') {
                if (!req.headers['user-agent'] || !cond.allowedDevices.includes(req.headers['user-agent'])) return false;
            }
        }
    }
    return true;
}

// --- Fine-Grained Resource Controls --- //
function matchResource(resource, permissionResource) {
    // Wildcard, regex, or direct match
    if (permissionResource === '*') return true;
    if (permissionResource === resource) return true;
    if (permissionResource.endsWith('/*')) {
        return resource.startsWith(permissionResource.slice(0, -1));
    }
    return false;
}

// --- Custom Policy Support --- //
async function checkCustomPolicies(userId, action, resource, context) {
    const policies = await Policy.find({});
    for (const policy of policies) {
        for (const rule of policy.rules) {
            if (matchResource(resource, rule.resource) && rule.action === action) {
                if (typeof rule.conditionFn === 'function') {
                    if (!rule.conditionFn(userId, context)) return false;
                }
            }
        }
    }
    return true;
}

// --- Auditing & Access Logging --- //
async function logAccessAttempt({ user, action, resource, result, context }) {
    await AuditLog.create({
        user,
        action,
        resource,
        result,
        timestamp: new Date(),
        context
    });
}

// --- RBAC Middleware --- //
function rbacMiddleware(requiredAction, resourceType) {
    return async (req, res, next) => {
        try {
            const userId = req.user._id;
            const workspaceId = req.workspace?._id || req.body.workspaceId || req.query.workspaceId;
            const resource = resourceType || req.originalUrl;
            const context = {
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                time: new Date(),
                location: geoip.lookup(req.ip)
            };

            // Get permissions
            const permissionIds = await getEffectivePermissions(userId, workspaceId);
            const permissions = await Permission.find({ _id: { $in: permissionIds } });
            let allowed = false;
            for (const perm of permissions) {
                if (perm.actions.includes(requiredAction) && matchResource(resource, perm.resource)) {
                    if (checkContextualAccess(req, perm)) {
                        allowed = true;
                        break;
                    }
                }
            }
            // Custom policy check
            if (allowed) {
                allowed = await checkCustomPolicies(userId, requiredAction, resource, context);
            }
            // Log access attempt
            await logAccessAttempt({ user: userId, action: requiredAction, resource, result: allowed ? 'allowed' : 'denied', context });
            if (!allowed) {
                return res.status(403).json({ error: 'Access denied by RBAC policy' });
            }
            next();
        } catch (err) {
            console.error('[RBAC] Error:', err);
            res.status(500).json({ error: 'RBAC middleware error' });
        }
    };
}

// --- Dynamic Permission Assignment API --- //
// Assign, revoke, update permissions for users/roles/resources
async function assignPermissionToRole(roleName, permissionId) {
    const role = await Role.findOne({ name: roleName });
    if (!role) throw new Error('Role not found');
    if (!role.permissions.includes(permissionId)) role.permissions.push(permissionId);
    await role.save();
}

async function revokePermissionFromRole(roleName, permissionId) {
    const role = await Role.findOne({ name: roleName });
    if (!role) throw new Error('Role not found');
    role.permissions = role.permissions.filter(p => p.toString() !== permissionId.toString());
    await role.save();
}

async function assignPermissionToUser(userId, permissionId) {
    const user = await User.findById(userId);
    if (!user) throw new Error('User not found');
    if (!user.permissions.includes(permissionId)) user.permissions.push(permissionId);
    await user.save();
}

async function revokePermissionFromUser(userId, permissionId) {
    const user = await User.findById(userId);
    if (!user) throw new Error('User not found');
    user.permissions = user.permissions.filter(p => p.toString() !== permissionId.toString());
    await user.save();
}

// --- Role Management API --- //
async function createRole({ name, inherits = [], permissions = [], description = '' }) {
    const role = new Role({ name, inherits, permissions, description });
    await role.save();
    return role;
}

async function updateRole(roleId, updates) {
    const role = await Role.findById(roleId);
    if (!role) throw new Error('Role not found');
    Object.assign(role, updates);
    await role.save();
    return role;
}

async function deleteRole(roleId) {
    await Role.findByIdAndDelete(roleId);
}

// --- Permission Management API --- //
async function createPermission({ name, resource, actions = [], conditions = [] }) {
    const permission = new Permission({ name, resource, actions, conditions });
    await permission.save();
    return permission;
}

async function updatePermission(permissionId, updates) {
    const permission = await Permission.findById(permissionId);
    if (!permission) throw new Error('Permission not found');
    Object.assign(permission, updates);
    await permission.save();
    return permission;
}

async function deletePermission(permissionId) {
    await Permission.findByIdAndDelete(permissionId);
}

// --- Policy Management API --- //
async function createPolicy({ name, description, rules }) {
    const policy = new Policy({ name, description, rules });
    await policy.save();
    return policy;
}

async function updatePolicy(policyId, updates) {
    const policy = await Policy.findById(policyId);
    if (!policy) throw new Error('Policy not found');
    Object.assign(policy, updates);
    await policy.save();
    return policy;
}

async function deletePolicy(policyId) {
    await Policy.findByIdAndDelete(policyId);
}

// --- Audit Log Query API --- //
async function getAuditLogs({ user, resource, action, from, to, result }) {
    const query = {};
    if (user) query.user = user;
    if (resource) query.resource = resource;
    if (action) query.action = action;
    if (result) query.result = result;
    if (from || to) query.timestamp = {};
    if (from) query.timestamp.$gte = new Date(from);
    if (to) query.timestamp.$lte = new Date(to);
    return AuditLog.find(query).sort({ timestamp: -1 });
}

// --- External Identity Provider Integration --- //
async function syncExternalRoles(userId, externalRoles) {
    // Map external roles to internal roles
    const user = await User.findById(userId);
    if (!user) throw new Error('User not found');
    user.externalRoles = externalRoles;
    await user.save();
}

// --- Exported API --- //
module.exports = {
    rbacMiddleware,
    assignPermissionToRole,
    revokePermissionFromRole,
    assignPermissionToUser,
    revokePermissionFromUser,
    createRole,
    updateRole,
    deleteRole,
    createPermission,
    updatePermission,
    deletePermission,
    createPolicy,
    updatePolicy,
    deletePolicy,
    getAuditLogs,
    syncExternalRoles
};
