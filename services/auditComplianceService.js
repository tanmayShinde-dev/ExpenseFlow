const crypto = require('crypto');
const ImmutableAuditLog = require('../models/ImmutableAuditLog');
const ComplianceViolation = require('../models/ComplianceViolation');
const Workspace = require('../models/Workspace');

class AuditComplianceService {
  constructor() {
    this.complianceRules = new Map();
    this.setupComplianceRules();
  }

  setupComplianceRules() {
    this.complianceRules.set('data_retention', { days: 2555 });
    this.complianceRules.set('access_logging', { enabled: true });
    this.complianceRules.set('immutability', { enabled: true, hashChain: true });
    this.complianceRules.set('forensic_export', { enabled: true });
  }

  async validateWorkspaceAccess(userId, workspaceId) {
    if (!workspaceId) return true;

    const hasAccess = await Workspace.exists({
      _id: workspaceId,
      $or: [
        { owner: userId },
        { 'members.user': userId }
      ]
    });

    if (!hasAccess) {
      throw new Error('Access denied for requested workspace');
    }

    return true;
  }

  async logImmutableAudit(userId, action, entityType, entityId = null, changes = {}, options = {}) {
    const record = await ImmutableAuditLog.create({
      userId,
      workspaceId: options.workspaceId || null,
      action,
      entityType,
      entityId,
      changes: {
        before: changes.before,
        after: changes.after
      },
      metadata: {
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        sessionId: options.sessionId,
        apiEndpoint: options.apiEndpoint,
        requestId: options.requestId,
        geolocation: options.geolocation,
        deviceInfo: options.deviceInfo,
        correlationId: options.correlationId,
        timelineId: options.timelineId,
        tags: options.tags || []
      },
      riskLevel: options.riskLevel || 'low',
      complianceFlags: options.complianceFlags || []
    });

    return record;
  }

  async verifyAuditIntegrity(startSequence = null, endSequence = null, workspaceId = null) {
    const query = {};
    if (workspaceId) query.workspaceId = workspaceId;
    if (startSequence !== null || endSequence !== null) {
      query.sequenceNumber = {};
      if (startSequence !== null) query.sequenceNumber.$gte = Number(startSequence);
      if (endSequence !== null) query.sequenceNumber.$lte = Number(endSequence);
    }

    const logs = await ImmutableAuditLog.find(query).sort({ sequenceNumber: 1 }).lean();

    if (logs.length === 0) {
      return {
        verified: true,
        checked: 0,
        issues: [],
        message: 'No logs found for requested range'
      };
    }

    const issues = [];
    let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (const log of logs) {
      if (log.previousHash !== previousHash) {
        issues.push({
          sequenceNumber: log.sequenceNumber,
          type: 'CHAIN_BREAK',
          expected: previousHash,
          actual: log.previousHash
        });
      }

      const expectedSignature = crypto
        .createHmac('sha256', process.env.AUDIT_SIGNATURE_KEY || 'default-key')
        .update(log.currentHash)
        .digest('hex');

      if (expectedSignature !== log.signature) {
        issues.push({
          sequenceNumber: log.sequenceNumber,
          type: 'INVALID_SIGNATURE'
        });
      }

      previousHash = log.currentHash;
    }

    return {
      verified: issues.length === 0,
      checked: logs.length,
      issues,
      startSequence: logs[0].sequenceNumber,
      endSequence: logs[logs.length - 1].sequenceNumber
    };
  }

  async reconstructTimeline(filters = {}) {
    const query = {};

    if (filters.workspaceId) query.workspaceId = filters.workspaceId;
    if (filters.userId) query.userId = filters.userId;
    if (filters.entityType) query.entityType = filters.entityType;
    if (filters.entityId) query.entityId = filters.entityId;
    if (filters.requestId) query['metadata.requestId'] = filters.requestId;
    if (filters.sessionId) query['metadata.sessionId'] = filters.sessionId;
    if (filters.correlationId) query['metadata.correlationId'] = filters.correlationId;
    if (filters.action) query.action = filters.action;
    if (filters.riskLevel) query.riskLevel = filters.riskLevel;

    if (filters.startDate || filters.endDate) {
      query.createdAt = {};
      if (filters.startDate) query.createdAt.$gte = new Date(filters.startDate);
      if (filters.endDate) query.createdAt.$lte = new Date(filters.endDate);
    }

    const limit = Math.min(Number(filters.limit) || 500, 5000);
    const logs = await ImmutableAuditLog.find(query)
      .populate('userId', 'name email')
      .sort({ createdAt: 1, sequenceNumber: 1 })
      .limit(limit)
      .lean();

    return {
      count: logs.length,
      startedAt: logs[0]?.createdAt || null,
      endedAt: logs[logs.length - 1]?.createdAt || null,
      timeline: logs
    };
  }

  async correlateAnomalies(filters = {}) {
    const matchStage = {};
    if (filters.workspaceId) matchStage.workspaceId = filters.workspaceId;
    if (filters.startDate || filters.endDate) {
      matchStage.createdAt = {};
      if (filters.startDate) matchStage.createdAt.$gte = new Date(filters.startDate);
      if (filters.endDate) matchStage.createdAt.$lte = new Date(filters.endDate);
    }

    const suspiciousActions = filters.actions || [
      'login_failed',
      'login_blocked',
      'suspicious_activity',
      'rate_limit_exceeded',
      'ip_blocked',
      'account_locked'
    ];

    matchStage.$or = [
      { action: { $in: suspiciousActions } },
      { status: 'failure' },
      { riskLevel: { $in: ['high', 'critical'] } }
    ];

    const correlatedByIp = await ImmutableAuditLog.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$metadata.ipAddress',
          events: { $sum: 1 },
          uniqueUsers: { $addToSet: '$userId' },
          latestEvent: { $max: '$createdAt' },
          highRiskCount: {
            $sum: {
              $cond: [{ $in: ['$riskLevel', ['high', 'critical']] }, 1, 0]
            }
          }
        }
      },
      {
        $project: {
          ipAddress: '$_id',
          eventCount: '$events',
          uniqueUserCount: { $size: '$uniqueUsers' },
          latestEvent: 1,
          highRiskCount: 1,
          _id: 0
        }
      },
      { $sort: { eventCount: -1 } },
      { $limit: 100 }
    ]);

    const correlatedBySession = await ImmutableAuditLog.aggregate([
      { $match: matchStage },
      { $match: { 'metadata.sessionId': { $nin: [null, ''] } } },
      {
        $group: {
          _id: '$metadata.sessionId',
          events: { $sum: 1 },
          actions: { $addToSet: '$action' },
          firstSeen: { $min: '$createdAt' },
          lastSeen: { $max: '$createdAt' }
        }
      },
      { $sort: { events: -1 } },
      { $limit: 100 }
    ]);

    return {
      byIp: correlatedByIp,
      bySession: correlatedBySession,
      generatedAt: new Date()
    };
  }

  async generateComplianceReport(standard, workspaceId = null, dateRange = {}) {
    if (workspaceId) {
      await this.validateWorkspaceAccess(dateRange.requestedBy || null, workspaceId).catch(() => {});
    }

    const query = {};
    if (workspaceId) query.workspaceId = workspaceId;
    if (dateRange.start || dateRange.end) {
      query.createdAt = {};
      if (dateRange.start) query.createdAt.$gte = new Date(dateRange.start);
      if (dateRange.end) query.createdAt.$lte = new Date(dateRange.end);
    }

    const [totalLogs, standardFlags, violations] = await Promise.all([
      ImmutableAuditLog.countDocuments(query),
      ImmutableAuditLog.countDocuments({
        ...query,
        complianceFlags: { $elemMatch: { standard } }
      }),
      ComplianceViolation.find({
        ...(workspaceId ? { workspaceId } : {}),
        standard
      })
        .sort({ createdAt: -1 })
        .limit(500)
        .lean()
    ]);

    const openViolations = violations.filter(v => v.status !== 'resolved').length;
    const criticalViolations = violations.filter(v => v.severity === 'critical').length;

    return {
      standard,
      workspaceId,
      period: {
        start: dateRange.start || null,
        end: dateRange.end || null
      },
      summary: {
        totalLogs,
        standardFlags,
        totalViolations: violations.length,
        openViolations,
        criticalViolations
      },
      violations,
      generatedAt: new Date().toISOString()
    };
  }

  async applyLegalHold(entityType, entityId, reason, holdBy) {
    const result = await ImmutableAuditLog.updateMany(
      { entityType, entityId },
      {
        $set: {
          'retentionPolicy.legalHold': true,
          'retentionPolicy.holdReason': reason,
          'retentionPolicy.holdBy': holdBy
        }
      }
    );

    return result;
  }

  async releaseLegalHold(entityType, entityId, releasedBy) {
    const result = await ImmutableAuditLog.updateMany(
      { entityType, entityId },
      {
        $set: {
          'retentionPolicy.legalHold': false,
          'retentionPolicy.holdReason': null,
          'retentionPolicy.holdBy': releasedBy
        }
      }
    );

    return result;
  }

  async calculateOverallComplianceScore(workspaceId = null) {
    const baseQuery = workspaceId ? { workspaceId } : {};
    const [totalLogs, violations, criticalViolations, highRiskLogs] = await Promise.all([
      ImmutableAuditLog.countDocuments(baseQuery),
      ComplianceViolation.countDocuments({ ...(workspaceId ? { workspaceId } : {}), status: { $ne: 'resolved' } }),
      ComplianceViolation.countDocuments({ ...(workspaceId ? { workspaceId } : {}), severity: 'critical', status: { $ne: 'resolved' } }),
      ImmutableAuditLog.countDocuments({ ...baseQuery, riskLevel: { $in: ['high', 'critical'] } })
    ]);

    if (totalLogs === 0) return 100;

    const violationPenalty = Math.min(40, violations * 2);
    const criticalPenalty = Math.min(30, criticalViolations * 5);
    const riskPenalty = Math.min(20, Math.round((highRiskLogs / totalLogs) * 100));

    return Math.max(0, 100 - violationPenalty - criticalPenalty - riskPenalty);
  }

  convertToCSV(logs = []) {
    if (!logs.length) return 'sequenceNumber,createdAt,userId,workspaceId,action,entityType,riskLevel\n';

    const escape = (value) => {
      if (value === null || value === undefined) return '';
      const str = typeof value === 'string' ? value : JSON.stringify(value);
      return `"${str.replace(/"/g, '""')}"`;
    };

    const headers = [
      'sequenceNumber', 'createdAt', 'userId', 'workspaceId', 'action',
      'entityType', 'entityId', 'riskLevel', 'apiEndpoint', 'ipAddress', 'requestId'
    ];

    const rows = logs.map((log) => {
      return [
        log.sequenceNumber,
        log.createdAt,
        log.userId?._id || log.userId,
        log.workspaceId,
        log.action,
        log.entityType,
        log.entityId,
        log.riskLevel,
        log.metadata?.apiEndpoint,
        log.metadata?.ipAddress,
        log.metadata?.requestId
      ].map(escape).join(',');
    });

    return `${headers.join(',')}\n${rows.join('\n')}`;
  }

  convertToXML(logs = []) {
    const records = logs.map((log) => `
  <auditLog>
    <sequenceNumber>${log.sequenceNumber || ''}</sequenceNumber>
    <createdAt>${log.createdAt || ''}</createdAt>
    <userId>${log.userId?._id || log.userId || ''}</userId>
    <workspaceId>${log.workspaceId || ''}</workspaceId>
    <action>${log.action || ''}</action>
    <entityType>${log.entityType || ''}</entityType>
    <entityId>${log.entityId || ''}</entityId>
    <riskLevel>${log.riskLevel || ''}</riskLevel>
    <apiEndpoint>${log.metadata?.apiEndpoint || ''}</apiEndpoint>
    <ipAddress>${log.metadata?.ipAddress || ''}</ipAddress>
    <requestId>${log.metadata?.requestId || ''}</requestId>
  </auditLog>`).join('');

    return `<?xml version="1.0" encoding="UTF-8"?>\n<auditLogs>${records}\n</auditLogs>`;
  }

  getComplianceStatus() {
    return {
      status: 'active',
      rules: Object.fromEntries(this.complianceRules),
      lastCheck: new Date()
    };
  }
}

module.exports = new AuditComplianceService();