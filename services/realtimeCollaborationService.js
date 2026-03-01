const mongoose = require('mongoose');
const CollaborativeDocument = require('../models/CollaborativeDocument');

const MAX_OPERATION_HISTORY = 10000;
const MAX_APPLIED_OPS = 20000;

class RealtimeCollaborationService {
  constructor() {
    this.retryLimit = 3;
  }

  createDefaultState() {
    return {
      clock: 0,
      version: 0,
      vectorClock: {},
      appliedOps: [],
      atoms: [],
      registers: {},
      cells: {}
    };
  }

  ensureState(document) {
    if (!document.state || typeof document.state !== 'object') {
      document.state = this.createDefaultState();
    }

    document.state.clock = Number(document.state.clock) || 0;
    document.state.version = Number(document.state.version) || 0;
    document.state.vectorClock = document.state.vectorClock || {};
    document.state.appliedOps = Array.isArray(document.state.appliedOps) ? document.state.appliedOps : [];
    document.state.atoms = Array.isArray(document.state.atoms) ? document.state.atoms : [];
    document.state.registers = document.state.registers || {};
    document.state.cells = document.state.cells || {};

    document.operations = Array.isArray(document.operations) ? document.operations : [];
  }

  getActorId(userId) {
    return String(userId);
  }

  compareOperationIds(idA, idB) {
    return String(idA).localeCompare(String(idB));
  }

  compareTimestamps(a, b) {
    if (a.lamport !== b.lamport) {
      return a.lamport - b.lamport;
    }

    const actorComparison = String(a.actorId).localeCompare(String(b.actorId));
    if (actorComparison !== 0) {
      return actorComparison;
    }

    return String(a.opId).localeCompare(String(b.opId));
  }

  linearizeAtoms(atoms) {
    const atomMap = new Map();
    const childrenMap = new Map();

    for (const atom of atoms) {
      atomMap.set(atom.id, atom);
      const leftId = atom.leftId || 'HEAD';
      if (!childrenMap.has(leftId)) {
        childrenMap.set(leftId, []);
      }
      childrenMap.get(leftId).push(atom);
    }

    for (const children of childrenMap.values()) {
      children.sort((a, b) => this.compareOperationIds(a.id, b.id));
    }

    const ordered = [];
    const walk = (leftId) => {
      const children = childrenMap.get(leftId) || [];
      for (const atom of children) {
        ordered.push(atom);
        walk(atom.id);
      }
    };

    walk('HEAD');
    return ordered;
  }

  buildTextSnapshot(state) {
    const ordered = this.linearizeAtoms(state.atoms);
    const text = ordered
      .filter((atom) => !atom.deleted)
      .map((atom) => atom.value)
      .join('');

    return {
      text,
      atomCount: state.atoms.length,
      visibleCharCount: text.length
    };
  }

  sanitizeParticipant(userId, role = 'editor') {
    const normalizedRole = ['owner', 'editor', 'viewer'].includes(role) ? role : 'editor';
    return {
      user: new mongoose.Types.ObjectId(userId),
      role: normalizedRole,
      lastSeenAt: new Date()
    };
  }

  async createDocument({ title, docType = 'document', workspace = null, createdBy, participants = [] }) {
    const participantMap = new Map();
    participantMap.set(String(createdBy), this.sanitizeParticipant(createdBy, 'owner'));

    for (const participant of participants) {
      if (!participant?.user) {
        continue;
      }
      participantMap.set(
        String(participant.user),
        this.sanitizeParticipant(participant.user, participant.role || 'editor')
      );
    }

    const document = await CollaborativeDocument.create({
      title,
      docType,
      workspace,
      createdBy,
      participants: Array.from(participantMap.values()),
      state: this.createDefaultState(),
      metadata: {
        lastSyncedAt: new Date(),
        activeEditors: 0
      }
    });

    return this.buildDocumentPayload(document);
  }

  canAccess(document, userId) {
    const userIdStr = String(userId);
    if (String(document.createdBy) === userIdStr) {
      return true;
    }

    return document.participants.some((participant) => String(participant.user) === userIdStr);
  }

  canEdit(document, userId) {
    const userIdStr = String(userId);
    if (String(document.createdBy) === userIdStr) {
      return true;
    }

    const participant = document.participants.find((candidate) => String(candidate.user) === userIdStr);
    return Boolean(participant && participant.role !== 'viewer');
  }

  async getDocument(documentId, userId) {
    const document = await CollaborativeDocument.findById(documentId);
    if (!document) {
      throw new Error('Collaborative document not found');
    }

    if (!this.canAccess(document, userId)) {
      const error = new Error('Access denied for this document');
      error.status = 403;
      throw error;
    }

    this.ensureState(document);
    return this.buildDocumentPayload(document);
  }

  buildDocumentPayload(document) {
    this.ensureState(document);

    return {
      id: document._id,
      title: document.title,
      docType: document.docType,
      workspace: document.workspace,
      createdBy: document.createdBy,
      participants: document.participants,
      version: document.state.version,
      clock: document.state.clock,
      vectorClock: document.state.vectorClock,
      text: this.buildTextSnapshot(document.state).text,
      registers: document.state.registers,
      cells: document.state.cells,
      updatedAt: document.updatedAt
    };
  }

  ensureParticipantPresence(document, userId) {
    const now = new Date();
    const userIdStr = String(userId);
    const participant = document.participants.find((candidate) => String(candidate.user) === userIdStr);

    if (participant) {
      participant.lastSeenAt = now;
      return;
    }

    document.participants.push(this.sanitizeParticipant(userId, 'editor'));
  }

  normalizeOperation(rawOperation, actorId, deviceId, sequenceFallback) {
    if (!rawOperation || typeof rawOperation !== 'object') {
      throw new Error('Invalid operation payload');
    }

    const type = rawOperation.type;
    if (!['insert', 'delete', 'set_field', 'set_cell'].includes(type)) {
      throw new Error(`Unsupported operation type: ${type}`);
    }

    const opId = rawOperation.opId || `${actorId}:${deviceId || 'device'}:${sequenceFallback}`;
    const payload = rawOperation.payload && typeof rawOperation.payload === 'object'
      ? rawOperation.payload
      : {};

    return {
      opId,
      type,
      actorId,
      deviceId: deviceId || 'unknown-device',
      payload
    };
  }

  applyInsert(state, operation, lamport) {
    const value = String(operation.payload.value || '');
    const leftId = operation.payload.leftId || 'HEAD';
    const charId = operation.payload.charId || operation.opId;

    if (!value) {
      return false;
    }

    if (state.atoms.some((atom) => atom.id === charId)) {
      return false;
    }

    state.atoms.push({
      id: charId,
      leftId,
      value,
      deleted: false,
      lamport,
      actorId: operation.actorId,
      opId: operation.opId
    });

    return true;
  }

  applyDelete(state, operation) {
    const targetId = operation.payload.targetId;
    if (!targetId) {
      return false;
    }

    const target = state.atoms.find((atom) => atom.id === targetId);
    if (!target || target.deleted) {
      return false;
    }

    target.deleted = true;
    return true;
  }

  updateLwwRegister(registerMap, key, value, metadata) {
    const current = registerMap[key];
    if (!current) {
      registerMap[key] = {
        value,
        lamport: metadata.lamport,
        actorId: metadata.actorId,
        opId: metadata.opId
      };
      return true;
    }

    const comparison = this.compareTimestamps(
      { lamport: current.lamport, actorId: current.actorId, opId: current.opId },
      metadata
    );

    if (comparison <= 0) {
      registerMap[key] = {
        value,
        lamport: metadata.lamport,
        actorId: metadata.actorId,
        opId: metadata.opId
      };
      return true;
    }

    return false;
  }

  applyFieldSet(state, operation, lamport) {
    const field = operation.payload.field;
    if (!field) {
      return false;
    }

    return this.updateLwwRegister(state.registers, field, operation.payload.value, {
      lamport,
      actorId: operation.actorId,
      opId: operation.opId
    });
  }

  applyCellSet(state, operation, lamport) {
    const cellKey = operation.payload.cellKey;
    if (!cellKey) {
      return false;
    }

    return this.updateLwwRegister(state.cells, cellKey.toUpperCase(), operation.payload.value, {
      lamport,
      actorId: operation.actorId,
      opId: operation.opId
    });
  }

  applyOperationToState(state, operation) {
    state.clock += 1;
    const lamport = state.clock;

    if (operation.type === 'insert') {
      return { applied: this.applyInsert(state, operation, lamport), lamport };
    }

    if (operation.type === 'delete') {
      return { applied: this.applyDelete(state, operation), lamport };
    }

    if (operation.type === 'set_field') {
      return { applied: this.applyFieldSet(state, operation, lamport), lamport };
    }

    if (operation.type === 'set_cell') {
      return { applied: this.applyCellSet(state, operation, lamport), lamport };
    }

    return { applied: false, lamport };
  }

  trimState(document) {
    if (document.state.appliedOps.length > MAX_APPLIED_OPS) {
      document.state.appliedOps = document.state.appliedOps.slice(-MAX_APPLIED_OPS);
    }

    if (document.operations.length > MAX_OPERATION_HISTORY) {
      document.operations = document.operations.slice(-MAX_OPERATION_HISTORY);
    }
  }

  async applyOperations(documentId, userId, deviceId, operations = []) {
    if (!Array.isArray(operations) || operations.length === 0) {
      return this.getDocument(documentId, userId);
    }

    const actorId = this.getActorId(userId);

    for (let attempt = 1; attempt <= this.retryLimit; attempt += 1) {
      const document = await CollaborativeDocument.findById(documentId);
      if (!document) {
        throw new Error('Collaborative document not found');
      }

      if (!this.canEdit(document, userId)) {
        const error = new Error('You do not have edit permissions for this document');
        error.status = 403;
        throw error;
      }

      this.ensureState(document);
      this.ensureParticipantPresence(document, userId);

      const appliedResults = [];
      let sequence = document.state.version + 1;

      for (const incoming of operations) {
        const normalized = this.normalizeOperation(incoming, actorId, deviceId, sequence);

        if (document.state.appliedOps.includes(normalized.opId)) {
          appliedResults.push({ opId: normalized.opId, status: 'duplicate_ignored' });
          continue;
        }

        const applyResult = this.applyOperationToState(document.state, normalized);
        document.state.version += 1;
        document.state.vectorClock[actorId] = (document.state.vectorClock[actorId] || 0) + 1;
        document.state.appliedOps.push(normalized.opId);

        const committedOp = {
          opId: normalized.opId,
          type: normalized.type,
          actorId: normalized.actorId,
          deviceId: normalized.deviceId,
          lamport: applyResult.lamport,
          serverVersion: document.state.version,
          payload: normalized.payload,
          createdAt: new Date()
        };

        document.operations.push(committedOp);

        appliedResults.push({
          opId: normalized.opId,
          status: applyResult.applied ? 'applied' : 'noop',
          lamport: applyResult.lamport,
          serverVersion: document.state.version,
          type: normalized.type
        });

        sequence += 1;
      }

      document.markModified('state');
      document.markModified('operations');
      document.metadata.lastSyncedAt = new Date();
      this.trimState(document);

      try {
        const saved = await document.save();
        const payload = this.buildDocumentPayload(saved);

        return {
          ...payload,
          appliedResults,
          serverOperations: saved.operations.slice(-operations.length)
        };
      } catch (error) {
        if (error.name === 'VersionError' && attempt < this.retryLimit) {
          continue;
        }
        throw error;
      }
    }

    throw new Error('Unable to apply operations due to concurrent updates');
  }

  async getChangesSince(documentId, userId, sinceVersion = 0) {
    const document = await CollaborativeDocument.findById(documentId);
    if (!document) {
      throw new Error('Collaborative document not found');
    }

    if (!this.canAccess(document, userId)) {
      const error = new Error('Access denied for this document');
      error.status = 403;
      throw error;
    }

    this.ensureState(document);
    const versionThreshold = Number(sinceVersion) || 0;
    const changes = document.operations.filter((operation) => operation.serverVersion > versionThreshold);

    return {
      documentId: document._id,
      sinceVersion: versionThreshold,
      currentVersion: document.state.version,
      changes,
      snapshot: this.buildDocumentPayload(document)
    };
  }

  async markPresence(documentId, userId, isOnline) {
    const document = await CollaborativeDocument.findById(documentId);
    if (!document) {
      throw new Error('Collaborative document not found');
    }

    if (!this.canAccess(document, userId)) {
      const error = new Error('Access denied for this document');
      error.status = 403;
      throw error;
    }

    const userIdStr = String(userId);
    let participant = document.participants.find((candidate) => String(candidate.user) === userIdStr);

    if (!participant) {
      participant = this.sanitizeParticipant(userId, 'editor');
      document.participants.push(participant);
    }

    participant.lastSeenAt = isOnline ? new Date() : new Date(0);

    const activeEditors = document.participants.filter((participant) => {
      const lastSeenAt = new Date(participant.lastSeenAt).getTime();
      return Date.now() - lastSeenAt < 60 * 1000;
    }).length;

    document.metadata.activeEditors = activeEditors;
    document.metadata.lastSyncedAt = new Date();

    await document.save();

    return {
      documentId: document._id,
      activeEditors: document.metadata.activeEditors,
      updatedAt: document.updatedAt
    };
  }
}

module.exports = new RealtimeCollaborationService();
