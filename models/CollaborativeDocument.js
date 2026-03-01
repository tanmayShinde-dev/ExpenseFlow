const mongoose = require('mongoose');

const collabOperationSchema = new mongoose.Schema({
  opId: { type: String, required: true },
  type: {
    type: String,
    enum: ['insert', 'delete', 'set_field', 'set_cell'],
    required: true
  },
  actorId: { type: String, required: true },
  deviceId: { type: String },
  lamport: { type: Number, required: true },
  serverVersion: { type: Number, required: true },
  payload: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const participantSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['owner', 'editor', 'viewer'], default: 'editor' },
  lastSeenAt: { type: Date, default: Date.now }
}, { _id: false });

const collaborativeDocumentSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  docType: {
    type: String,
    enum: ['document', 'spreadsheet', 'note'],
    default: 'document'
  },
  workspace: { type: mongoose.Schema.Types.ObjectId, ref: 'Workspace', index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  participants: [participantSchema],
  state: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({
      clock: 0,
      version: 0,
      vectorClock: {},
      appliedOps: [],
      atoms: [],
      registers: {},
      cells: {}
    })
  },
  operations: {
    type: [collabOperationSchema],
    default: []
  },
  metadata: {
    lastSyncedAt: { type: Date, default: Date.now },
    activeEditors: { type: Number, default: 0 }
  }
}, {
  timestamps: true,
  optimisticConcurrency: true
});

collaborativeDocumentSchema.index({ workspace: 1, updatedAt: -1 });
collaborativeDocumentSchema.index({ 'participants.user': 1, updatedAt: -1 });
collaborativeDocumentSchema.index({ 'operations.serverVersion': 1 });

module.exports = mongoose.model('CollaborativeDocument', collaborativeDocumentSchema);
