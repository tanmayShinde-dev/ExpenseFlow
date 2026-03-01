const mongoose = require('mongoose');

const riskPolicyVersionSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    index: true,
    default: 'global'
  },
  version: {
    type: Number,
    required: true,
    min: 1
  },
  modelVersion: {
    type: String,
    required: true,
    default: 'ensemble-v2'
  },
  status: {
    type: String,
    enum: ['active', 'archived'],
    default: 'active',
    index: true
  },
  policy: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  checksum: {
    type: String,
    required: true
  },
  rolledBackFromVersion: {
    type: Number,
    default: null
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

riskPolicyVersionSchema.index({ tenantId: 1, version: -1 }, { unique: true });
riskPolicyVersionSchema.index({ tenantId: 1, status: 1, createdAt: -1 });

riskPolicyVersionSchema.statics.getActivePolicy = async function(tenantId = 'global') {
  const scopedPolicy = await this.findOne({ tenantId, status: 'active' }).sort({ version: -1 });
  if (scopedPolicy) {
    return scopedPolicy;
  }

  if (tenantId !== 'global') {
    return this.findOne({ tenantId: 'global', status: 'active' }).sort({ version: -1 });
  }

  return null;
};

riskPolicyVersionSchema.statics.publishPolicy = async function({
  tenantId = 'global',
  policy,
  modelVersion = 'ensemble-v2',
  checksum,
  createdBy,
  rolledBackFromVersion = null
}) {
  const latest = await this.findOne({ tenantId }).sort({ version: -1 });
  const nextVersion = latest ? latest.version + 1 : 1;

  await this.updateMany(
    { tenantId, status: 'active' },
    { $set: { status: 'archived' } }
  );

  const created = await this.create({
    tenantId,
    version: nextVersion,
    modelVersion,
    status: 'active',
    policy,
    checksum,
    rolledBackFromVersion,
    createdBy
  });

  return created;
};

module.exports = mongoose.model('RiskPolicyVersion', riskPolicyVersionSchema);
