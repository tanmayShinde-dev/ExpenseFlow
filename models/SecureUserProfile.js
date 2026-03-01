const mongoose = require('mongoose');
const { encryptionPlugin } = require('../middleware/fieldEncryption');

/**
 * SecureUserProfile Model
 * Example implementation of field-level encryption
 * Issue #827: End-to-End Encryption for Sensitive Data
 * 
 * This model demonstrates best practices for storing
 * PII (Personally Identifiable Information) and
 * sensitive financial data with automatic encryption.
 */

const SecureUserProfileSchema = new mongoose.Schema({
  // ============================================================================
  // Public Fields (Not Encrypted)
  // ============================================================================
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true
  },
  displayName: {
    type: String
  },
  profilePicture: {
    type: String
  },
  
  // ============================================================================
  // PII Fields (Auto-Encrypted with 'userData' purpose)
  // ============================================================================
  // These fields are automatically detected and encrypted
  email: {
    type: String,
    required: true
  },
  phoneNumber: {
    type: String
  },
  dateOfBirth: {
    type: Date
  },
  ssn: {
    type: String  // Social Security Number - PCI DSS Level 1
  },
  passport: {
    type: String
  },
  driverLicense: {
    type: String
  },
  nationalId: {
    type: String
  },
  
  // Address (contains PII)
  address: {
    street: { type: String },
    city: { type: String },
    state: { type: String },
    zipCode: { type: String },
    country: { type: String }
  },
  
  // ============================================================================
  // Financial Data (Auto-Encrypted with 'financialData' purpose)
  // ============================================================================
  financialInfo: {
    // Primary bank account
    bankAccountNumber: {
      type: String
    },
    routingNumber: {
      type: String
    },
    iban: {
      type: String
    },
    swift: {
      type: String
    },
    
    // Payment cards
    paymentCards: [{
      cardNumber: { type: String },  // PAN - must be encrypted
      cardholderName: { type: String },
      expirationDate: { type: String },
      cardBrand: { type: String },  // Visa, MasterCard, etc.
      lastFourDigits: { type: String },  // For display only
      isDefault: { type: Boolean, default: false }
    }],
    
    // Income information
    annualIncome: {
      type: Number
    },
    salary: {
      type: Number
    },
    
    // Net worth (sensitive)
    netWorth: {
      type: Number
    }
  },
  
  // ============================================================================
  // Tax Information (Auto-Encrypted)
  // ============================================================================
  taxInfo: {
    taxId: { type: String },  // TIN/EIN
    filingStatus: { type: String },
    dependents: { type: Number }
  },
  
  // ============================================================================
  // Employment Information (Partially Sensitive)
  // ============================================================================
  employment: {
    employer: { type: String },  // Not encrypted
    position: { type: String },  // Not encrypted
    employeeId: { type: String },  // Encrypted
    startDate: { type: Date },  // Not encrypted
    workEmail: { type: String }  // Encrypted
  },
  
  // ============================================================================
  // Security & Privacy Settings
  // ============================================================================
  privacySettings: {
    dataRetentionDays: { type: Number, default: 365 },
    allowDataExport: { type: Boolean, default: true },
    consentToProcess: { type: Boolean, default: true },
    consentGivenAt: { type: Date }
  },
  
  // ============================================================================
  // Encryption Audit Trail
  // ============================================================================
  encryptionAudit: [{
    action: { type: String, enum: ['encrypted', 'decrypted', 'reencrypted'] },
    fields: [{ type: String }],
    keyId: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  
  // ============================================================================
  // Compliance Metadata
  // ============================================================================
  compliance: {
    pciDssCompliant: { type: Boolean, default: true },
    gdprCompliant: { type: Boolean, default: true },
    dataClassification: { 
      type: String, 
      enum: ['public', 'internal', 'confidential', 'restricted'],
      default: 'restricted'
    },
    lastComplianceCheck: { type: Date }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      // Remove encryption metadata from JSON output
      delete ret._encrypted;
      delete ret._encryptionVersion;
      return ret;
    }
  }
});

// ============================================================================
// Apply Encryption Plugin
// ============================================================================

SecureUserProfileSchema.plugin(encryptionPlugin, {
  // Explicitly specify sensitive fields to encrypt
  fields: [
    // PII
    'email',
    'phoneNumber',
    'ssn',
    'passport',
    'driverLicense',
    'nationalId',
    'address',
    
    // Financial
    'financialInfo.bankAccountNumber',
    'financialInfo.routingNumber',
    'financialInfo.iban',
    'financialInfo.swift',
    'financialInfo.salary',
    'financialInfo.annualIncome',
    'financialInfo.netWorth',
    
    // Payment cards
    'financialInfo.paymentCards',
    
    // Tax info
    'taxInfo.taxId',
    
    // Employment
    'employment.employeeId',
    'employment.workEmail'
  ],
  
  // Primary purpose for this model
  purpose: 'userData',
  
  // Auto-detect additional sensitive fields based on field names
  autoDetect: true
});

// ============================================================================
// Indexes
// ============================================================================

SecureUserProfileSchema.index({ userId: 1 }, { unique: true });
SecureUserProfileSchema.index({ username: 1 });
SecureUserProfileSchema.index({ createdAt: -1 });

// ============================================================================
// Instance Methods
// ============================================================================

/**
 * Get masked profile for display
 * Returns profile with sensitive fields masked
 */
SecureUserProfileSchema.methods.getMaskedProfile = function() {
  const encryptionService = require('../services/encryptionService');
  
  const masked = this.toObject();
  
  // Mask sensitive fields
  if (masked.ssn) {
    masked.ssn = encryptionService.mask(masked.ssn, 'ssn');
  }
  
  if (masked.phoneNumber) {
    masked.phoneNumber = encryptionService.mask(masked.phoneNumber, 'phone');
  }
  
  if (masked.email) {
    masked.email = encryptionService.mask(masked.email, 'email');
  }
  
  if (masked.financialInfo?.bankAccountNumber) {
    masked.financialInfo.bankAccountNumber = encryptionService.mask(
      masked.financialInfo.bankAccountNumber,
      'bankAccount'
    );
  }
  
  if (masked.financialInfo?.paymentCards) {
    masked.financialInfo.paymentCards = masked.financialInfo.paymentCards.map(card => ({
      ...card,
      cardNumber: encryptionService.mask(card.cardNumber, 'card'),
      lastFourDigits: card.cardNumber ? card.cardNumber.slice(-4) : null
    }));
  }
  
  return masked;
};

/**
 * Update encryption audit trail
 */
SecureUserProfileSchema.methods.logEncryptionAudit = function(action, fields, keyId) {
  this.encryptionAudit.push({
    action,
    fields,
    keyId,
    timestamp: new Date()
  });
};

/**
 * Check if profile is compliant with regulations
 */
SecureUserProfileSchema.methods.checkCompliance = async function() {
  const { getEncryptionStatus } = require('../middleware/fieldEncryption');
  
  const encryptionStatus = getEncryptionStatus(this);
  
  const compliance = {
    pciDss: true,
    gdpr: true,
    issues: []
  };
  
  // Check if sensitive financial data is encrypted
  if (this.financialInfo?.cardNumber && !encryptionStatus.isEncrypted) {
    compliance.pciDss = false;
    compliance.issues.push('Payment card data must be encrypted (PCI DSS 3.4)');
  }
  
  // Check if PII is encrypted (GDPR Article 32)
  if ((this.ssn || this.email) && !encryptionStatus.isEncrypted) {
    compliance.gdpr = false;
    compliance.issues.push('Personal data must be encrypted (GDPR Article 32)');
  }
  
  // Update compliance metadata
  this.compliance.pciDssCompliant = compliance.pciDss;
  this.compliance.gdprCompliant = compliance.gdpr;
  this.compliance.lastComplianceCheck = new Date();
  
  return compliance;
};

/**
 * Export user data (GDPR right to data portability)
 */
SecureUserProfileSchema.methods.exportUserData = async function() {
  // Decrypt all fields for export
  const decrypted = await this.decryptFields([
    'email', 'phoneNumber', 'ssn', 'passport', 'driverLicense',
    'financialInfo.bankAccountNumber', 'financialInfo.routingNumber'
  ]);
  
  return {
    exportedAt: new Date().toISOString(),
    userId: this.userId,
    username: this.username,
    personalInfo: {
      email: decrypted.email,
      phoneNumber: decrypted.phoneNumber,
      dateOfBirth: this.dateOfBirth,
      address: decrypted.address
    },
    identityDocuments: {
      ssn: decrypted.ssn,
      passport: decrypted.passport,
      driverLicense: decrypted.driverLicense
    },
    financialInfo: {
      bankAccountNumber: decrypted.financialInfo?.bankAccountNumber,
      routingNumber: decrypted.financialInfo?.routingNumber,
      // Note: Payment card numbers are NOT exported for security
    },
    metadata: {
      accountCreated: this.createdAt,
      lastUpdated: this.updatedAt,
      dataClassification: this.compliance.dataClassification
    }
  };
};

// ============================================================================
// Static Methods
// ============================================================================

/**
 * Find profile with decrypted sensitive fields
 */
SecureUserProfileSchema.statics.findByUserIdDecrypted = async function(userId, fields = []) {
  const profile = await this.findOne({ userId });
  
  if (!profile) {
    return null;
  }
  
  if (fields.length > 0) {
    await profile.decryptFields(fields);
  }
  
  return profile;
};

/**
 * Batch re-encryption for key rotation
 */
SecureUserProfileSchema.statics.batchReEncrypt = async function(batchSize = 50) {
  const fields = [
    'email', 'phoneNumber', 'ssn', 'passport', 'driverLicense',
    'financialInfo.bankAccountNumber', 'financialInfo.routingNumber',
    'taxInfo.taxId'
  ];
  
  return await this.reEncryptAllDocuments(fields, batchSize);
};

/**
 * Get profiles requiring compliance review
 */
SecureUserProfileSchema.statics.getComplianceReviewQueue = async function() {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  
  return await this.find({
    $or: [
      { 'compliance.lastComplianceCheck': { $lt: thirtyDaysAgo } },
      { 'compliance.lastComplianceCheck': null }
    ]
  }).select('userId username compliance');
};

// ============================================================================
// Hooks
// ============================================================================

/**
 * Pre-save hook for additional validation
 */
SecureUserProfileSchema.pre('save', async function(next) {
  // Validate SSN format if provided
  if (this.isModified('ssn') && this.ssn) {
    const ssnRegex = /^\d{3}-?\d{2}-?\d{4}$/;
    if (!ssnRegex.test(this.ssn)) {
      return next(new Error('Invalid SSN format'));
    }
  }
  
  // Validate email format
  if (this.isModified('email') && this.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(this.email)) {
      return next(new Error('Invalid email format'));
    }
  }
  
  // Run compliance check on first save
  if (this.isNew) {
    await this.checkCompliance();
  }
  
  next();
});

/**
 * Post-save hook for audit logging
 */
SecureUserProfileSchema.post('save', function(doc) {
  console.log(`✓ Secure profile saved for user: ${doc.userId}`);
  
  // In production, integrate with your audit logging system
  // Example: AuditLog.create({ ... })
});

// ============================================================================
// Virtual Properties
// ============================================================================

/**
 * Get user's age from date of birth
 */
SecureUserProfileSchema.virtual('age').get(function() {
  if (!this.dateOfBirth) return null;
  
  const today = new Date();
  const birthDate = new Date(this.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  
  return age;
});

/**
 * Check if user is an adult (18+)
 */
SecureUserProfileSchema.virtual('isAdult').get(function() {
  return this.age >= 18;
});

// ============================================================================
// Model Export
// ============================================================================

module.exports = mongoose.model('SecureUserProfile', SecureUserProfileSchema);
