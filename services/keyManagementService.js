const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const mongoose = require('mongoose');

/**
 * Key Management Service (KMS)
 * Issue #827: End-to-End Encryption for Sensitive Data
 * 
 * Provides secure key generation, storage, rotation, and management
 * Compliant with PCI DSS 3.2.1, GDPR Article 32, and NIST SP 800-57
 * 
 * Key Management Features:
 * - Master key encryption (KEK - Key Encryption Key)
 * - Data encryption keys (DEK) rotation
 * - Secure key derivation using PBKDF2
 * - Hardware Security Module (HSM) compatible
 * - Key versioning and history
 * - Automated key rotation policies
 */

// Encryption Key Schema
const EncryptionKeySchema = new mongoose.Schema({
  keyId: { type: String, required: true, unique: true },
  version: { type: Number, required: true, default: 1 },
  algorithm: { type: String, required: true, default: 'aes-256-gcm' },
  encryptedKey: { type: String, required: true }, // DEK encrypted with KEK
  keyType: { type: String, enum: ['master', 'data', 'field'], required: true },
  purpose: { type: String, required: true }, // e.g., 'user-data', 'financial-data'
  status: { 
    type: String, 
    enum: ['active', 'rotating', 'deprecated', 'revoked'], 
    default: 'active' 
  },
  createdAt: { type: Date, default: Date.now },
  rotatedAt: { type: Date },
  expiresAt: { type: Date },
  metadata: {
    rotationPeriodDays: { type: Number, default: 90 },
    lastUsed: { type: Date },
    usageCount: { type: Number, default: 0 }
  },
  compliance: {
    pciDss: { type: Boolean, default: true },
    gdpr: { type: Boolean, default: true },
    hipaa: { type: Boolean, default: false }
  }
}, { timestamps: true });

EncryptionKeySchema.index({ keyId: 1, version: -1 });
EncryptionKeySchema.index({ status: 1, purpose: 1 });
EncryptionKeySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const EncryptionKey = mongoose.model('EncryptionKey', EncryptionKeySchema);

class KeyManagementService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16; // 128 bits
    this.authTagLength = 16; // 128 bits
    this.saltLength = 32;
    this.pbkdf2Iterations = 100000;
    
    // In-memory cache for active keys (refreshed periodically)
    this.keyCache = new Map();
    this.cacheTimeout = 3600000; // 1 hour
    
    // Master Key Encryption Key (KEK) - should be stored in HSM in production
    this.masterKEK = null;
    
    this.initialize();
  }

  /**
   * Initialize the KMS
   */
  async initialize() {
    try {
      // Load or generate master KEK
      await this.loadOrGenerateMasterKEK();
      
      // Set up automatic key rotation check
      setInterval(() => this.checkKeyRotation(), 86400000); // Check daily
      
      console.log('✓ Key Management Service initialized');
    } catch (error) {
      console.error('Failed to initialize KMS:', error);
      throw error;
    }
  }

  /**
   * Load or generate master Key Encryption Key (KEK)
   * In production, this should be stored in a Hardware Security Module (HSM)
   * or cloud KMS (AWS KMS, Azure Key Vault, Google Cloud KMS)
   */
  async loadOrGenerateMasterKEK() {
    const kekPath = process.env.KEK_PATH || path.join(__dirname, '../.keys/master.kek');
    const kekPassword = process.env.KEK_PASSWORD || this.generateSecurePassword();
    
    try {
      // Try to load existing KEK
      const encryptedKEK = await fs.readFile(kekPath, 'utf8');
      this.masterKEK = await this.decryptKEK(encryptedKEK, kekPassword);
      console.log('✓ Master KEK loaded from secure storage');
    } catch (error) {
      // Generate new KEK if doesn't exist
      console.log('Generating new Master KEK...');
      this.masterKEK = crypto.randomBytes(this.keyLength);
      
      // Encrypt and save KEK
      const encryptedKEK = await this.encryptKEK(this.masterKEK, kekPassword);
      
      // Ensure directory exists
      const dir = path.dirname(kekPath);
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
      
      await fs.writeFile(kekPath, encryptedKEK, { mode: 0o600 });
      console.log('✓ Master KEK generated and saved');
      console.warn('⚠ IMPORTANT: Store KEK_PASSWORD securely in environment variables or secrets manager');
    }
  }

  /**
   * Encrypt the master KEK using password-based encryption
   */
  async encryptKEK(kek, password) {
    const salt = crypto.randomBytes(this.saltLength);
    const key = crypto.pbkdf2Sync(password, salt, this.pbkdf2Iterations, this.keyLength, 'sha256');
    const iv = crypto.randomBytes(this.ivLength);
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(kek), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Combine: salt + iv + authTag + encrypted
    return Buffer.concat([salt, iv, authTag, encrypted]).toString('base64');
  }

  /**
   * Decrypt the master KEK
   */
  async decryptKEK(encryptedData, password) {
    const buffer = Buffer.from(encryptedData, 'base64');
    
    const salt = buffer.slice(0, this.saltLength);
    const iv = buffer.slice(this.saltLength, this.saltLength + this.ivLength);
    const authTag = buffer.slice(this.saltLength + this.ivLength, this.saltLength + this.ivLength + this.authTagLength);
    const encrypted = buffer.slice(this.saltLength + this.ivLength + this.authTagLength);
    
    const key = crypto.pbkdf2Sync(password, salt, this.pbkdf2Iterations, this.keyLength, 'sha256');
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  /**
   * Generate a new Data Encryption Key (DEK)
   */
  async generateDataEncryptionKey(purpose, keyType = 'data') {
    // Generate random DEK
    const dek = crypto.randomBytes(this.keyLength);
    const keyId = this.generateKeyId(purpose);
    
    // Encrypt DEK with master KEK
    const encryptedDEK = await this.encryptWithKEK(dek);
    
    // Calculate expiration (default 90 days)
    const rotationPeriod = 90;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + rotationPeriod);
    
    // Store encrypted key in database
    const encryptionKey = new EncryptionKey({
      keyId,
      version: 1,
      algorithm: this.algorithm,
      encryptedKey: encryptedDEK,
      keyType,
      purpose,
      status: 'active',
      expiresAt,
      metadata: {
        rotationPeriodDays: rotationPeriod,
        lastUsed: new Date(),
        usageCount: 0
      }
    });
    
    await encryptionKey.save();
    
    // Cache the decrypted key
    this.keyCache.set(keyId, {
      key: dek,
      timestamp: Date.now(),
      version: 1
    });
    
    console.log(`✓ Generated new DEK: ${keyId} for purpose: ${purpose}`);
    return { keyId, key: dek, version: 1 };
  }

  /**
   * Encrypt DEK with master KEK
   */
  async encryptWithKEK(dek) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, this.masterKEK, iv);
    
    const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Combine: iv + authTag + encrypted
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
  }

  /**
   * Decrypt DEK with master KEK
   */
  async decryptWithKEK(encryptedDEK) {
    const buffer = Buffer.from(encryptedDEK, 'base64');
    
    const iv = buffer.slice(0, this.ivLength);
    const authTag = buffer.slice(this.ivLength, this.ivLength + this.authTagLength);
    const encrypted = buffer.slice(this.ivLength + this.authTagLength);
    
    const decipher = crypto.createDecipheriv(this.algorithm, this.masterKEK, iv);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  /**
   * Get active encryption key for a purpose
   */
  async getEncryptionKey(purpose) {
    // Check cache first
    const cachedKey = Array.from(this.keyCache.entries())
      .find(([keyId, data]) => keyId.startsWith(`${purpose}-`) && 
             (Date.now() - data.timestamp) < this.cacheTimeout);
    
    if (cachedKey) {
      await this.updateKeyUsage(cachedKey[0]);
      return { keyId: cachedKey[0], key: cachedKey[1].key, version: cachedKey[1].version };
    }
    
    // Load from database
    let encryptionKey = await EncryptionKey.findOne({
      purpose,
      status: 'active',
      $or: [
        { expiresAt: { $gt: new Date() } },
        { expiresAt: null }
      ]
    }).sort({ version: -1 });
    
    // Generate new key if none exists
    if (!encryptionKey) {
      return await this.generateDataEncryptionKey(purpose);
    }
    
    // Decrypt the DEK
    const dek = await this.decryptWithKEK(encryptionKey.encryptedKey);
    
    // Cache it
    this.keyCache.set(encryptionKey.keyId, {
      key: dek,
      timestamp: Date.now(),
      version: encryptionKey.version
    });
    
    await this.updateKeyUsage(encryptionKey.keyId);
    
    return { keyId: encryptionKey.keyId, key: dek, version: encryptionKey.version };
  }

  /**
   * Update key usage statistics
   */
  async updateKeyUsage(keyId) {
    await EncryptionKey.updateOne(
      { keyId },
      { 
        $set: { 'metadata.lastUsed': new Date() },
        $inc: { 'metadata.usageCount': 1 }
      }
    );
  }

  /**
   * Rotate encryption key
   */
  async rotateKey(purpose) {
    console.log(`Starting key rotation for purpose: ${purpose}`);
    
    // Get current active key
    const currentKey = await EncryptionKey.findOne({
      purpose,
      status: 'active'
    }).sort({ version: -1 });
    
    if (!currentKey) {
      throw new Error(`No active key found for purpose: ${purpose}`);
    }
    
    // Mark current key as rotating
    currentKey.status = 'rotating';
    currentKey.rotatedAt = new Date();
    await currentKey.save();
    
    // Generate new key with incremented version
    const dek = crypto.randomBytes(this.keyLength);
    const keyId = this.generateKeyId(purpose);
    const encryptedDEK = await this.encryptWithKEK(dek);
    
    const newVersion = currentKey.version + 1;
    const rotationPeriod = currentKey.metadata.rotationPeriodDays;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + rotationPeriod);
    
    const newKey = new EncryptionKey({
      keyId,
      version: newVersion,
      algorithm: this.algorithm,
      encryptedKey: encryptedDEK,
      keyType: currentKey.keyType,
      purpose,
      status: 'active',
      expiresAt,
      metadata: {
        rotationPeriodDays: rotationPeriod,
        lastUsed: new Date(),
        usageCount: 0
      },
      compliance: currentKey.compliance
    });
    
    await newKey.save();
    
    // Update cache
    this.keyCache.set(keyId, {
      key: dek,
      timestamp: Date.now(),
      version: newVersion
    });
    
    // Deprecate old key after grace period (30 days)
    setTimeout(async () => {
      currentKey.status = 'deprecated';
      await currentKey.save();
      this.keyCache.delete(currentKey.keyId);
    }, 30 * 24 * 60 * 60 * 1000);
    
    console.log(`✓ Key rotated: ${purpose} (v${currentKey.version} → v${newVersion})`);
    
    return { oldKeyId: currentKey.keyId, newKeyId: keyId, version: newVersion };
  }

  /**
   * Check and perform automatic key rotation
   */
  async checkKeyRotation() {
    console.log('Checking for keys requiring rotation...');
    
    const keysToRotate = await EncryptionKey.find({
      status: 'active',
      expiresAt: { $lt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) } // Expires within 7 days
    });
    
    for (const key of keysToRotate) {
      try {
        await this.rotateKey(key.purpose);
      } catch (error) {
        console.error(`Failed to rotate key ${key.keyId}:`, error);
      }
    }
    
    console.log(`✓ Key rotation check complete. Rotated ${keysToRotate.length} keys.`);
  }

  /**
   * Get key by ID (supports versioning)
   */
  async getKeyById(keyId, version = null) {
    // Check cache
    const cached = this.keyCache.get(keyId);
    if (cached && (version === null || cached.version === version)) {
      return { keyId, key: cached.key, version: cached.version };
    }
    
    // Load from database
    const query = { keyId };
    if (version !== null) {
      query.version = version;
    }
    
    const encryptionKey = await EncryptionKey.findOne(query).sort({ version: -1 });
    
    if (!encryptionKey) {
      throw new Error(`Encryption key not found: ${keyId}${version ? ` (v${version})` : ''}`);
    }
    
    // Decrypt DEK
    const dek = await this.decryptWithKEK(encryptionKey.encryptedKey);
    
    // Cache it
    this.keyCache.set(keyId, {
      key: dek,
      timestamp: Date.now(),
      version: encryptionKey.version
    });
    
    return { keyId, key: dek, version: encryptionKey.version };
  }

  /**
   * Revoke a key (emergency action)
   */
  async revokeKey(keyId, reason) {
    const key = await EncryptionKey.findOne({ keyId });
    
    if (!key) {
      throw new Error(`Key not found: ${keyId}`);
    }
    
    key.status = 'revoked';
    key.metadata.revocationReason = reason;
    await key.save();
    
    // Remove from cache
    this.keyCache.delete(keyId);
    
    console.log(`✓ Key revoked: ${keyId} (Reason: ${reason})`);
    
    // Audit log the revocation
    // This should integrate with your audit logging system
    return { keyId, status: 'revoked', reason };
  }

  /**
   * List all keys with optional filtering
   */
  async listKeys(filter = {}) {
    const keys = await EncryptionKey.find(filter)
      .select('-encryptedKey') // Don't return the actual encrypted key
      .sort({ createdAt: -1 })
      .lean();
    
    return keys;
  }

  /**
   * Generate a unique key identifier
   */
  generateKeyId(purpose) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    return `${purpose}-${timestamp}-${random}`;
  }

  /**
   * Generate a secure random password
   */
  generateSecurePassword(length = 32) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    const randomBytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      password += charset[randomBytes[i] % charset.length];
    }
    
    return password;
  }

  /**
   * Export key backup (encrypted)
   */
  async exportKeyBackup(password) {
    const keys = await EncryptionKey.find({ status: { $in: ['active', 'rotating'] } }).lean();
    
    const backup = {
      version: '1.0',
      exportedAt: new Date().toISOString(),
      keys: keys.map(k => ({
        keyId: k.keyId,
        version: k.version,
        algorithm: k.algorithm,
        encryptedKey: k.encryptedKey,
        purpose: k.purpose,
        metadata: k.metadata
      }))
    };
    
    const backupJson = JSON.stringify(backup);
    const salt = crypto.randomBytes(this.saltLength);
    const key = crypto.pbkdf2Sync(password, salt, this.pbkdf2Iterations, this.keyLength, 'sha256');
    const iv = crypto.randomBytes(this.ivLength);
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(backupJson, 'utf8')),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    
    return Buffer.concat([salt, iv, authTag, encrypted]).toString('base64');
  }

  /**
   * Import key backup
   */
  async importKeyBackup(encryptedBackup, password) {
    const buffer = Buffer.from(encryptedBackup, 'base64');
    
    const salt = buffer.slice(0, this.saltLength);
    const iv = buffer.slice(this.saltLength, this.saltLength + this.ivLength);
    const authTag = buffer.slice(this.saltLength + this.ivLength, this.saltLength + this.ivLength + this.authTagLength);
    const encrypted = buffer.slice(this.saltLength + this.ivLength + this.authTagLength);
    
    const key = crypto.pbkdf2Sync(password, salt, this.pbkdf2Iterations, this.keyLength, 'sha256');
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    const backup = JSON.parse(decrypted.toString('utf8'));
    
    console.log(`Importing ${backup.keys.length} keys from backup...`);
    
    for (const keyData of backup.keys) {
      // Check if key already exists
      const existing = await EncryptionKey.findOne({ keyId: keyData.keyId });
      
      if (!existing) {
        await EncryptionKey.create(keyData);
        console.log(`✓ Imported key: ${keyData.keyId}`);
      } else {
        console.log(`⊘ Key already exists: ${keyData.keyId}`);
      }
    }
    
    console.log('✓ Key backup import complete');
  }

  /**
   * Get key rotation status and health metrics
   */
  async getKeyHealthMetrics() {
    const totalKeys = await EncryptionKey.countDocuments();
    const activeKeys = await EncryptionKey.countDocuments({ status: 'active' });
    const expiringSoon = await EncryptionKey.countDocuments({
      status: 'active',
      expiresAt: { $lt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }
    });
    const deprecated = await EncryptionKey.countDocuments({ status: 'deprecated' });
    const revoked = await EncryptionKey.countDocuments({ status: 'revoked' });
    
    const keysByPurpose = await EncryptionKey.aggregate([
      { $match: { status: 'active' } },
      { $group: { _id: '$purpose', count: { $sum: 1 } } }
    ]);
    
    return {
      total: totalKeys,
      active: activeKeys,
      expiringSoon,
      deprecated,
      revoked,
      cacheSize: this.keyCache.size,
      byPurpose: keysByPurpose,
      healthStatus: expiringSoon > 0 ? 'warning' : 'healthy'
    };
  }
}

// Export singleton instance
module.exports = new KeyManagementService();
