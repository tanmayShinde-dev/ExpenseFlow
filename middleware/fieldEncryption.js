const encryptionService = require('../services/encryptionService');

/**
 * Field-Level Encryption Middleware
 * Issue #827: End-to-End Encryption for Sensitive Data
 * 
 * Provides automatic encryption/decryption of sensitive fields
 * Integrates with Mongoose schemas
 * Supports transparent encryption at rest
 * 
 * Features:
 * - Automatic field detection and encryption
 * - Pre-save hooks for encryption
 * - Post-find hooks for decryption
 * - Selective field decryption
 * - Compliance tracking
 */

/**
 * Mongoose schema plugin for automatic field encryption
 * Usage: schema.plugin(encryptionPlugin, { fields: ['ssn', 'bankAccount'], purpose: 'userData' })
 */
function encryptionPlugin(schema, options = {}) {
  const encryptFields = options.fields || [];
  const purpose = options.purpose || 'userData';
  const autoDetect = options.autoDetect !== false; // Default true
  
  // Add encryption metadata to schema
  schema.add({
    _encrypted: { type: Map, of: Object, select: false },
    _encryptionVersion: { type: String, select: false }
  });

  // Pre-save hook: Encrypt sensitive fields before saving
  schema.pre('save', async function(next) {
    try {
      // Skip if document is not modified
      if (!this.isModified() && !this.isNew) {
        return next();
      }

      // Get fields to encrypt
      let fieldsToEncrypt = [...encryptFields];
      
      // Auto-detect sensitive fields if enabled
      if (autoDetect) {
        const sensitiveFields = encryptionService.getSensitiveFieldsForPurpose(purpose);
        const detectedFields = [];
        
        for (const field of Object.keys(this._doc)) {
          if (sensitiveFields.includes(field.toLowerCase()) && 
              !fieldsToEncrypt.includes(field)) {
            detectedFields.push(field);
          }
        }
        
        fieldsToEncrypt = [...fieldsToEncrypt, ...detectedFields];
      }

      // Filter to only modified fields
      const modifiedFields = fieldsToEncrypt.filter(field => 
        this.isModified(field) && this[field] !== undefined && this[field] !== null
      );

      if (modifiedFields.length === 0) {
        return next();
      }

      // Encrypt each field
      const encryptedMetadata = this._encrypted ? this._encrypted.toObject() : {};
      
      for (const field of modifiedFields) {
        try {
          const encrypted = await encryptionService.encrypt(
            this[field], 
            purpose, 
            { returnObject: true }
          );
          
          // Store ciphertext in field
          this[field] = encrypted.ciphertext;
          
          // Store metadata
          encryptedMetadata[field] = {
            keyId: encrypted.keyId,
            keyVersion: encrypted.keyVersion,
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            algorithm: encrypted.algorithm,
            encryptedAt: encrypted.encryptedAt
          };
        } catch (error) {
          console.error(`Failed to encrypt field ${field}:`, error);
          return next(error);
        }
      }
      
      this._encrypted = encryptedMetadata;
      this._encryptionVersion = '1.0';
      
      next();
    } catch (error) {
      next(error);
    }
  });

  // Post-find hook: Decrypt fields after retrieval
  schema.post('find', async function(docs) {
    if (!docs || docs.length === 0) return;
    
    for (const doc of docs) {
      await decryptDocument(doc, encryptFields, autoDetect, purpose);
    }
  });

  schema.post('findOne', async function(doc) {
    if (!doc) return;
    await decryptDocument(doc, encryptFields, autoDetect, purpose);
  });

  schema.post('findOneAndUpdate', async function(doc) {
    if (!doc) return;
    await decryptDocument(doc, encryptFields, autoDetect, purpose);
  });

  // Instance method to manually decrypt specific fields
  schema.methods.decryptFields = async function(fields) {
    if (!this._encrypted) return this;
    
    for (const field of fields) {
      if (this[field] && this._encrypted.get(field)) {
        try {
          const encryptedPackage = {
            ciphertext: this[field],
            ...this._encrypted.get(field)
          };
          
          this[field] = await encryptionService.decrypt(encryptedPackage);
        } catch (error) {
          console.error(`Failed to decrypt field ${field}:`, error);
          this[field] = '[DECRYPTION_FAILED]';
        }
      }
    }
    
    return this;
  };

  // Instance method to re-encrypt with new key
  schema.methods.reEncryptFields = async function(fields) {
    if (!this._encrypted) return this;
    
    for (const field of fields) {
      if (this[field] && this._encrypted.get(field)) {
        try {
          const encryptedPackage = {
            ciphertext: this[field],
            ...this._encrypted.get(field)
          };
          
          // Decrypt and re-encrypt
          const decrypted = await encryptionService.decrypt(encryptedPackage);
          const reEncrypted = await encryptionService.encrypt(
            decrypted,
            purpose,
            { returnObject: true }
          );
          
          this[field] = reEncrypted.ciphertext;
          this._encrypted.set(field, {
            keyId: reEncrypted.keyId,
            keyVersion: reEncrypted.keyVersion,
            iv: reEncrypted.iv,
            authTag: reEncrypted.authTag,
            algorithm: reEncrypted.algorithm,
            encryptedAt: reEncrypted.encryptedAt
          });
        } catch (error) {
          console.error(`Failed to re-encrypt field ${field}:`, error);
        }
      }
    }
    
    await this.save();
    return this;
  };

  // Static method to batch re-encrypt all documents (for key rotation)
  schema.statics.reEncryptAllDocuments = async function(fields, batchSize = 100) {
    console.log(`Starting batch re-encryption for ${this.modelName}...`);
    
    let processed = 0;
    let errors = 0;
    let hasMore = true;
    let lastId = null;
    
    while (hasMore) {
      const query = lastId ? { _id: { $gt: lastId } } : {};
      const docs = await this.find(query).limit(batchSize).sort({ _id: 1 });
      
      if (docs.length === 0) {
        hasMore = false;
        break;
      }
      
      for (const doc of docs) {
        try {
          await doc.reEncryptFields(fields);
          processed++;
        } catch (error) {
          console.error(`Failed to re-encrypt document ${doc._id}:`, error);
          errors++;
        }
        
        lastId = doc._id;
      }
      
      console.log(`Progress: ${processed} documents re-encrypted, ${errors} errors`);
    }
    
    console.log(`✓ Batch re-encryption complete: ${processed} processed, ${errors} errors`);
    
    return { processed, errors };
  };
}

/**
 * Helper function to decrypt a document
 */
async function decryptDocument(doc, encryptFields, autoDetect, purpose) {
  if (!doc._encrypted) return;
  
  let fieldsToDecrypt = [...encryptFields];
  
  // Auto-detect fields if enabled
  if (autoDetect) {
    const encryptedFieldNames = doc._encrypted instanceof Map ? 
      Array.from(doc._encrypted.keys()) : 
      Object.keys(doc._encrypted);
    
    fieldsToDecrypt = [...new Set([...fieldsToDecrypt, ...encryptedFieldNames])];
  }
  
  for (const field of fieldsToDecrypt) {
    const metadata = doc._encrypted instanceof Map ? 
      doc._encrypted.get(field) : 
      doc._encrypted[field];
    
    if (doc[field] && metadata) {
      try {
        const encryptedPackage = {
          ciphertext: doc[field],
          ...metadata
        };
        
        doc[field] = await encryptionService.decrypt(encryptedPackage);
      } catch (error) {
        console.error(`Failed to decrypt field ${field} in document ${doc._id}:`, error);
        doc[field] = '[DECRYPTION_FAILED]';
      }
    }
  }
}

/**
 * Express middleware to encrypt request body fields
 */
function encryptRequestFields(fields, purpose = 'userData') {
  return async (req, res, next) => {
    try {
      if (!req.body || typeof req.body !== 'object') {
        return next();
      }

      for (const field of fields) {
        if (req.body[field] !== undefined && req.body[field] !== null) {
          req.body[field] = await encryptionService.encrypt(req.body[field], purpose);
        }
      }

      next();
    } catch (error) {
      console.error('Request encryption failed:', error);
      res.status(500).json({ error: 'Data encryption failed' });
    }
  };
}

/**
 * Express middleware to decrypt response fields
 */
function decryptResponseFields(fields) {
  return async (req, res, next) => {
    const originalJson = res.json;

    res.json = async function(data) {
      try {
        if (data && typeof data === 'object') {
          // Handle arrays
          if (Array.isArray(data)) {
            for (const item of data) {
              await decryptObjectFields(item, fields);
            }
          } else {
            await decryptObjectFields(data, fields);
          }
        }
      } catch (error) {
        console.error('Response decryption failed:', error);
      }

      originalJson.call(this, data);
    };

    next();
  };
}

/**
 * Helper to decrypt fields in an object
 */
async function decryptObjectFields(obj, fields) {
  if (!obj || typeof obj !== 'object') return;

  for (const field of fields) {
    if (obj[field] && encryptionService.isEncrypted(obj[field])) {
      try {
        obj[field] = await encryptionService.decrypt(obj[field]);
      } catch (error) {
        console.error(`Failed to decrypt field ${field}:`, error);
        obj[field] = '[DECRYPTION_FAILED]';
      }
    }
  }
}

/**
 * Middleware to mask sensitive fields in responses
 */
function maskSensitiveFields(fieldMappings) {
  return (req, res, next) => {
    const originalJson = res.json;

    res.json = function(data) {
      try {
        if (data && typeof data === 'object') {
          // Handle arrays
          if (Array.isArray(data)) {
            for (const item of data) {
              maskObjectFields(item, fieldMappings);
            }
          } else {
            maskObjectFields(data, fieldMappings);
          }
        }
      } catch (error) {
        console.error('Field masking failed:', error);
      }

      originalJson.call(this, data);
    };

    next();
  };
}

/**
 * Helper to mask fields in an object
 */
function maskObjectFields(obj, fieldMappings) {
  if (!obj || typeof obj !== 'object') return;

  for (const [field, type] of Object.entries(fieldMappings)) {
    if (obj[field]) {
      obj[field] = encryptionService.mask(obj[field], type);
    }
  }
}

/**
 * Middleware to enforce encryption for specific routes
 */
function requireEncryption(purpose = 'userData') {
  return async (req, res, next) => {
    // Check if request contains encrypted data markers
    if (req.body && req.body._encryptionVersion) {
      return next();
    }

    // Check if sensitive fields are present but not encrypted
    const sensitiveFields = encryptionService.getSensitiveFieldsForPurpose(purpose);
    const unencryptedFields = [];

    for (const field of sensitiveFields) {
      if (req.body[field] && !encryptionService.isEncrypted(req.body[field])) {
        unencryptedFields.push(field);
      }
    }

    if (unencryptedFields.length > 0) {
      console.warn(`Unencrypted sensitive fields detected: ${unencryptedFields.join(', ')}`);
      
      // In strict mode, reject the request
      if (process.env.ENCRYPTION_STRICT_MODE === 'true') {
        return res.status(400).json({
          error: 'Sensitive data must be encrypted',
          fields: unencryptedFields
        });
      }
      
      // Otherwise, auto-encrypt
      for (const field of unencryptedFields) {
        req.body[field] = await encryptionService.encrypt(req.body[field], purpose);
      }
    }

    next();
  };
}

/**
 * Utility to get encryption status for a document
 */
function getEncryptionStatus(doc) {
  if (!doc._encrypted) {
    return {
      isEncrypted: false,
      encryptedFields: [],
      version: null
    };
  }

  const encryptedFields = doc._encrypted instanceof Map ?
    Array.from(doc._encrypted.keys()) :
    Object.keys(doc._encrypted);

  return {
    isEncrypted: true,
    encryptedFields,
    version: doc._encryptionVersion,
    fieldCount: encryptedFields.length,
    details: encryptedFields.map(field => {
      const metadata = doc._encrypted instanceof Map ?
        doc._encrypted.get(field) :
        doc._encrypted[field];
      
      return {
        field,
        keyId: metadata.keyId,
        keyVersion: metadata.keyVersion,
        algorithm: metadata.algorithm,
        encryptedAt: metadata.encryptedAt
      };
    })
  };
}

module.exports = {
  encryptionPlugin,
  encryptRequestFields,
  decryptResponseFields,
  maskSensitiveFields,
  requireEncryption,
  getEncryptionStatus
};
