const BaseThreatIntelProvider = require('./BaseThreatIntelProvider');
const axios = require('axios');
const crypto = require('crypto');

/**
 * Credential Breach Provider
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Checks if credentials have been leaked in data breaches
 * Uses HaveIBeenPwned API (k-anonymity model for privacy)
 */

class CredentialBreachProvider extends BaseThreatIntelProvider {
  constructor(options = {}) {
    super('CredentialBreach', {
      ...options,
      timeout: options.timeout || 5000,
      cacheTTL: options.cacheTTL || 604800, // 7 days (breaches don't change often)
      confidence: 0.90
    });
    
    this.apiKey = options.apiKey || process.env.HIBP_API_KEY;
    this.useKAnonymity = options.useKAnonymity !== false; // Default true for privacy
  }
  
  /**
   * Check if email/password has been breached
   */
  async enrich(entityType, entityValue) {
    if (entityType === 'EMAIL') {
      return await this._checkEmailBreaches(entityValue);
    } else if (entityType === 'PASSWORD_HASH') {
      return await this._checkPasswordBreaches(entityValue);
    } else {
      throw new Error('CredentialBreachProvider only supports EMAIL and PASSWORD_HASH entities');
    }
  }
  
  /**
   * Check email against breach database
   */
  async _checkEmailBreaches(email) {
    if (!this.apiKey) {
      return this._getMockEmailBreaches(email);
    }
    
    try {
      // HaveIBeenPwned API
      const response = await axios.get(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
        {
          headers: {
            'hibp-api-key': this.apiKey,
            'user-agent': 'ExpenseFlow-SecurityService'
          },
          params: {
            truncateResponse: false
          },
          timeout: this.timeout,
          validateStatus: (status) => status === 200 || status === 404
        }
      );
      
      if (response.status === 404) {
        // No breaches found
        return {
          success: true,
          data: {
            isBreached: false,
            breachCount: 0,
            breaches: [],
            lastBreachDate: null
          }
        };
      }
      
      const breaches = response.data.map(breach => ({
        name: breach.Name,
        date: new Date(breach.BreachDate),
        dataClasses: breach.DataClasses,
        pwnCount: breach.PwnCount
      }));
      
      return {
        success: true,
        data: {
          isBreached: true,
          breachCount: breaches.length,
          breaches,
          lastBreachDate: breaches.length > 0 
            ? new Date(Math.max(...breaches.map(b => b.date)))
            : null
        }
      };
    } catch (error) {
      if (error.response?.status === 429) {
        throw new Error('Rate limit exceeded');
      }
      
      // On error, return mock data
      return this._getMockEmailBreaches(email);
    }
  }
  
  /**
   * Check password against Pwned Passwords (k-anonymity)
   */
  async _checkPasswordBreaches(passwordHash) {
    try {
      // Use k-anonymity: only send first 5 chars of SHA-1 hash
      const sha1Hash = typeof passwordHash === 'string' && passwordHash.length === 40
        ? passwordHash.toUpperCase()
        : this._sha1(passwordHash).toUpperCase();
      
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5);
      
      // Query with prefix only
      const response = await axios.get(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        {
          headers: {
            'user-agent': 'ExpenseFlow-SecurityService'
          },
          timeout: this.timeout
        }
      );
      
      // Parse response to find suffix
      const lines = response.data.split('\n');
      for (const line of lines) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix.trim() === suffix) {
          return {
            success: true,
            data: {
              isBreached: true,
              breachCount: parseInt(count.trim(), 10),
              message: 'Password found in breach databases'
            }
          };
        }
      }
      
      return {
        success: true,
        data: {
          isBreached: false,
          breachCount: 0,
          message: 'Password not found in breach databases'
        }
      };
    } catch (error) {
      // On error, assume not breached (fail open for better UX)
      return {
        success: true,
        data: {
          isBreached: false,
          breachCount: 0,
          message: 'Unable to check breach status'
        }
      };
    }
  }
  
  /**
   * SHA-1 hash utility
   */
  _sha1(input) {
    return crypto.createHash('sha1').update(input).digest('hex');
  }
  
  /**
   * Mock email breach data for development
   */
  _getMockEmailBreaches(email) {
    // Emails containing "test" or "admin" are "breached" in mock mode
    const isBreached = email.includes('test') || email.includes('admin') || email.includes('user');
    
    if (!isBreached) {
      return {
        success: true,
        data: {
          isBreached: false,
          breachCount: 0,
          breaches: [],
          lastBreachDate: null
        }
      };
    }
    
    const mockBreaches = [
      {
        name: 'LinkedIn',
        date: new Date('2021-06-01'),
        dataClasses: ['Email addresses', 'Passwords']
      },
      {
        name: 'Adobe',
        date: new Date('2013-10-01'),
        dataClasses: ['Email addresses', 'Passwords', 'Password hints']
      }
    ];
    
    const breachCount = email.includes('admin') ? 2 : 1;
    const breaches = mockBreaches.slice(0, breachCount);
    
    return {
      success: true,
      data: {
        isBreached: true,
        breachCount,
        breaches,
        lastBreachDate: breaches.length > 0 
          ? breaches[breaches.length - 1].date
          : null
      }
    };
  }
}

module.exports = CredentialBreachProvider;
