const BaseThreatIntelProvider = require('./BaseThreatIntelProvider');
const axios = require('axios');

/**
 * Disposable Email Provider
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Detects temporary/disposable email addresses
 * Uses local database + external validation
 */

class DisposableEmailProvider extends BaseThreatIntelProvider {
  constructor(options = {}) {
    super('DisposableEmail', {
      ...options,
      timeout: options.timeout || 3000,
      cacheTTL: options.cacheTTL || 86400, // 24 hours
      confidence: 0.95
    });
    
    // Common disposable email domains (subset)
    this.disposableDomains = new Set([
      '10minutemail.com',
      'guerrillamail.com',
      'mailinator.com',
      'tempmail.com',
      'throwaway.email',
      'yopmail.com',
      'maildrop.cc',
      'temp-mail.org',
      'getairmail.com',
      'trashmail.com',
      'fakeinbox.com',
      'sharklasers.com',
      'grr.la',
      'guerrillamail.biz',
      'spam4.me',
      'mailnesia.com',
      '10mail.org',
      'emltmp.com'
      // Add more from disposable-email-domains package
    ]);
    
    this.apiKey = options.apiKey || process.env.EMAILREP_API_KEY;
  }
  
  /**
   * Check if email is disposable
   */
  async enrich(entityType, entityValue) {
    if (entityType !== 'EMAIL') {
      throw new Error('DisposableEmailProvider only supports EMAIL entities');
    }
    
    const email = entityValue.toLowerCase();
    const domain = this._extractDomain(email);
    
    // Quick local check first
    const localResult = this._checkLocalDatabase(domain);
    
    if (localResult.isDisposable) {
      // Definitive match in local database
      return {
        success: true,
        data: localResult
      };
    }
    
    // Check external API if available
    if (this.apiKey) {
      return await this._checkExternalAPI(email);
    }
    
    // Return local result
    return {
      success: true,
      data: localResult
    };
  }
  
  /**
   * Extract domain from email
   */
  _extractDomain(email) {
    const parts = email.split('@');
    return parts.length === 2 ? parts[1] : '';
  }
  
  /**
   * Check local disposable domain database
   */
  _checkLocalDatabase(domain) {
    const isDisposable = this.disposableDomains.has(domain);
    
    // Additional heuristics
    const isTemporary = domain.includes('temp') || 
                        domain.includes('disposable') || 
                        domain.includes('trash') ||
                        domain.includes('throw') ||
                        domain.includes('fake');
    
    return {
      isDisposable: isDisposable || isTemporary,
      isTemporary,
      domain,
      source: 'local_database'
    };
  }
  
  /**
   * Check external API (EmailRep, etc.)
   */
  async _checkExternalAPI(email) {
    try {
      const response = await axios.get(`https://emailrep.io/${email}`, {
        headers: {
          'Key': this.apiKey
        },
        timeout: this.timeout
      });
      
      const data = response.data;
      
      return {
        success: true,
        data: {
          isDisposable: data.details?.disposable || false,
          isTemporary: data.details?.disposable || false,
          domain: this._extractDomain(email),
          reputation: data.reputation,
          suspicious: data.suspicious,
          source: 'emailrep_api'
        }
      };
    } catch (error) {
      // Fallback to local check
      const domain = this._extractDomain(email);
      return {
        success: true,
        data: this._checkLocalDatabase(domain)
      };
    }
  }
  
  /**
   * Mock disposable email check
   */
  _getMockDisposableEmail(email) {
    const domain = this._extractDomain(email);
    const isDisposable = this.disposableDomains.has(domain) ||
                         domain.includes('temp') ||
                         domain.includes('test');
    
    return {
      success: true,
      data: {
        isDisposable,
        isTemporary: isDisposable,
        domain,
        source: 'mock_data'
      }
    };
  }
}

module.exports = DisposableEmailProvider;
