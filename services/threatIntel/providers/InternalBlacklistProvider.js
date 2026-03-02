const BaseThreatProvider = require('./BaseThreatProvider');

class InternalBlacklistProvider extends BaseThreatProvider {
  constructor(options = {}) {
    super('InternalBlacklist', {
      capabilities: ['IP', 'CHECKSUM', 'CALLBACK_URL'],
      timeoutMs: 100,
      weight: 1.2,
      ...options
    });

    this.blacklists = {
      ip: new Set((process.env.INTERNAL_BLACKLIST_IPS || '').split(',').map(v => v.trim()).filter(Boolean)),
      checksum: new Set((process.env.INTERNAL_BLACKLIST_CHECKSUMS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean)),
      callbackUrl: new Set((process.env.INTERNAL_BLACKLIST_CALLBACK_URLS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean))
    };
  }

  addToBlacklist(indicatorType, indicatorValue) {
    if (!indicatorValue) return;

    if (indicatorType === 'IP') this.blacklists.ip.add(indicatorValue.trim());
    if (indicatorType === 'CHECKSUM') this.blacklists.checksum.add(indicatorValue.trim().toLowerCase());
    if (indicatorType === 'CALLBACK_URL') this.blacklists.callbackUrl.add(indicatorValue.trim().toLowerCase());
  }

  async fetch(indicatorType, indicatorValue) {
    const normalized = String(indicatorValue || '').trim();

    if (indicatorType === 'IP' && this.blacklists.ip.has(normalized)) {
      return {
        confidence: 1,
        riskScore: 100,
        indicators: ['IP_BLACKLIST'],
        metadata: { source: 'internal_blacklist' }
      };
    }

    if (indicatorType === 'CHECKSUM' && this.blacklists.checksum.has(normalized.toLowerCase())) {
      return {
        confidence: 1,
        riskScore: 100,
        indicators: ['MALWARE_CHECKSUM'],
        metadata: { source: 'internal_blacklist' }
      };
    }

    if (indicatorType === 'CALLBACK_URL' && this.blacklists.callbackUrl.has(normalized.toLowerCase())) {
      return {
        confidence: 1,
        riskScore: 100,
        indicators: ['C2_CALLBACK'],
        metadata: { source: 'internal_blacklist' }
      };
    }

    return {
      confidence: 0.6,
      riskScore: 0,
      indicators: [],
      metadata: { source: 'internal_blacklist' }
    };
  }
}

module.exports = InternalBlacklistProvider;
