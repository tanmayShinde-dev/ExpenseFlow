const BaseThreatProvider = require('./BaseThreatProvider');

class AbuseIPDBProvider extends BaseThreatProvider {
  constructor(options = {}) {
    super('AbuseIPDB', {
      capabilities: ['IP'],
      timeoutMs: 4500,
      weight: 1.0,
      ...options
    });
    this.apiKey = options.apiKey || process.env.ABUSEIPDB_API_KEY;
  }

  async fetch(indicatorType, ipAddress) {
    if (!this.apiKey) {
      return {
        confidence: 0,
        riskScore: 0,
        indicators: [],
        metadata: { reason: 'ABUSEIPDB_API_KEY not configured' }
      };
    }

    const response = await this.get('https://api.abuseipdb.com/api/v2/check', {
      headers: {
        Key: this.apiKey,
        Accept: 'application/json'
      },
      params: {
        ipAddress,
        maxAgeInDays: 90,
        verbose: true
      }
    });

    const data = response?.data?.data || {};
    const riskScore = Number(data.abuseConfidenceScore || 0);
    const indicators = [];

    if (riskScore >= 80) indicators.push('IP_BLACKLIST');
    if (riskScore >= 60) indicators.push('KNOWN_BOTNET_IP');

    return {
      confidence: 0.9,
      riskScore,
      indicators,
      metadata: {
        reportsCount: data.totalReports || 0,
        usageType: data.usageType,
        isp: data.isp,
        countryCode: data.countryCode,
        domain: data.domain
      }
    };
  }
}

module.exports = AbuseIPDBProvider;
