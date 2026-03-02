const BaseThreatProvider = require('./BaseThreatProvider');

class AlienVaultOTXProvider extends BaseThreatProvider {
  constructor(options = {}) {
    super('AlienVaultOTX', {
      capabilities: ['IP', 'DOMAIN'],
      timeoutMs: 4500,
      weight: 0.9,
      ...options
    });
    this.apiKey = options.apiKey || process.env.ALIENVAULT_OTX_API_KEY;
  }

  async fetch(indicatorType, indicatorValue) {
    const headers = this.apiKey ? { 'X-OTX-API-KEY': this.apiKey } : {};

    if (indicatorType === 'IP') {
      const response = await this.get(
        `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(indicatorValue)}/general`,
        { headers }
      );

      const pulseInfo = response?.data?.pulse_info || {};
      const pulseCount = Number(pulseInfo.count || 0);
      const reputation = Number(response?.data?.reputation || 0);
      const riskScore = Math.min(100, Math.max(0, reputation + pulseCount * 4));
      const indicators = [];

      if (pulseCount >= 3) indicators.push('KNOWN_BOTNET_IP');
      if (pulseCount >= 5) indicators.push('C2_CALLBACK');

      return {
        confidence: this.apiKey ? 0.85 : 0.65,
        riskScore,
        indicators,
        metadata: {
          pulseCount,
          reputation,
          sections: response?.data?.sections || []
        }
      };
    }

    const response = await this.get(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(indicatorValue)}/general`,
      { headers }
    );

    const pulseInfo = response?.data?.pulse_info || {};
    const pulseCount = Number(pulseInfo.count || 0);

    return {
      confidence: this.apiKey ? 0.8 : 0.6,
      riskScore: Math.min(100, pulseCount * 10),
      indicators: pulseCount > 0 ? ['C2_CALLBACK'] : [],
      metadata: {
        pulseCount
      }
    };
  }
}

module.exports = AlienVaultOTXProvider;
