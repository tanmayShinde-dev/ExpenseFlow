const BaseThreatProvider = require('./BaseThreatProvider');

class VirusTotalProvider extends BaseThreatProvider {
  constructor(options = {}) {
    super('VirusTotal', {
      capabilities: ['IP', 'CHECKSUM', 'CALLBACK_URL'],
      timeoutMs: 5000,
      weight: 1.0,
      ...options
    });
    this.apiKey = options.apiKey || process.env.VIRUSTOTAL_API_KEY;
  }

  async fetch(indicatorType, indicatorValue) {
    if (!this.apiKey) {
      return {
        confidence: 0,
        riskScore: 0,
        indicators: [],
        metadata: { reason: 'VIRUSTOTAL_API_KEY not configured' }
      };
    }

    if (indicatorType === 'IP') {
      const response = await this.get(
        `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicatorValue)}`,
        { headers: { 'x-apikey': this.apiKey } }
      );

      const stats = response?.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const total = Object.values(stats).reduce((acc, val) => acc + Number(val || 0), 0) || 1;
      const riskScore = Math.min(100, Math.round(((malicious + suspicious) / total) * 100));

      return {
        confidence: 0.9,
        riskScore,
        indicators: riskScore >= 70 ? ['KNOWN_BOTNET_IP'] : [],
        metadata: { stats }
      };
    }

    if (indicatorType === 'CHECKSUM') {
      const response = await this.get(
        `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicatorValue)}`,
        { headers: { 'x-apikey': this.apiKey } }
      );

      const stats = response?.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const total = Object.values(stats).reduce((acc, val) => acc + Number(val || 0), 0) || 1;
      const riskScore = Math.min(100, Math.round(((malicious + suspicious) / total) * 100));

      return {
        confidence: 0.95,
        riskScore,
        indicators: riskScore >= 50 ? ['MALWARE_CHECKSUM'] : [],
        metadata: { stats }
      };
    }

    const response = await this.get(
      `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(Buffer.from(indicatorValue).toString('base64url'))}`,
      { headers: { 'x-apikey': this.apiKey } }
    );

    const stats = response?.data?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const total = Object.values(stats).reduce((acc, val) => acc + Number(val || 0), 0) || 1;
    const riskScore = Math.min(100, Math.round(((malicious + suspicious) / total) * 100));

    return {
      confidence: 0.9,
      riskScore,
      indicators: riskScore >= 50 ? ['C2_CALLBACK'] : [],
      metadata: { stats }
    };
  }
}

module.exports = VirusTotalProvider;
