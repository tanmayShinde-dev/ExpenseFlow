const axios = require('axios');

/**
 * Base pluggable threat provider
 * Issue #877: Real-Time Threat Intelligence Integration
 */
class BaseThreatProvider {
  constructor(name, options = {}) {
    this.name = name;
    this.enabled = options.enabled !== false;
    this.timeoutMs = options.timeoutMs || 5000;
    this.capabilities = options.capabilities || [];
    this.weight = options.weight || 1.0;
  }

  supports(indicatorType) {
    return this.capabilities.includes(indicatorType);
  }

  async fetch() {
    throw new Error('fetch() must be implemented by provider');
  }

  async execute(indicatorType, indicatorValue, context = {}) {
    if (!this.enabled) {
      return {
        provider: this.name,
        status: 'unavailable',
        error: 'Provider disabled',
        latencyMs: 0
      };
    }

    if (!this.supports(indicatorType)) {
      return {
        provider: this.name,
        status: 'unsupported',
        error: `Unsupported indicator type: ${indicatorType}`,
        latencyMs: 0
      };
    }

    const startedAt = Date.now();

    try {
      const response = await this.withTimeout(
        this.fetch(indicatorType, indicatorValue, context),
        this.timeoutMs
      );

      return {
        provider: this.name,
        status: 'success',
        latencyMs: Date.now() - startedAt,
        ...response
      };
    } catch (error) {
      return {
        provider: this.name,
        status: 'failure',
        latencyMs: Date.now() - startedAt,
        error: error.message || 'Provider request failed'
      };
    }
  }

  async get(url, config = {}) {
    return axios.get(url, {
      timeout: this.timeoutMs,
      ...config
    });
  }

  withTimeout(promise, timeoutMs) {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Provider timeout after ${timeoutMs}ms`)), timeoutMs)
      )
    ]);
  }
}

module.exports = BaseThreatProvider;
