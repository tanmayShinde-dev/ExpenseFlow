const CircuitBreaker = require('../../utils/CircuitBreaker');
const RetryHandler = require('../../utils/RetryHandler');

/**
 * Base Threat Intelligence Provider
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Abstract base class for all enrichment providers
 */

class BaseThreatIntelProvider {
  constructor(name, options = {}) {
    this.name = name;
    this.enabled = options.enabled !== false;
    this.timeout = options.timeout || 5000; // 5 seconds default
    this.cacheTTL = options.cacheTTL || 3600; // 1 hour default
    this.confidence = options.confidence || 0.8; // Default confidence
    
    // Circuit breaker
    this.circuitBreaker = new CircuitBreaker({
      name: `${name}-breaker`,
      failureThreshold: options.failureThreshold || 5,
      successThreshold: options.successThreshold || 2,
      timeout: this.timeout,
      resetTimeout: options.resetTimeout || 30000
    });
    
    // Retry handler
    this.retryHandler = new RetryHandler({
      maxRetries: options.maxRetries || 2,
      initialDelayMs: options.initialDelayMs || 500,
      maxDelayMs: options.maxDelayMs || 5000
    });
    
    // Metrics
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      avgLatencyMs: 0,
      totalLatencyMs: 0
    };
  }
  
  /**
   * Main enrichment method - to be implemented by subclasses
   */
  async enrich(entityType, entityValue) {
    throw new Error('enrich() must be implemented by subclass');
  }
  
  /**
   * Execute enrichment with circuit breaker and retry logic
   */
  async executeEnrichment(entityType, entityValue) {
    if (!this.enabled) {
      return this._unavailableResponse();
    }
    
    this.metrics.totalRequests++;
    const startTime = Date.now();
    
    try {
      // Execute through circuit breaker
      const result = await this.circuitBreaker.execute(
        () => this.retryHandler.execute(() => this.enrich(entityType, entityValue)),
        () => this._fallbackResponse()
      );
      
      // Record metrics
      const latency = Date.now() - startTime;
      this.metrics.totalLatencyMs += latency;
      this.metrics.avgLatencyMs = this.metrics.totalLatencyMs / this.metrics.totalRequests;
      
      if (result.success) {
        this.metrics.successfulRequests++;
        return this._successResponse(result.data, latency);
      } else {
        this.metrics.failedRequests++;
        return this._errorResponse(result.error, latency);
      }
    } catch (error) {
      const latency = Date.now() - startTime;
      this.metrics.failedRequests++;
      return this._errorResponse(error, latency);
    }
  }
  
  /**
   * Format successful response
   */
  _successResponse(data, latencyMs) {
    return {
      provider: this.name,
      status: 'success',
      data,
      confidence: this.confidence,
      latencyMs,
      fetchedAt: new Date(),
      ttl: this.cacheTTL,
      sources: [this.name]
    };
  }
  
  /**
   * Format error response
   */
  _errorResponse(error, latencyMs) {
    return {
      provider: this.name,
      status: 'failure',
      error: error?.message || 'Unknown error',
      confidence: 0,
      latencyMs,
      fetchedAt: new Date(),
      ttl: 60, // Short TTL for errors
      sources: [this.name]
    };
  }
  
  /**
   * Format fallback response (circuit breaker open)
   */
  _fallbackResponse() {
    return {
      success: false,
      error: new Error(`Provider ${this.name} is currently unavailable (circuit breaker open)`)
    };
  }
  
  /**
   * Format unavailable response (provider disabled)
   */
  _unavailableResponse() {
    return {
      provider: this.name,
      status: 'unavailable',
      error: 'Provider is disabled',
      confidence: 0,
      fetchedAt: new Date(),
      ttl: 300, // 5 minutes
      sources: [this.name]
    };
  }
  
  /**
   * Get provider status
   */
  getStatus() {
    return {
      name: this.name,
      enabled: this.enabled,
      circuitBreaker: this.circuitBreaker.getStatus(),
      retryHandler: this.retryHandler.getMetrics(),
      metrics: {
        ...this.metrics,
        successRate: this.metrics.totalRequests > 0
          ? (this.metrics.successfulRequests / this.metrics.totalRequests) * 100
          : 0
      }
    };
  }
  
  /**
   * Reset provider metrics
   */
  resetMetrics() {
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      avgLatencyMs: 0,
      totalLatencyMs: 0
    };
    this.retryHandler.resetMetrics();
  }
  
  /**
   * Validate API key or credentials
   */
  validateCredentials() {
    // Override in subclasses if needed
    return true;
  }
}

module.exports = BaseThreatIntelProvider;
