/**
 * Retry Logic with Exponential Backoff
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Provides retry functionality with exponential backoff and jitter
 */

class RetryHandler {
  constructor(options = {}) {
    this.maxRetries = options.maxRetries || 3;
    this.initialDelayMs = options.initialDelayMs || 1000;
    this.maxDelayMs = options.maxDelayMs || 10000;
    this.backoffMultiplier = options.backoffMultiplier || 2;
    this.jitter = options.jitter !== false; // Default true
    
    // Metrics
    this.metrics = {
      totalAttempts: 0,
      successfulAttempts: 0,
      failedAttempts: 0,
      retriesPerformed: 0
    };
  }
  
  /**
   * Execute function with retry logic
   */
  async execute(fn, options = {}) {
    const maxRetries = options.maxRetries || this.maxRetries;
    const shouldRetry = options.shouldRetry || this._defaultShouldRetry;
    
    let lastError;
    let attempt = 0;
    
    while (attempt <= maxRetries) {
      this.metrics.totalAttempts++;
      
      try {
        const result = await fn();
        this.metrics.successfulAttempts++;
        
        if (attempt > 0) {
          this.metrics.retriesPerformed += attempt;
        }
        
        return {
          success: true,
          data: result,
          attempts: attempt + 1
        };
      } catch (error) {
        lastError = error;
        attempt++;
        
        // Check if we should retry this error
        if (!shouldRetry(error) || attempt > maxRetries) {
          this.metrics.failedAttempts++;
          break;
        }
        
        // Calculate delay with exponential backoff
        const delay = this._calculateDelay(attempt);
        
        console.log(`Retry attempt ${attempt}/${maxRetries} after ${delay}ms. Error: ${error.message}`);
        
        // Wait before retrying
        await this._sleep(delay);
      }
    }
    
    // All retries exhausted
    this.metrics.failedAttempts++;
    
    return {
      success: false,
      error: lastError,
      attempts: attempt
    };
  }
  
  /**
   * Calculate delay with exponential backoff and jitter
   */
  _calculateDelay(attempt) {
    // Exponential backoff: delay = initialDelay * (multiplier ^ attempt)
    let delay = this.initialDelayMs * Math.pow(this.backoffMultiplier, attempt - 1);
    
    // Cap at max delay
    delay = Math.min(delay, this.maxDelayMs);
    
    // Add jitter to prevent thundering herd
    if (this.jitter) {
      const jitterAmount = delay * 0.25; // 25% jitter
      delay = delay - jitterAmount + (Math.random() * jitterAmount * 2);
    }
    
    return Math.floor(delay);
  }
  
  /**
   * Default retry decision logic
   */
  _defaultShouldRetry(error) {
    // Retry on network errors, timeouts, and 5xx errors
    if (error.code === 'ECONNREFUSED') return true;
    if (error.code === 'ETIMEDOUT') return true;
    if (error.code === 'ENOTFOUND') return true;
    if (error.message?.includes('timeout')) return true;
    if (error.response?.status >= 500) return true;
    if (error.response?.status === 429) return true; // Rate limited
    
    // Don't retry client errors (4xx except 429)
    if (error.response?.status >= 400 && error.response?.status < 500) {
      return false;
    }
    
    // Retry by default for unknown errors
    return true;
  }
  
  /**
   * Sleep utility
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Get retry handler metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      successRate: this.metrics.totalAttempts > 0 
        ? (this.metrics.successfulAttempts / this.metrics.totalAttempts) * 100 
        : 0,
      avgRetriesPerSuccess: this.metrics.successfulAttempts > 0
        ? this.metrics.retriesPerformed / this.metrics.successfulAttempts
        : 0
    };
  }
  
  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      totalAttempts: 0,
      successfulAttempts: 0,
      failedAttempts: 0,
      retriesPerformed: 0
    };
  }
}

module.exports = RetryHandler;
