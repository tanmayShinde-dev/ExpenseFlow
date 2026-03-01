/**
 * Circuit Breaker Implementation
 * Issue #849: Real-Time Threat Intelligence Enrichment Pipeline
 * 
 * Implements circuit breaker pattern for provider resilience
 * States: CLOSED (normal), OPEN (failing), HALF_OPEN (testing recovery)
 */

class CircuitBreaker {
  constructor(options = {}) {
    this.name = options.name || 'CircuitBreaker';
    this.failureThreshold = options.failureThreshold || 5;
    this.successThreshold = options.successThreshold || 2;
    this.timeout = options.timeout || 60000; // 60 seconds
    this.resetTimeout = options.resetTimeout || 30000; // 30 seconds
    
    // State
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttempt = Date.now();
    this.lastFailure = null;
    this.lastSuccess = null;
    
    // Metrics
    this.metrics = {
      totalCalls: 0,
      successfulCalls: 0,
      failedCalls: 0,
      timeouts: 0,
      circuitOpens: 0,
      circuitCloses: 0
    };
  }
  
  /**
   * Execute a function through the circuit breaker
   */
  async execute(fn, fallback = null) {
    this.metrics.totalCalls++;
    
    // Check if circuit is open
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        // Circuit still open, use fallback
        if (fallback) {
          return await fallback();
        }
        throw new Error(`Circuit breaker [${this.name}] is OPEN`);
      }
      
      // Try to transition to HALF_OPEN
      this.state = 'HALF_OPEN';
      this.successCount = 0;
    }
    
    try {
      // Execute with timeout
      const result = await this._executeWithTimeout(fn, this.timeout);
      
      // Success - record it
      this.onSuccess();
      
      return result;
    } catch (error) {
      // Failure - record it
      this.onFailure(error);
      
      // Use fallback if available
      if (fallback) {
        return await fallback();
      }
      
      throw error;
    }
  }
  
  /**
   * Execute function with timeout
   */
  async _executeWithTimeout(fn, timeoutMs) {
    return new Promise(async (resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.metrics.timeouts++;
        reject(new Error(`Operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      
      try {
        const result = await fn();
        clearTimeout(timeoutId);
        resolve(result);
      } catch (error) {
        clearTimeout(timeoutId);
        reject(error);
      }
    });
  }
  
  /**
   * Handle successful execution
   */
  onSuccess() {
    this.failureCount = 0;
    this.lastSuccess = new Date();
    this.metrics.successfulCalls++;
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      
      if (this.successCount >= this.successThreshold) {
        // Enough successes, close the circuit
        this.state = 'CLOSED';
        this.metrics.circuitCloses++;
        console.log(`[Circuit Breaker: ${this.name}] Circuit CLOSED after ${this.successCount} successes`);
      }
    }
  }
  
  /**
   * Handle failed execution
   */
  onFailure(error) {
    this.failureCount++;
    this.lastFailure = {
      time: new Date(),
      error: error.message
    };
    this.metrics.failedCalls++;
    
    if (this.state === 'HALF_OPEN') {
      // Failed while testing, open again
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
      this.metrics.circuitOpens++;
      console.log(`[Circuit Breaker: ${this.name}] Circuit OPEN again during testing`);
    } else if (this.failureCount >= this.failureThreshold) {
      // Too many failures, open the circuit
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
      this.metrics.circuitOpens++;
      console.log(`[Circuit Breaker: ${this.name}] Circuit OPEN after ${this.failureCount} failures`);
    }
  }
  
  /**
   * Get circuit breaker status
   */
  getStatus() {
    return {
      name: this.name,
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailure: this.lastFailure,
      lastSuccess: this.lastSuccess,
      nextAttempt: this.state === 'OPEN' ? new Date(this.nextAttempt) : null,
      metrics: this.metrics
    };
  }
  
  /**
   * Manually reset the circuit breaker
   */
  reset() {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttempt = Date.now();
    console.log(`[Circuit Breaker: ${this.name}] Manually reset`);
  }
  
  /**
   * Check if circuit is allowing requests
   */
  isAllowingRequests() {
    if (this.state === 'CLOSED') return true;
    if (this.state === 'HALF_OPEN') return true;
    if (this.state === 'OPEN' && Date.now() >= this.nextAttempt) return true;
    return false;
  }
}

module.exports = CircuitBreaker;
