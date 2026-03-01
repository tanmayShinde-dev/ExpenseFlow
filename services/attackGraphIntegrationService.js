const SecurityEvent = require('../models/SecurityEvent');
const attackGraphDetectionService = require('./attackGraphDetectionService');
const cron = require('node-cron');

/**
 * Attack Graph Integration Service
 * Issue #848: Cross-Account Attack Graph Detection
 * 
 * Integrates attack graph detection with the existing security infrastructure
 * Automatically processes security events and schedules periodic analysis
 */

class AttackGraphIntegrationService {
  constructor() {
    this.isInitialized = false;
    this.cronJob = null;
    this.eventProcessingQueue = [];
    this.isProcessing = false;
    
    // Configuration
    this.config = {
      batchSize: 50,
      processingIntervalMs: 5000, // Process batch every 5 seconds
      fullAnalysisSchedule: '0 */6 * * *', // Every 6 hours
      enableRealTimeProcessing: true
    };
  }
  
  /**
   * Initialize the integration service
   */
  initialize() {
    if (this.isInitialized) {
      console.log('[Attack Graph Integration] Already initialized');
      return;
    }
    
    console.log('[Attack Graph Integration] Initializing...');
    
    // Set up event listener for new security events
    this.setupSecurityEventListener();
    
    // Schedule periodic full graph analysis
    this.scheduleFullAnalysis();
    
    // Start batch processing
    this.startBatchProcessing();
    
    this.isInitialized = true;
    console.log('[Attack Graph Integration] Initialized successfully');
  }
  
  /**
   * Set up listener for new security events
   */
  setupSecurityEventListener() {
    // Watch for new security events in MongoDB (using change streams)
    if (this.config.enableRealTimeProcessing) {
      try {
        const SecurityEventModel = SecurityEvent;
        const changeStream = SecurityEventModel.watch([
          {
            $match: {
              operationType: 'insert',
              'fullDocument.eventType': {
                $in: [
                  'LOGIN_ATTEMPT',
                  'SUSPICIOUS_LOGIN',
                  'BRUTE_FORCE_ATTEMPT',
                  '2FA_FAILURE',
                  'SESSION_ANOMALY_DETECTED',
                  'IMPOSSIBLE_TRAVEL_DETECTED'
                ]
              }
            }
          }
        ]);
        
        changeStream.on('change', async (change) => {
          if (change.operationType === 'insert') {
            const securityEvent = change.fullDocument;
            await this.queueEventForProcessing(securityEvent);
          }
        });
        
        console.log('[Attack Graph Integration] Security event listener started');
      } catch (error) {
        console.error('[Attack Graph Integration] Failed to setup change stream:', error);
        console.log('[Attack Graph Integration] Falling back to polling mode');
        this.setupPollingMode();
      }
    }
  }
  
  /**
   * Fallback polling mode if change streams not available
   */
  setupPollingMode() {
    let lastCheckTime = new Date();
    
    setInterval(async () => {
      try {
        const newEvents = await SecurityEvent.find({
          createdAt: { $gt: lastCheckTime },
          eventType: {
            $in: [
              'LOGIN_ATTEMPT',
              'SUSPICIOUS_LOGIN',
              'BRUTE_FORCE_ATTEMPT',
              '2FA_FAILURE',
              'SESSION_ANOMALY_DETECTED',
              'IMPOSSIBLE_TRAVEL_DETECTED'
            ]
          }
        }).sort({ createdAt: 1 });
        
        for (const event of newEvents) {
          await this.queueEventForProcessing(event);
        }
        
        lastCheckTime = new Date();
      } catch (error) {
        console.error('[Attack Graph Integration] Polling error:', error);
      }
    }, 30000); // Poll every 30 seconds
  }
  
  /**
   * Queue an event for batch processing
   */
  async queueEventForProcessing(securityEvent) {
    this.eventProcessingQueue.push(securityEvent);
    
    // If queue is getting large, process immediately
    if (this.eventProcessingQueue.length >= this.config.batchSize) {
      await this.processBatch();
    }
  }
  
  /**
   * Start batch processing timer
   */
  startBatchProcessing() {
    setInterval(async () => {
      if (this.eventProcessingQueue.length > 0 && !this.isProcessing) {
        await this.processBatch();
      }
    }, this.config.processingIntervalMs);
  }
  
  /**
   * Process a batch of events
   */
  async processBatch() {
    if (this.isProcessing || this.eventProcessingQueue.length === 0) {
      return;
    }
    
    this.isProcessing = true;
    
    try {
      const batchSize = Math.min(this.config.batchSize, this.eventProcessingQueue.length);
      const batch = this.eventProcessingQueue.splice(0, batchSize);
      
      console.log(`[Attack Graph Integration] Processing batch of ${batch.length} events`);
      
      // Process events in parallel (with rate limiting)
      const results = await Promise.allSettled(
        batch.map(event => this.processSecurityEvent(event))
      );
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      
      console.log(`[Attack Graph Integration] Batch complete: ${successful} successful, ${failed} failed`);
    } catch (error) {
      console.error('[Attack Graph Integration] Batch processing error:', error);
    } finally {
      this.isProcessing = false;
    }
  }
  
  /**
   * Process a single security event
   */
  async processSecurityEvent(securityEvent) {
    try {
      await attackGraphDetectionService.processSecurityEvent(securityEvent);
    } catch (error) {
      console.error('[Attack Graph Integration] Error processing event:', error);
      throw error;
    }
  }
  
  /**
   * Schedule periodic full graph analysis
   */
  scheduleFullAnalysis() {
    // Run full analysis every 6 hours
    this.cronJob = cron.schedule(this.config.fullAnalysisSchedule, async () => {
      console.log('[Attack Graph Integration] Starting scheduled full graph analysis');
      
      try {
        const result = await attackGraphDetectionService.runFullGraphAnalysis();
        console.log('[Attack Graph Integration] Full analysis complete:', result);
      } catch (error) {
        console.error('[Attack Graph Integration] Full analysis error:', error);
      }
    });
    
    console.log(`[Attack Graph Integration] Scheduled full analysis: ${this.config.fullAnalysisSchedule}`);
  }
  
  /**
   * Manually trigger a full analysis
   */
  async triggerFullAnalysis() {
    console.log('[Attack Graph Integration] Manual full analysis triggered');
    return await attackGraphDetectionService.runFullGraphAnalysis();
  }
  
  /**
   * Get integration service status
   */
  getStatus() {
    return {
      initialized: this.isInitialized,
      queueSize: this.eventProcessingQueue.length,
      isProcessing: this.isProcessing,
      config: this.config,
      cronSchedule: this.config.fullAnalysisSchedule
    };
  }
  
  /**
   * Shutdown gracefully
   */
  shutdown() {
    console.log('[Attack Graph Integration] Shutting down...');
    
    if (this.cronJob) {
      this.cronJob.stop();
    }
    
    // Process remaining events
    if (this.eventProcessingQueue.length > 0) {
      console.log(`[Attack Graph Integration] Processing ${this.eventProcessingQueue.length} remaining events...`);
      this.processBatch().then(() => {
        console.log('[Attack Graph Integration] Shutdown complete');
      });
    } else {
      console.log('[Attack Graph Integration] Shutdown complete');
    }
    
    this.isInitialized = false;
  }
}

// Export singleton instance
module.exports = new AttackGraphIntegrationService();
