/**
 * Real-Time Threat Intelligence Integration Service
 * Issue #877: Real-Time Threat Intelligence Integration
 */

const ThreatIntelligenceCache = require('../models/ThreatIntelligenceCache');

const AbuseIPDBProvider = require('./threatIntel/providers/AbuseIPDBProvider');
const AlienVaultOTXProvider = require('./threatIntel/providers/AlienVaultOTXProvider');
const VirusTotalProvider = require('./threatIntel/providers/VirusTotalProvider');
const InternalBlacklistProvider = require('./threatIntel/providers/InternalBlacklistProvider');

class ThreatIntelIntegrationService {
  constructor() {
    this.providers = [];
    this.defaultTtlSeconds = Number(process.env.THREAT_INTEL_CACHE_TTL_SECONDS || 900);
    this.internalBlacklistProvider = null;
    this.initialized = false;
  }

  initialize() {
    if (this.initialized) return;

    const internal = new InternalBlacklistProvider();
    const abuse = new AbuseIPDBProvider();
    const otx = new AlienVaultOTXProvider();
    const vt = new VirusTotalProvider();

    this.internalBlacklistProvider = internal;
    this.providers = [internal, abuse, otx, vt];
    this.initialized = true;

    console.log(`[ThreatIntelIntegrationService] Initialized ${this.providers.length} providers`);
  }

  getProvidersForType(indicatorType) {
    return this.providers.filter(provider => provider.supports(indicatorType));
  }

  mapToCacheEntityType(indicatorType) {
    if (indicatorType === 'CALLBACK_URL') return 'CALLBACK_URL';
    if (indicatorType === 'CHECKSUM') return 'CHECKSUM';
    return indicatorType;
  }

  async getThreatAssessment({
    ipAddress,
    malwareChecksum,
    c2CallbackUrl,
    forceRefresh = false,
    requestContext = {}
  } = {}) {
    this.initialize();

    const assessments = [];

    if (ipAddress) {
      assessments.push(await this.queryIndicator('IP', ipAddress, { forceRefresh, requestContext }));
    }

    if (malwareChecksum) {
      assessments.push(await this.queryIndicator('CHECKSUM', malwareChecksum, { forceRefresh, requestContext }));
    }

    if (c2CallbackUrl) {
      assessments.push(await this.queryIndicator('CALLBACK_URL', c2CallbackUrl, { forceRefresh, requestContext }));
    }

    if (assessments.length === 0) {
      return {
        overallRiskScore: 0,
        indicators: [],
        confidence: 0.5,
        byIndicator: []
      };
    }

    const overallRiskScore = Math.min(
      100,
      Math.max(...assessments.map(item => Number(item?.aggregated?.riskScore || 0)))
    );

    const indicators = [...new Set(
      assessments.flatMap(item => item?.aggregated?.indicators || [])
    )];

    const confidenceValues = assessments
      .map(item => Number(item?.aggregated?.confidence || 0))
      .filter(val => !Number.isNaN(val));

    const confidence = confidenceValues.length > 0
      ? confidenceValues.reduce((a, b) => a + b, 0) / confidenceValues.length
      : 0.5;

    return {
      overallRiskScore,
      indicators,
      confidence,
      byIndicator: assessments,
      degraded: assessments.some(item => item.degraded === true)
    };
  }

  async queryIndicator(indicatorType, indicatorValue, options = {}) {
    this.initialize();

    const forceRefresh = options.forceRefresh === true;
    const cacheEntityType = this.mapToCacheEntityType(indicatorType);

    if (!forceRefresh) {
      const cached = await ThreatIntelligenceCache.getCached(cacheEntityType, String(indicatorValue));
      if (cached) {
        return {
          indicatorType,
          indicatorValue,
          fromCache: true,
          degraded: false,
          aggregated: {
            riskScore: Number(cached?.aggregatedRisk?.overallScore || 0),
            indicators: (cached?.enrichment?.customThreat?.indicators || []),
            confidence: Number(cached?.enrichment?.customThreat?.confidence || 0.5),
            providers: cached?.metadata?.providers || []
          }
        };
      }
    }

    const providers = this.getProvidersForType(indicatorType);
    const providerResults = await Promise.all(
      providers.map(provider => provider.execute(indicatorType, indicatorValue, options.requestContext || {}))
    );

    const successful = providerResults.filter(result => result.status === 'success');

    const aggregated = this.aggregateProviderResults(successful, providerResults);

    const cachePayload = {
      customThreat: {
        indicatorType,
        indicators: aggregated.indicators,
        confidence: aggregated.confidence,
        providerCount: successful.length,
        fetchedAt: new Date(),
        ttl: this.defaultTtlSeconds
      }
    };

    if (indicatorType === 'IP') {
      cachePayload.ipReputation = {
        score: aggregated.riskScore,
        categories: aggregated.indicators,
        reportsCount: successful.length,
        isMalicious: aggregated.riskScore >= 70,
        confidence: aggregated.confidence,
        sources: successful.map(item => item.provider),
        fetchedAt: new Date(),
        ttl: this.defaultTtlSeconds
      };
    }

    const cachedDoc = await ThreatIntelligenceCache.storeEnrichment(
      cacheEntityType,
      String(indicatorValue),
      cachePayload,
      this.defaultTtlSeconds
    );

    cachedDoc.aggregatedRisk = {
      overallScore: aggregated.riskScore,
      riskLevel: this.getRiskLevel(aggregated.riskScore),
      factors: aggregated.indicators.map(indicator => ({
        factor: indicator,
        weight: 1,
        contribution: aggregated.riskScore
      }))
    };

    cachedDoc.metadata.providers = providerResults.map(result => ({
      name: result.provider,
      status: this.mapProviderStatus(result.status),
      lastAttempt: new Date(),
      latencyMs: result.latencyMs || 0,
      error: result.error
    }));

    await cachedDoc.save();

    return {
      indicatorType,
      indicatorValue,
      fromCache: false,
      degraded: successful.length === 0,
      aggregated,
      providers: providerResults
    };
  }

  aggregateProviderResults(successful, allResults) {
    if (successful.length === 0) {
      return {
        riskScore: 0,
        indicators: [],
        confidence: 0.2,
        providersAvailable: allResults.length,
        providersSucceeded: 0
      };
    }

    const weightedScores = successful.map(result => {
      const provider = this.providers.find(item => item.name === result.provider);
      const weight = provider?.weight || 1;
      return {
        score: Number(result.riskScore || 0),
        weight
      };
    });

    const weightedSum = weightedScores.reduce((sum, item) => sum + item.score * item.weight, 0);
    const totalWeight = weightedScores.reduce((sum, item) => sum + item.weight, 0) || 1;
    const riskScore = Math.min(100, Math.round(weightedSum / totalWeight));

    const indicators = [...new Set(successful.flatMap(result => result.indicators || []))];

    const confidenceValues = successful
      .map(result => Number(result.confidence || 0.5))
      .filter(val => !Number.isNaN(val));

    const confidence = confidenceValues.length
      ? confidenceValues.reduce((a, b) => a + b, 0) / confidenceValues.length
      : 0.5;

    return {
      riskScore,
      indicators,
      confidence,
      providersAvailable: allResults.length,
      providersSucceeded: successful.length
    };
  }

  mapProviderStatus(status) {
    if (status === 'success') return 'success';
    if (status === 'unavailable') return 'unavailable';
    return 'failure';
  }

  getRiskLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
  }

  async ingestIndicator({ indicatorType, indicatorValue, source = 'INTERNAL_FEED', ttlSeconds } = {}) {
    this.initialize();

    if (!indicatorType || !indicatorValue) {
      throw new Error('indicatorType and indicatorValue are required');
    }

    const normalizedType = indicatorType === 'BOTNET_IP' ? 'IP' : indicatorType;
    const normalizedValue = String(indicatorValue).trim();

    if (this.internalBlacklistProvider) {
      if (indicatorType === 'BOTNET_IP') {
        this.internalBlacklistProvider.addToBlacklist('IP', normalizedValue);
      } else if (indicatorType === 'C2_CALLBACK_URL') {
        this.internalBlacklistProvider.addToBlacklist('CALLBACK_URL', normalizedValue);
      } else {
        this.internalBlacklistProvider.addToBlacklist(normalizedType, normalizedValue);
      }
    }

    const cacheType = this.mapToCacheEntityType(
      indicatorType === 'BOTNET_IP'
        ? 'IP'
        : indicatorType === 'C2_CALLBACK_URL'
          ? 'CALLBACK_URL'
          : normalizedType
    );

    const effectiveTtl = Number(ttlSeconds || this.defaultTtlSeconds);

    const cached = await ThreatIntelligenceCache.storeEnrichment(
      cacheType,
      normalizedValue,
      {
        customThreat: {
          indicatorType,
          indicators: [indicatorType],
          confidence: 1,
          source,
          fetchedAt: new Date(),
          ttl: effectiveTtl
        },
        ipReputation: cacheType === 'IP' ? {
          score: 100,
          categories: [indicatorType],
          reportsCount: 1,
          isMalicious: true,
          confidence: 1,
          sources: [source],
          fetchedAt: new Date(),
          ttl: effectiveTtl
        } : undefined
      },
      effectiveTtl
    );

    cached.aggregatedRisk = {
      overallScore: 100,
      riskLevel: 'CRITICAL',
      factors: [{ factor: indicatorType, weight: 1, contribution: 100 }]
    };

    cached.metadata.providers = [{
      name: source,
      status: 'success',
      lastAttempt: new Date(),
      latencyMs: 0
    }];

    await cached.save();

    return {
      indicatorType,
      indicatorValue: normalizedValue,
      source,
      riskLevel: 'CRITICAL'
    };
  }

  async getStatus() {
    this.initialize();

    const cacheStats = await ThreatIntelligenceCache.getStats();
    return {
      providers: this.providers.map(provider => ({
        name: provider.name,
        enabled: provider.enabled,
        capabilities: provider.capabilities,
        weight: provider.weight
      })),
      cache: cacheStats
    };
  }
}

module.exports = new ThreatIntelIntegrationService();
