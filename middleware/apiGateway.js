const jwt = require('jsonwebtoken');
const apiGatewayPolicyService = require('../services/apiGatewayPolicyService');
const securityMonitor = require('../services/securityMonitor');

class ApiGateway {
  constructor() {
    this.rateLimitStore = new Map();
    this.trackedMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

    apiGatewayPolicyService.on('reloaded', (event) => {
      console.log('API Gateway policies reloaded:', event);
    });

    apiGatewayPolicyService.on('reload_error', (event) => {
      console.error('API Gateway policy reload error:', event);
    });

    apiGatewayPolicyService.on('updated', (event) => {
      console.log('API Gateway policies updated:', event);
    });
  }

  getClientIp(req) {
    return req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
  }

  getAuthToken(req) {
    const authHeader = req.header('Authorization') || req.header('authorization');
    if (!authHeader || typeof authHeader !== 'string') {
      return null;
    }

    if (!authHeader.startsWith('Bearer ')) {
      return null;
    }

    return authHeader.replace('Bearer ', '').trim();
  }

  verifyJwtToken(token) {
    if (!process.env.JWT_SECRET) {
      return null;
    }

    try {
      return {
        type: 'jwt',
        claims: jwt.verify(token, process.env.JWT_SECRET)
      };
    } catch (error) {
      return null;
    }
  }

  verifyOAuthToken(token) {
    const publicKey = process.env.OAUTH2_JWT_PUBLIC_KEY;
    const sharedSecret = process.env.OAUTH2_JWT_SECRET;

    if (!publicKey && !sharedSecret) {
      return null;
    }

    const verifier = publicKey || sharedSecret;

    try {
      return {
        type: 'oauth2',
        claims: jwt.verify(token, verifier, {
          algorithms: publicKey ? ['RS256', 'RS384', 'RS512'] : ['HS256', 'HS384', 'HS512'],
          audience: process.env.OAUTH2_AUDIENCE || undefined,
          issuer: process.env.OAUTH2_ISSUER || undefined
        })
      };
    } catch (error) {
      return null;
    }
  }

  extractScopes(claims = {}) {
    if (Array.isArray(claims.scopes)) {
      return claims.scopes;
    }

    if (Array.isArray(claims.scope)) {
      return claims.scope;
    }

    if (typeof claims.scope === 'string') {
      return claims.scope
        .split(/\s+/)
        .map((value) => value.trim())
        .filter(Boolean);
    }

    return [];
  }

  enforceAuthentication(req, res, policy) {
    if (!policy.authRequired) {
      return true;
    }

    const token = this.getAuthToken(req);

    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Authentication required by API gateway policy',
        code: 'GATEWAY_AUTH_REQUIRED'
      });
      return false;
    }

    const allowedAuth = Array.isArray(policy.allowedAuth) && policy.allowedAuth.length > 0
      ? policy.allowedAuth
      : ['jwt', 'oauth2'];

    let verified = null;

    if (allowedAuth.includes('jwt')) {
      verified = this.verifyJwtToken(token);
    }

    if (!verified && allowedAuth.includes('oauth2')) {
      verified = this.verifyOAuthToken(token);
    }

    if (!verified) {
      res.status(401).json({
        success: false,
        error: 'Token validation failed for allowed auth strategies',
        code: 'GATEWAY_AUTH_INVALID'
      });
      return false;
    }

    const requiredScopes = Array.isArray(policy.requiredScopes) ? policy.requiredScopes : [];
    const tokenScopes = this.extractScopes(verified.claims);
    const missingScopes = requiredScopes.filter((scope) => !tokenScopes.includes(scope));

    if (missingScopes.length > 0) {
      res.status(403).json({
        success: false,
        error: 'Insufficient token scope for this endpoint',
        code: 'GATEWAY_SCOPE_DENIED',
        missingScopes
      });
      return false;
    }

    req.gatewayAuth = {
      type: verified.type,
      claims: verified.claims,
      scopes: tokenScopes
    };

    return true;
  }

  applyRateLimit(req, res, policy) {
    const rateLimit = policy.rateLimit || {};
    const windowMs = Number(rateLimit.windowMs) || 60000;
    const max = Number(rateLimit.max) || 120;

    const routeKey = policy.policyId || policy.pattern || req.path;
    const clientIp = this.getClientIp(req);
    const key = `${routeKey}:${clientIp}`;
    const now = Date.now();

    const previous = this.rateLimitStore.get(key);
    if (!previous || now > previous.resetAt) {
      this.rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }

    if (previous.count >= max) {
      const retryAfterSeconds = Math.ceil((previous.resetAt - now) / 1000);
      res.set('Retry-After', String(retryAfterSeconds));
      res.status(429).json({
        success: false,
        error: 'Rate limit exceeded by API gateway policy',
        code: 'GATEWAY_RATE_LIMITED',
        retryAfterSeconds
      });
      return false;
    }

    previous.count += 1;
    this.rateLimitStore.set(key, previous);
    return true;
  }

  validateRequest(req, res, policy) {
    const requestValidation = policy.requestValidation || {};
    const allowedContentTypes = Array.isArray(requestValidation.allowedContentTypes)
      ? requestValidation.allowedContentTypes
      : [];

    if (this.trackedMethods.has(req.method.toUpperCase()) && allowedContentTypes.length > 0) {
      const contentType = (req.headers['content-type'] || '').toLowerCase();
      const isAllowed = allowedContentTypes.some((allowedType) => contentType.includes(String(allowedType).toLowerCase()));

      if (!isAllowed) {
        res.status(415).json({
          success: false,
          error: 'Unsupported content type by API gateway policy',
          code: 'GATEWAY_CONTENT_TYPE_REJECTED'
        });
        return false;
      }
    }

    const requiredBodyFields = Array.isArray(requestValidation.requiredBodyFields)
      ? requestValidation.requiredBodyFields
      : [];

    if (requiredBodyFields.length > 0) {
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const missingFields = requiredBodyFields.filter((field) => {
        const value = body[field];
        return value === undefined || value === null || value === '';
      });

      if (missingFields.length > 0) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields by API gateway policy',
          code: 'GATEWAY_VALIDATION_FAILED',
          missingFields
        });
        return false;
      }
    }

    return true;
  }

  flattenValues(input, output = []) {
    if (input === null || input === undefined) {
      return output;
    }

    if (typeof input === 'string' || typeof input === 'number' || typeof input === 'boolean') {
      output.push(String(input));
      return output;
    }

    if (Array.isArray(input)) {
      for (const item of input) {
        this.flattenValues(item, output);
      }
      return output;
    }

    if (typeof input === 'object') {
      for (const [key, value] of Object.entries(input)) {
        output.push(String(key));
        this.flattenValues(value, output);
      }
    }

    return output;
  }

  getThreatPatterns(sensitivity = 'medium') {
    const low = [
      { type: 'xss', regex: /<\s*script\b|javascript:|onerror\s*=|onload\s*=/i },
      { type: 'sql_injection', regex: /(union\s+select|drop\s+table|information_schema|or\s+1=1|--|;\s*shutdown)/i }
    ];

    const highOnly = [
      { type: 'sql_injection', regex: /(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|into\s+outfile)/i },
      { type: 'xss', regex: /<\s*iframe\b|<\s*svg\b|document\.cookie|window\.location/i }
    ];

    if (sensitivity === 'high') {
      return low.concat(highOnly);
    }

    if (sensitivity === 'low') {
      return low;
    }

    return low.concat([{ type: 'nosql_injection', regex: /(\$where|\$regex|\$ne|\$gt|\$lt)/i }]);
  }

  detectThreats(req, policy) {
    const threatPolicy = policy.threatDetection || {};
    if (!threatPolicy.enabled) {
      return { detected: false, matches: [] };
    }

    const values = [];
    this.flattenValues(req.query, values);
    this.flattenValues(req.params, values);
    this.flattenValues(req.body, values);
    values.push(req.originalUrl || '');
    values.push(req.headers['user-agent'] || '');

    const patterns = this.getThreatPatterns(threatPolicy.sensitivity || 'medium');
    const matches = [];

    for (const rawValue of values) {
      for (const pattern of patterns) {
        if (pattern.regex.test(rawValue)) {
          matches.push({
            type: pattern.type,
            sample: rawValue.slice(0, 140)
          });
        }
      }
    }

    return {
      detected: matches.length > 0,
      matches
    };
  }

  blockOrLogThreat(req, res, policy, threatReport) {
    for (const threat of threatReport.matches) {
      securityMonitor.logSecurityEvent(req, 'gateway_threat_detected', {
        threatType: threat.type,
        sample: threat.sample,
        endpoint: req.originalUrl,
        method: req.method,
        policyId: policy.policyId || 'unknown'
      });
    }

    if (policy.threatDetection?.blockOnDetection) {
      res.status(403).json({
        success: false,
        error: 'Request blocked by API gateway threat detection',
        code: 'GATEWAY_THREAT_BLOCKED',
        threats: threatReport.matches.map((threat) => threat.type)
      });
      return false;
    }

    return true;
  }

  logRequest(req, res, policy, startedAt, context = {}) {
    const durationMs = Date.now() - startedAt;
    const logEntry = {
      timestamp: new Date().toISOString(),
      gateway: true,
      endpoint: req.originalUrl,
      method: req.method,
      policyId: policy.policyId || 'default',
      statusCode: res.statusCode,
      durationMs,
      ip: this.getClientIp(req),
      authType: req.gatewayAuth?.type || null,
      blocked: Boolean(context.blocked),
      threatDetected: Boolean(context.threatDetected)
    };

    console.log('API_GATEWAY_LOG', JSON.stringify(logEntry));
  }

  middleware() {
    return (req, res, next) => {
      const startedAt = Date.now();
      const policy = apiGatewayPolicyService.getPolicyForRequest(req);

      res.on('finish', () => {
        this.logRequest(req, res, policy, startedAt, req.gatewayContext || {});
      });

      if (!this.validateRequest(req, res, policy)) {
        req.gatewayContext = { blocked: true, threatDetected: false };
        return;
      }

      if (!this.applyRateLimit(req, res, policy)) {
        req.gatewayContext = { blocked: true, threatDetected: false };
        securityMonitor.logSecurityEvent(req, 'gateway_rate_limit', {
          endpoint: req.originalUrl,
          method: req.method,
          policyId: policy.policyId || 'default'
        });
        return;
      }

      const threatReport = this.detectThreats(req, policy);
      if (threatReport.detected) {
        const allowed = this.blockOrLogThreat(req, res, policy, threatReport);
        req.gatewayContext = { blocked: !allowed, threatDetected: true };
        if (!allowed) {
          return;
        }
      }

      if (!this.enforceAuthentication(req, res, policy)) {
        req.gatewayContext = { blocked: true, threatDetected: threatReport.detected };
        securityMonitor.logSecurityEvent(req, 'gateway_auth_denied', {
          endpoint: req.originalUrl,
          method: req.method,
          policyId: policy.policyId || 'default'
        });
        return;
      }

      req.gatewayPolicy = policy;
      req.gatewayContext = { blocked: false, threatDetected: threatReport.detected };
      next();
    };
  }
}

module.exports = new ApiGateway();
module.exports.ApiGateway = ApiGateway;
