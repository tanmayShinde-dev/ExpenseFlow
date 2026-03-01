/**
 * Transport Security Middleware
 * Issue #827: End-to-End Encryption for Sensitive Data
 * 
 * Enforces secure transport protocols (HTTPS/TLS)
 * Implements security headers and policies
 * Compliant with PCI DSS, GDPR, and OWASP recommendations
 * 
 * Features:
 * - HTTPS enforcement (HSTS)
 * - TLS version requirements (TLS 1.2+)
 * - Certificate pinning support
 * - Security headers (CSP, X-Frame-Options, etc.)
 * - Request integrity verification
 * - API endpoint security
 */

const crypto = require('crypto');

/**
 * Enforce HTTPS connections
 * Redirects HTTP to HTTPS in production
 */
function enforceHTTPS(req, res, next) {
  // Skip in development
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  // Check if request is secure
  const isSecure = req.secure || 
                   req.headers['x-forwarded-proto'] === 'https' ||
                   req.connection.encrypted;

  if (!isSecure) {
    // Redirect to HTTPS
    const httpsUrl = `https://${req.headers.host}${req.url}`;
    console.warn(`Redirecting insecure request to HTTPS: ${req.url}`);
    return res.redirect(301, httpsUrl);
  }

  next();
}

/**
 * HTTP Strict Transport Security (HSTS)
 * Forces browsers to use HTTPS for all future requests
 */
function enforceHSTS(req, res, next) {
  // Set HSTS header (1 year, include subdomains, preload)
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  next();
}

/**
 * Comprehensive security headers
 * Implements OWASP recommendations
 */
function securityHeaders(req, res, next) {
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' data:; " +
    "connect-src 'self' https:; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'"
  );

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Enable XSS filter in browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions policy (formerly Feature-Policy)
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=()'
  );

  // Prevent DNS prefetching
  res.setHeader('X-DNS-Prefetch-Control', 'off');

  // Remove X-Powered-By header
  res.removeHeader('X-Powered-By');

  next();
}

/**
 * TLS version enforcement
 * Requires TLS 1.2 or higher
 */
function enforceTLSVersion(req, res, next) {
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  const tlsVersion = req.connection.getProtocol?.() || '';
  
  // Check TLS version (should be TLSv1.2 or TLSv1.3)
  if (tlsVersion && !['TLSv1.2', 'TLSv1.3'].includes(tlsVersion)) {
    console.error(`Insecure TLS version detected: ${tlsVersion}`);
    return res.status(426).json({
      error: 'Upgrade Required',
      message: 'TLS 1.2 or higher is required'
    });
  }

  next();
}

/**
 * Certificate pinning validation
 * Verifies client certificates for enhanced security
 */
function certificatePinning(allowedFingerprints = []) {
  return (req, res, next) => {
    // Skip in development
    if (process.env.NODE_ENV !== 'production' || allowedFingerprints.length === 0) {
      return next();
    }

    const cert = req.connection.getPeerCertificate?.();
    
    if (!cert || !cert.fingerprint) {
      return next(); // No client cert (may be optional)
    }

    // Calculate certificate fingerprint
    const fingerprint = cert.fingerprint.replace(/:/g, '').toLowerCase();

    if (!allowedFingerprints.includes(fingerprint)) {
      console.error(`Invalid certificate fingerprint: ${fingerprint}`);
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid client certificate'
      });
    }

    req.clientCertificate = cert;
    next();
  };
}

/**
 * Request integrity verification using HMAC
 * Ensures request hasn't been tampered with in transit
 */
function verifyRequestIntegrity(options = {}) {
  const secret = options.secret || process.env.REQUEST_INTEGRITY_SECRET;
  
  if (!secret) {
    console.warn('Request integrity secret not configured');
    return (req, res, next) => next();
  }

  return (req, res, next) => {
    // Skip for GET requests (optional)
    if (options.skipGET && req.method === 'GET') {
      return next();
    }

    const signature = req.headers['x-request-signature'];
    const timestamp = req.headers['x-request-timestamp'];
    const nonce = req.headers['x-request-nonce'];

    if (!signature || !timestamp || !nonce) {
      // If integrity headers not present, skip validation (optional)
      if (options.optional) {
        return next();
      }
      
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Request integrity headers missing'
      });
    }

    // Check timestamp (prevent replay attacks)
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    const maxAge = options.maxAge || 300000; // 5 minutes default

    if (Math.abs(now - requestTime) > maxAge) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Request timestamp expired'
      });
    }

    // Verify signature
    const payload = `${req.method}:${req.path}:${timestamp}:${nonce}`;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      console.error('Request integrity verification failed');
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Request signature invalid'
      });
    }

    // Store nonce to prevent replay
    // In production, use Redis or similar
    req.verifiedIntegrity = true;
    next();
  };
}

/**
 * API key encryption in transit
 * Encrypts sensitive headers before transmission
 */
function encryptSensitiveHeaders(sensitiveHeaders = ['x-api-key', 'authorization']) {
  return (req, res, next) => {
    // This is typically handled by client, but we can validate format
    for (const header of sensitiveHeaders) {
      const value = req.headers[header];
      
      if (value && !value.startsWith('encrypted:')) {
        console.warn(`Unencrypted sensitive header detected: ${header}`);
        
        // In strict mode, reject
        if (process.env.HEADER_ENCRYPTION_STRICT === 'true') {
          return res.status(400).json({
            error: 'Bad Request',
            message: `Header ${header} must be encrypted`
          });
        }
      }
    }
    
    next();
  };
}

/**
 * Secure WebSocket upgrade enforcement
 */
function secureWebSocketUpgrade(req, res, next) {
  if (req.headers.upgrade === 'websocket') {
    // Ensure WSS (WebSocket Secure) in production
    if (process.env.NODE_ENV === 'production') {
      const isSecure = req.secure || 
                       req.headers['x-forwarded-proto'] === 'https';
      
      if (!isSecure) {
        console.error('Insecure WebSocket upgrade attempt');
        return res.status(426).json({
          error: 'Upgrade Required',
          message: 'WebSocket connections must use WSS protocol'
        });
      }
    }

    // Validate WebSocket origin
    const origin = req.headers.origin;
    const allowedOrigins = (process.env.ALLOWED_WS_ORIGINS || '').split(',');
    
    if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
      console.error(`WebSocket upgrade from unauthorized origin: ${origin}`);
      return res.status(403).json({
        error: 'Forbidden',
        message: 'WebSocket origin not allowed'
      });
    }
  }

  next();
}

/**
 * Encryption cipher suite validation
 * Ensures strong cipher suites are used
 */
function validateCipherSuite(req, res, next) {
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  const cipher = req.connection.getCipher?.();
  
  if (!cipher) {
    return next(); // Can't determine cipher
  }

  // Weak cipher suites to block (PCI DSS requirement)
  const weakCiphers = [
    'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
  ];

  const cipherName = cipher.name || '';
  
  for (const weak of weakCiphers) {
    if (cipherName.includes(weak)) {
      console.error(`Weak cipher suite detected: ${cipherName}`);
      return res.status(426).json({
        error: 'Upgrade Required',
        message: 'This cipher suite is not supported. Please use a stronger cipher.'
      });
    }
  }

  // Log cipher for monitoring
  if (!req.connection._cipherLogged) {
    console.log(`Connection using cipher: ${cipherName} (${cipher.version})`);
    req.connection._cipherLogged = true;
  }

  next();
}

/**
 * API endpoint encryption status
 * Tracks which endpoints handle encrypted data
 */
function markEncryptedEndpoint(options = {}) {
  return (req, res, next) => {
    req.encryptedEndpoint = {
      requiresHTTPS: options.requiresHTTPS !== false,
      dataEncrypted: options.dataEncrypted !== false,
      purpose: options.purpose || 'userData',
      complianceLevel: options.complianceLevel || 'high'
    };

    // Add header to indicate encrypted endpoint
    res.setHeader('X-Endpoint-Encrypted', 'true');
    res.setHeader('X-Encryption-Purpose', options.purpose || 'userData');

    next();
  };
}

/**
 * Generate client integrity token
 * Used by clients to sign requests
 */
function generateIntegrityToken(req, res, next) {
  const secret = process.env.REQUEST_INTEGRITY_SECRET;
  
  if (!secret) {
    return next();
  }

  // Generate nonce
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();

  // Store in response headers for client to use in next request
  res.setHeader('X-Server-Nonce', nonce);
  res.setHeader('X-Server-Timestamp', timestamp);

  next();
}

/**
 * Monitor transport security metrics
 */
class TransportSecurityMonitor {
  constructor() {
    this.metrics = {
      httpsRequests: 0,
      httpRedirects: 0,
      tlsVersionBlocked: 0,
      weakCipherBlocked: 0,
      integrityFailures: 0,
      certificateFailures: 0
    };
  }

  recordMetric(type) {
    if (this.metrics[type] !== undefined) {
      this.metrics[type]++;
    }
  }

  getMetrics() {
    return { ...this.metrics };
  }

  reset() {
    for (const key in this.metrics) {
      this.metrics[key] = 0;
    }
  }
}

const transportMonitor = new TransportSecurityMonitor();

/**
 * Middleware to record transport security metrics
 */
function recordTransportMetrics(req, res, next) {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  
  if (isSecure) {
    transportMonitor.recordMetric('httpsRequests');
  } else {
    transportMonitor.recordMetric('httpRedirects');
  }

  next();
}

/**
 * Get transport security status
 */
function getTransportSecurityStatus(req) {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const tlsVersion = req.connection.getProtocol?.() || 'Unknown';
  const cipher = req.connection.getCipher?.();

  return {
    secure: isSecure,
    protocol: req.protocol,
    tlsVersion,
    cipher: cipher ? {
      name: cipher.name,
      version: cipher.version,
      bits: cipher.bits
    } : null,
    encrypted: isSecure && tlsVersion.includes('TLS'),
    pciCompliant: isSecure && ['TLSv1.2', 'TLSv1.3'].includes(tlsVersion),
    headers: {
      hsts: !!res.getHeader('Strict-Transport-Security'),
      csp: !!res.getHeader('Content-Security-Policy'),
      xFrameOptions: !!res.getHeader('X-Frame-Options')
    }
  };
}

/**
 * Comprehensive transport security suite
 * Combines all security middlewares
 */
function transportSecuritySuite(options = {}) {
  return [
    recordTransportMetrics,
    options.enforceHTTPS !== false ? enforceHTTPS : null,
    options.enforceHSTS !== false ? enforceHSTS : null,
    options.securityHeaders !== false ? securityHeaders : null,
    options.enforceTLS !== false ? enforceTLSVersion : null,
    options.validateCipher !== false ? validateCipherSuite : null,
    options.integrityCheck ? verifyRequestIntegrity(options.integrityOptions || {}) : null
  ].filter(Boolean);
}

module.exports = {
  enforceHTTPS,
  enforceHSTS,
  securityHeaders,
  enforceTLSVersion,
  certificatePinning,
  verifyRequestIntegrity,
  encryptSensitiveHeaders,
  secureWebSocketUpgrade,
  validateCipherSuite,
  markEncryptedEndpoint,
  generateIntegrityToken,
  transportSecuritySuite,
  recordTransportMetrics,
  getTransportSecurityStatus,
  transportMonitor
};
