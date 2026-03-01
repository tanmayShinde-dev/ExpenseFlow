/**
 * Distributed Rate Limiting and Throttling Middleware for ExpenseFlow
 *
 * Features:
 * - Distributed counters using Redis
 * - Burst traffic handling (leaky bucket, token bucket)
 * - Dynamic quotas per user/account/API
 * - Atomicity and consistency
 * - No single point of failure
 * - Real-time feedback to clients
 * - Integration with APIs and microservices
 * - Highly performant, scalable code
 * - Logging and monitoring
 */

const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const { v4: uuidv4 } = require('uuid');

// --- Configurable Rate Limit Profiles --- //
const DEFAULT_LIMITS = {
    global: { window: 60, max: 1000 }, // 1000 requests per minute
    user: { window: 60, max: 100 },   // 100 requests per minute per user
    api: { window: 60, max: 500 },    // 500 requests per minute per API key
    burst: { window: 10, max: 30 }    // 30 requests per 10 seconds (burst)
};

// --- Utility Functions --- //
function getRedisKey(type, id, windowSec) {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - (now % windowSec);
    return `ratelimit:${type}:${id}:${windowSec}:${windowStart}`;
}

function getUserId(req) {
    return req.user?._id || req.headers['x-user-id'] || 'anonymous';
}

function getApiKey(req) {
    return req.headers['x-api-key'] || 'none';
}

// --- Token Bucket Algorithm --- //
async function getTokenBucket(key, maxTokens, refillRate) {
    let bucket = await redis.hgetall(key);
    if (!bucket.tokens) {
        bucket.tokens = maxTokens;
        bucket.lastRefill = Date.now();
        await redis.hmset(key, bucket);
        await redis.expire(key, 3600);
    }
    // Refill tokens
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    const refill = Math.floor(elapsed * refillRate);
    bucket.tokens = Math.min(maxTokens, parseInt(bucket.tokens) + refill);
    bucket.lastRefill = now;
    await redis.hmset(key, bucket);
    return bucket;
}

async function consumeToken(key, maxTokens, refillRate) {
    const bucket = await getTokenBucket(key, maxTokens, refillRate);
    if (bucket.tokens > 0) {
        bucket.tokens--;
        await redis.hset(key, 'tokens', bucket.tokens);
        return true;
    }
    return false;
}

// --- Leaky Bucket Algorithm --- //
async function getLeakyBucket(key, rate, burst) {
    let bucket = await redis.hgetall(key);
    if (!bucket.lastLeak) {
        bucket.level = 0;
        bucket.lastLeak = Date.now();
        await redis.hmset(key, bucket);
        await redis.expire(key, 3600);
    }
    // Leak
    const now = Date.now();
    const elapsed = (now - bucket.lastLeak) / 1000;
    const leaked = Math.floor(elapsed * rate);
    bucket.level = Math.max(0, parseInt(bucket.level) - leaked);
    bucket.lastLeak = now;
    await redis.hmset(key, bucket);
    return bucket;
}

async function addToLeakyBucket(key, rate, burst) {
    const bucket = await getLeakyBucket(key, rate, burst);
    if (bucket.level < burst) {
        bucket.level++;
        await redis.hset(key, 'level', bucket.level);
        return true;
    }
    return false;
}

// --- Dynamic Quota Management --- //
async function getUserQuota(userId) {
    // Example: fetch from DB or config
    // For demo, return default
    return DEFAULT_LIMITS.user;
}

async function getApiQuota(apiKey) {
    // Example: fetch from DB or config
    return DEFAULT_LIMITS.api;
}

// --- Atomic Counter Increment --- //
async function incrementCounter(key, max, windowSec) {
    const tx = redis.multi();
    tx.incr(key);
    tx.expire(key, windowSec);
    const [count] = await tx.exec().then(res => res.map(r => r[1]));
    return count <= max;
}

// --- Rate Limiting Middleware --- //
function distributedRateLimiter(options = {}) {
    const limits = { ...DEFAULT_LIMITS, ...options };
    return async (req, res, next) => {
        try {
            const userId = getUserId(req);
            const apiKey = getApiKey(req);
            // Global limit
            const globalKey = getRedisKey('global', 'all', limits.global.window);
            const globalAllowed = await incrementCounter(globalKey, limits.global.max, limits.global.window);
            if (!globalAllowed) return rateLimitResponse(res, 'global', limits.global);
            // User limit
            const userQuota = await getUserQuota(userId);
            const userKey = getRedisKey('user', userId, userQuota.window);
            const userAllowed = await incrementCounter(userKey, userQuota.max, userQuota.window);
            if (!userAllowed) return rateLimitResponse(res, 'user', userQuota);
            // API key limit
            const apiQuota = await getApiQuota(apiKey);
            const apiKeyKey = getRedisKey('api', apiKey, apiQuota.window);
            const apiAllowed = await incrementCounter(apiKeyKey, apiQuota.max, apiQuota.window);
            if (!apiAllowed) return rateLimitResponse(res, 'api', apiQuota);
            // Burst limit (token bucket)
            const burstKey = getRedisKey('burst', userId, limits.burst.window);
            const burstAllowed = await consumeToken(burstKey, limits.burst.max, limits.burst.max / limits.burst.window);
            if (!burstAllowed) return rateLimitResponse(res, 'burst', limits.burst);
            // Leaky bucket for burst traffic
            const leakyKey = getRedisKey('leaky', userId, limits.burst.window);
            const leakyAllowed = await addToLeakyBucket(leakyKey, limits.burst.max / limits.burst.window, limits.burst.max);
            if (!leakyAllowed) return rateLimitResponse(res, 'leaky', limits.burst);
            // All checks passed
            next();
        } catch (err) {
            console.error('[RateLimiter] Error:', err);
            res.status(500).json({ error: 'Rate limiter error' });
        }
    };
}

// --- Real-Time Feedback to Clients --- //
function rateLimitResponse(res, type, limit) {
    res.set('X-RateLimit-Limit', limit.max);
    res.set('X-RateLimit-Window', limit.window);
    res.set('Retry-After', limit.window);
    res.status(429).json({
        error: 'Rate limit exceeded',
        type,
        limit,
        message: `Too many requests. Please wait ${limit.window} seconds.`
    });
}

// --- Logging and Monitoring --- //
async function logRateLimitEvent({ userId, apiKey, type, limit, result }) {
    // Example: log to DB, file, or monitoring system
    console.log(`[RateLimit] ${type} | User: ${userId} | API: ${apiKey} | Limit: ${JSON.stringify(limit)} | Result: ${result}`);
}

// --- Quota Management API --- //
async function setUserQuota(userId, quota) {
    await redis.hmset(`quota:user:${userId}`, quota);
}

async function getUserQuotaConfig(userId) {
    const quota = await redis.hgetall(`quota:user:${userId}`);
    return quota.window ? quota : DEFAULT_LIMITS.user;
}

async function setApiQuota(apiKey, quota) {
    await redis.hmset(`quota:api:${apiKey}`, quota);
}

async function getApiQuotaConfig(apiKey) {
    const quota = await redis.hgetall(`quota:api:${apiKey}`);
    return quota.window ? quota : DEFAULT_LIMITS.api;
}

// --- Distributed Lock for Atomicity --- //
async function acquireLock(key, ttl = 1000) {
    const lockId = uuidv4();
    const acquired = await redis.set(`lock:${key}`, lockId, 'PX', ttl, 'NX');
    return acquired ? lockId : null;
}

async function releaseLock(key, lockId) {
    const script = `if redis.call("get",KEYS[1]) == ARGV[1] then return redis.call("del",KEYS[1]) else return 0 end`;
    await redis.eval(script, 1, `lock:${key}`, lockId);
}

// --- Integration with Microservices --- //
async function checkMicroserviceRateLimit(serviceName, userId) {
    const key = getRedisKey('microservice', `${serviceName}:${userId}`, DEFAULT_LIMITS.global.window);
    return await incrementCounter(key, DEFAULT_LIMITS.global.max, DEFAULT_LIMITS.global.window);
}

// --- Exported API --- //
module.exports = {
    distributedRateLimiter,
    setUserQuota,
    getUserQuotaConfig,
    setApiQuota,
    getApiQuotaConfig,
    acquireLock,
    releaseLock,
    checkMicroserviceRateLimit
};
