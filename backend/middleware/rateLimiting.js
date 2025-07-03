/**
 * Rate Limiting Middleware
 * Implements various rate limiting strategies for API endpoints
 */

const rateLimit = require('express-rate-limit');
const RedisStore = require('express-rate-limit-redis');
const redisService = require('../services/redis');
const { logger, loggerUtils } = require('../config/logger');
const config = require('../config/env');

/**
 * Create Redis store for rate limiting
 * @returns {Object|null} Redis store or null if Redis not available
 */
const createRedisStore = () => {
  try {
    if (redisService.isReady()) {
      return new RedisStore({
        client: redisService.client,
        prefix: 'rate_limit:',
        resetExpiryOnChange: true
      });
    }
    return null;
  } catch (error) {
    logger.error('Failed to create Redis store for rate limiting:', error);
    return null;
  }
};

/**
 * Custom key generator for rate limiting
 * @param {Object} req - Express request object
 * @returns {string} Rate limit key
 */
const generateKey = (req) => {
  // Use user ID if authenticated, otherwise use IP
  const identifier = req.user?.id || req.ip;
  const endpoint = req.route?.path || req.path;
  return `${identifier}:${endpoint}`;
};

/**
 * Custom handler for rate limit exceeded
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const rateLimitHandler = (req, res, next) => {
  const identifier = req.user?.id || req.ip;
  
  loggerUtils.logSecurity('rate_limit_exceeded', req.ip, {
    userId: req.user?.id,
    endpoint: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent'),
    limit: req.rateLimit?.limit,
    current: req.rateLimit?.current,
    resetTime: req.rateLimit?.resetTime
  });

  res.status(429).json({
    status: 'error',
    message: 'Too many requests',
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      limit: req.rateLimit?.limit,
      current: req.rateLimit?.current,
      remaining: req.rateLimit?.remaining,
      resetTime: req.rateLimit?.resetTime
    }
  });
};

/**
 * Skip rate limiting function
 * @param {Object} req - Express request object
 * @returns {boolean} Whether to skip rate limiting
 */
const skipRateLimit = (req) => {
  // Skip rate limiting for admin users in development
  if (config.NODE_ENV === 'development' && req.user?.role === 'admin') {
    return true;
  }
  
  // Skip for health check endpoints
  if (req.path === '/health' || req.path === '/status') {
    return true;
  }
  
  return false;
};

/**
 * General API rate limiting
 */
const generalRateLimit = rateLimit({
  windowMs: config.security.rateLimitWindowMs, // 15 minutes
  max: config.security.rateLimitMaxRequests, // 100 requests per window
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later'
  }
});

/**
 * Strict rate limiting for authentication endpoints
 */
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  store: createRedisStore(),
  keyGenerator: (req) => {
    // Use phone number or username for auth endpoints
    const identifier = req.body.phone_number || req.body.username || req.ip;
    return `auth:${identifier}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again later'
  }
});

/**
 * SMS rate limiting
 */
const smsRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 SMS per hour
  store: createRedisStore(),
  keyGenerator: (req) => {
    const phoneNumber = req.body.phone_number || req.user?.phone_number;
    return `sms:${phoneNumber}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'SMS rate limit exceeded, please try again later'
  }
});

/**
 * Password reset rate limiting
 */
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  store: createRedisStore(),
  keyGenerator: (req) => {
    const identifier = req.body.phone_number || req.body.email || req.ip;
    return `password_reset:${identifier}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many password reset attempts, please try again later'
  }
});

/**
 * File upload rate limiting
 */
const uploadRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 uploads per window
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Upload rate limit exceeded, please try again later'
  }
});

/**
 * Search rate limiting
 */
const searchRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 searches per minute
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Search rate limit exceeded, please try again later'
  }
});

/**
 * Post creation rate limiting
 */
const postRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 posts per hour
  store: createRedisStore(),
  keyGenerator: (req) => {
    return `posts:${req.user?.id || req.ip}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Post creation rate limit exceeded, please try again later'
  }
});

/**
 * Message sending rate limiting
 */
const messageRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 messages per minute
  store: createRedisStore(),
  keyGenerator: (req) => {
    return `messages:${req.user?.id || req.ip}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Message rate limit exceeded, please slow down'
  }
});

/**
 * Friend request rate limiting
 */
const friendRequestRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // 50 friend requests per hour
  store: createRedisStore(),
  keyGenerator: (req) => {
    return `friend_requests:${req.user?.id || req.ip}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Friend request rate limit exceeded, please try again later'
  }
});

/**
 * Custom rate limiting middleware
 * @param {Object} options - Rate limiting options
 * @returns {Function} Rate limiting middleware
 */
const createCustomRateLimit = (options = {}) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    store: createRedisStore(),
    keyGenerator: generateKey,
    handler: rateLimitHandler,
    skip: skipRateLimit,
    standardHeaders: true,
    legacyHeaders: false
  };

  return rateLimit({ ...defaultOptions, ...options });
};

/**
 * Dynamic rate limiting based on user tier
 * @param {Object} req - Express request object
 * @returns {number} Rate limit for user
 */
const getDynamicRateLimit = (req) => {
  if (!req.user) {
    return 50; // Anonymous users
  }

  if (req.user.is_verified) {
    return 200; // Verified users
  }

  return 100; // Regular users
};

/**
 * Adaptive rate limiting middleware
 */
const adaptiveRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: (req) => getDynamicRateLimit(req),
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Rate limiting for specific IP addresses
 * @param {Array} blockedIPs - Array of blocked IP addresses
 * @returns {Function} Middleware function
 */
const ipRateLimit = (blockedIPs = []) => {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: (req) => {
      if (blockedIPs.includes(req.ip)) {
        return 1; // Very strict limit for blocked IPs
      }
      return 100; // Normal limit
    },
    store: createRedisStore(),
    keyGenerator: (req) => req.ip,
    handler: rateLimitHandler,
    standardHeaders: true,
    legacyHeaders: false
  });
};

/**
 * Burst rate limiting - allows short bursts but limits sustained usage
 */
const burstRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 20, // 20 requests per minute
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Sliding window rate limiting
 */
const slidingWindowRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  store: createRedisStore(),
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  // Use sliding window instead of fixed window
  skipSuccessfulRequests: false,
  skipFailedRequests: false
});

module.exports = {
  generalRateLimit,
  authRateLimit,
  smsRateLimit,
  passwordResetRateLimit,
  uploadRateLimit,
  searchRateLimit,
  postRateLimit,
  messageRateLimit,
  friendRequestRateLimit,
  adaptiveRateLimit,
  burstRateLimit,
  slidingWindowRateLimit,
  createCustomRateLimit,
  ipRateLimit
};