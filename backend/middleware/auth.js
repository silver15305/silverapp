/**
 * Authentication Middleware
 * Handles JWT token verification and user authentication
 */

const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const { AppError, AuthenticationError, AuthorizationError } = require('../errors/AppError');
const { TokenManager } = require('../utils/security');
const { logger, loggerUtils } = require('../config/logger');
const redisService = require('../services/redis');
const config = require('../config/env');

/**
 * Verify JWT token and authenticate user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticate = async (req, res, next) => {
  try {
    // 1) Get token from header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(new AuthenticationError('Access token required'));
    }

    // 2) Verify token
    let decoded;
    try {
      decoded = TokenManager.verifyAccessToken(token);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return next(new AuthenticationError('Access token expired'));
      }
      return next(new AuthenticationError('Invalid access token'));
    }

    // 3) Check if token is blacklisted
    const isBlacklisted = await checkTokenBlacklist(token);
    if (isBlacklisted) {
      return next(new AuthenticationError('Token has been revoked'));
    }

    // 4) Check if user still exists
    const user = await User.findByPk(decoded.userId);
    if (!user) {
      return next(new AuthenticationError('User no longer exists'));
    }

    // 5) Check if user is active
    if (!user.is_active) {
      return next(new AuthenticationError('User account is deactivated'));
    }

    // 6) Check if user changed password after token was issued
    if (user.password_changed_at && decoded.iat < user.password_changed_at.getTime() / 1000) {
      return next(new AuthenticationError('Password recently changed. Please log in again'));
    }

    // 7) Grant access to protected route
    req.user = user;
    req.token = token;

    // Log authentication event
    loggerUtils.logAuth('token_verified', user.id, req.ip, {
      userAgent: req.get('User-Agent'),
      tokenType: 'access'
    });

    next();
  } catch (error) {
    logger.error('Authentication middleware error:', error);
    return next(new AuthenticationError('Authentication failed'));
  }
};

/**
 * Optional authentication - doesn't fail if no token provided
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const optionalAuth = async (req, res, next) => {
  try {
    // Get token from header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(); // Continue without authentication
    }

    // Verify token
    let decoded;
    try {
      decoded = TokenManager.verifyAccessToken(token);
    } catch (error) {
      return next(); // Continue without authentication if token is invalid
    }

    // Check if token is blacklisted
    const isBlacklisted = await checkTokenBlacklist(token);
    if (isBlacklisted) {
      return next(); // Continue without authentication
    }

    // Check if user exists and is active
    const user = await User.findByPk(decoded.userId);
    if (user && user.is_active) {
      req.user = user;
      req.token = token;
    }

    next();
  } catch (error) {
    logger.error('Optional authentication error:', error);
    next(); // Continue without authentication on error
  }
};

/**
 * Require specific roles or permissions
 * @param {...string} roles - Required roles
 * @returns {Function} Middleware function
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AuthenticationError('Authentication required'));
    }

    if (!roles.includes(req.user.role)) {
      return next(new AuthorizationError('Insufficient permissions'));
    }

    next();
  };
};

/**
 * Check if user owns the resource or is admin
 * @param {string} resourceUserIdField - Field name containing the user ID in request params/body
 * @returns {Function} Middleware function
 */
const requireOwnership = (resourceUserIdField = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AuthenticationError('Authentication required'));
    }

    const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];
    
    if (req.user.id !== resourceUserId && req.user.role !== 'admin') {
      return next(new AuthorizationError('Access denied'));
    }

    next();
  };
};

/**
 * Verify phone number ownership
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const verifyPhoneOwnership = async (req, res, next) => {
  try {
    const { phone_number } = req.body;
    
    if (!phone_number) {
      return next(new AppError('Phone number is required', 400));
    }

    // Check if phone number belongs to authenticated user
    if (req.user && req.user.phone_number !== phone_number) {
      return next(new AuthorizationError('Phone number does not belong to authenticated user'));
    }

    next();
  } catch (error) {
    logger.error('Phone ownership verification error:', error);
    return next(new AppError('Phone verification failed', 500));
  }
};

/**
 * Rate limiting for authentication endpoints
 * @param {number} maxAttempts - Maximum attempts allowed
 * @param {number} windowMs - Time window in milliseconds
 * @param {string} keyGenerator - Function to generate rate limit key
 * @returns {Function} Middleware function
 */
const authRateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000, keyGenerator = null) => {
  return async (req, res, next) => {
    try {
      if (!redisService.isReady()) {
        return next(); // Skip rate limiting if Redis is not available
      }

      // Generate rate limit key
      let key;
      if (keyGenerator && typeof keyGenerator === 'function') {
        key = keyGenerator(req);
      } else {
        const identifier = req.body.phone_number || req.body.username || req.ip;
        key = `auth_rate_limit:${identifier}`;
      }

      // Check current attempts
      const current = await redisService.incr(key);
      
      if (current === 1) {
        await redisService.expire(key, Math.ceil(windowMs / 1000));
      }

      if (current > maxAttempts) {
        const ttl = await redisService.ttl(key);
        
        loggerUtils.logSecurity('rate_limit_exceeded', req.ip, {
          endpoint: req.originalUrl,
          attempts: current,
          maxAttempts,
          resetTime: new Date(Date.now() + (ttl * 1000))
        });

        return res.status(429).json({
          status: 'error',
          message: 'Too many authentication attempts',
          retryAfter: ttl
        });
      }

      // Add rate limit info to request
      req.rateLimit = {
        current,
        remaining: Math.max(0, maxAttempts - current),
        resetTime: new Date(Date.now() + windowMs)
      };

      next();
    } catch (error) {
      logger.error('Auth rate limiting error:', error);
      next(); // Continue without rate limiting on error
    }
  };
};

/**
 * Refresh token validation
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateRefreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return next(new AuthenticationError('Refresh token required'));
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = TokenManager.verifyRefreshToken(refreshToken);
    } catch (error) {
      return next(new AuthenticationError('Invalid refresh token'));
    }

    // Check if token is blacklisted
    const isBlacklisted = await checkTokenBlacklist(refreshToken);
    if (isBlacklisted) {
      return next(new AuthenticationError('Refresh token has been revoked'));
    }

    // Check if user exists
    const user = await User.findByPk(decoded.userId);
    if (!user) {
      return next(new AuthenticationError('User no longer exists'));
    }

    // Check if stored refresh token matches
    if (user.refresh_token !== refreshToken) {
      return next(new AuthenticationError('Invalid refresh token'));
    }

    // Check if refresh token is expired
    if (user.refresh_token_expires && new Date() > user.refresh_token_expires) {
      return next(new AuthenticationError('Refresh token expired'));
    }

    req.user = user;
    req.refreshToken = refreshToken;

    next();
  } catch (error) {
    logger.error('Refresh token validation error:', error);
    return next(new AuthenticationError('Refresh token validation failed'));
  }
};

/**
 * Check if token is blacklisted
 * @param {string} token - JWT token
 * @returns {Promise<boolean>} Whether token is blacklisted
 */
const checkTokenBlacklist = async (token) => {
  try {
    if (!redisService.isReady()) {
      return false; // Assume token is valid if Redis is not available
    }

    const key = `blacklisted_token:${token}`;
    return await redisService.exists(key);
  } catch (error) {
    logger.error('Token blacklist check error:', error);
    return false; // Assume token is valid on error
  }
};

/**
 * Blacklist token
 * @param {string} token - JWT token to blacklist
 * @param {number} expiresIn - Token expiration time in seconds
 */
const blacklistToken = async (token, expiresIn = null) => {
  try {
    if (!redisService.isReady()) {
      return;
    }

    const key = `blacklisted_token:${token}`;
    
    if (expiresIn) {
      await redisService.set(key, 'blacklisted', expiresIn);
    } else {
      // Decode token to get expiration time
      const decoded = TokenManager.decodeToken(token);
      if (decoded && decoded.payload.exp) {
        const ttl = decoded.payload.exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
          await redisService.set(key, 'blacklisted', ttl);
        }
      } else {
        // Default to 24 hours if we can't determine expiration
        await redisService.set(key, 'blacklisted', 86400);
      }
    }

    logger.info('Token blacklisted successfully');
  } catch (error) {
    logger.error('Token blacklisting error:', error);
  }
};

/**
 * Logout and blacklist token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const logout = async (req, res, next) => {
  try {
    const token = req.token;
    const user = req.user;

    if (token) {
      // Blacklist the access token
      await blacklistToken(token);
    }

    if (user && user.refresh_token) {
      // Blacklist the refresh token
      await blacklistToken(user.refresh_token);
      
      // Clear refresh token from database
      await user.update({
        refresh_token: null,
        refresh_token_expires: null
      });
    }

    // Log logout event
    loggerUtils.logAuth('logout', user?.id || 'unknown', req.ip, {
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (error) {
    logger.error('Logout error:', error);
    return next(new AppError('Logout failed', 500));
  }
};

module.exports = {
  authenticate,
  optionalAuth,
  requireRole,
  requireOwnership,
  verifyPhoneOwnership,
  authRateLimit,
  validateRefreshToken,
  checkTokenBlacklist,
  blacklistToken,
  logout
};