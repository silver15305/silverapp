/**
 * Security Utilities
 * Security-related helper functions for authentication, encryption, and validation
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { logger } = require('../config/logger');

/**
 * JWT Token Management
 */
class TokenManager {
  /**
   * Generate access token
   * @param {Object} payload - Token payload
   * @returns {string} JWT access token
   */
  static generateAccessToken(payload) {
    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
      issuer: 'silverapp',
      audience: 'silverapp-users'
    });
  }

  /**
   * Generate refresh token
   * @param {Object} payload - Token payload
   * @returns {string} JWT refresh token
   */
  static generateRefreshToken(payload) {
    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiresIn,
      issuer: 'silverapp',
      audience: 'silverapp-users'
    });
  }

  /**
   * Verify access token
   * @param {string} token - JWT token to verify
   * @returns {Object} Decoded token payload
   */
  static verifyAccessToken(token) {
    try {
      return jwt.verify(token, config.jwt.secret, {
        issuer: 'silverapp',
        audience: 'silverapp-users'
      });
    } catch (error) {
      logger.error('Access token verification failed:', error);
      throw error;
    }
  }

  /**
   * Verify refresh token
   * @param {string} token - JWT refresh token to verify
   * @returns {Object} Decoded token payload
   */
  static verifyRefreshToken(token) {
    try {
      return jwt.verify(token, config.jwt.refreshSecret, {
        issuer: 'silverapp',
        audience: 'silverapp-users'
      });
    } catch (error) {
      logger.error('Refresh token verification failed:', error);
      throw error;
    }
  }

  /**
   * Generate token pair (access + refresh)
   * @param {Object} payload - Token payload
   * @returns {Object} Token pair
   */
  static generateTokenPair(payload) {
    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);
    
    return {
      accessToken,
      refreshToken,
      expiresIn: config.jwt.expiresIn
    };
  }

  /**
   * Decode token without verification (for debugging)
   * @param {string} token - JWT token to decode
   * @returns {Object} Decoded token
   */
  static decodeToken(token) {
    return jwt.decode(token, { complete: true });
  }
}

/**
 * Encryption/Decryption utilities
 */
class CryptoManager {
  static algorithm = 'aes-256-gcm';
  static keyLength = 32;
  static ivLength = 16;
  static tagLength = 16;

  /**
   * Generate encryption key
   * @returns {string} Base64 encoded key
   */
  static generateKey() {
    return crypto.randomBytes(this.keyLength).toString('base64');
  }

  /**
   * Encrypt text
   * @param {string} text - Text to encrypt
   * @param {string} key - Encryption key (base64)
   * @returns {Object} Encrypted data with IV and tag
   */
  static encrypt(text, key) {
    try {
      const keyBuffer = Buffer.from(key, 'base64');
      const iv = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipheriv(this.algorithm, keyBuffer, iv);
      cipher.setAAD(Buffer.from('silverapp', 'utf8'));

      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag();

      return {
        encrypted,
        iv: iv.toString('hex'),
        tag: tag.toString('hex')
      };
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt text
   * @param {Object} encryptedData - Encrypted data object
   * @param {string} key - Decryption key (base64)
   * @returns {string} Decrypted text
   */
  static decrypt(encryptedData, key) {
    try {
      const keyBuffer = Buffer.from(key, 'base64');
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const tag = Buffer.from(encryptedData.tag, 'hex');
      const decipher = crypto.createDecipheriv(this.algorithm, keyBuffer, iv);
      
      decipher.setAAD(Buffer.from('silverapp', 'utf8'));
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw new Error('Decryption failed');
    }
  }

  /**
   * Hash password with salt
   * @param {string} password - Password to hash
   * @param {string} salt - Salt (optional, will generate if not provided)
   * @returns {Object} Hash and salt
   */
  static hashPassword(password, salt = null) {
    if (!salt) {
      salt = crypto.randomBytes(32).toString('hex');
    }
    
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    
    return { hash, salt };
  }

  /**
   * Verify password against hash
   * @param {string} password - Password to verify
   * @param {string} hash - Stored hash
   * @param {string} salt - Stored salt
   * @returns {boolean} Verification result
   */
  static verifyPassword(password, hash, salt) {
    const hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === hashVerify;
  }
}

/**
 * Input validation and sanitization
 */
class ValidationManager {
  /**
   * Sanitize HTML input
   * @param {string} input - Input to sanitize
   * @returns {string} Sanitized input
   */
  static sanitizeHtml(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, ''')
      )
      .replace(/\//g, '/');
  }

  /**
   * Validate and sanitize username
   * @param {string} username - Username to validate
   * @returns {Object} Validation result
   */
  static validateUsername(username) {
    const errors = [];
    
    if (!username || typeof username !== 'string') {
      errors.push('Username is required');
      return { isValid: false, errors, sanitized: null };
    }
    
    const sanitized = username.trim().toLowerCase();
    
    if (sanitized.length < 3) {
      errors.push('Username must be at least 3 characters long');
    }
    
    if (sanitized.length > 50) {
      errors.push('Username must be less than 50 characters long');
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(sanitized)) {
      errors.push('Username can only contain letters, numbers, and underscores');
    }
    
    if (/^[0-9]/.test(sanitized)) {
      errors.push('Username cannot start with a number');
    }
    
    const reservedUsernames = ['admin', 'root', 'user', 'test', 'api', 'www', 'mail', 'support'];
    if (reservedUsernames.includes(sanitized)) {
      errors.push('Username is reserved');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitized: errors.length === 0 ? sanitized : null
    };
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result with strength score
   */
  static validatePassword(password) {
    const errors = [];
    let score = 0;
    
    if (!password || typeof password !== 'string') {
      errors.push('Password is required');
      return { isValid: false, errors, score: 0 };
    }
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    } else {
      score += 1;
    }
    
    if (password.length >= 12) {
      score += 1;
    }
    
    if (/[a-z]/.test(password)) {
      score += 1;
    } else {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (/[A-Z]/.test(password)) {
      score += 1;
    } else {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (/[0-9]/.test(password)) {
      score += 1;
    } else {
      errors.push('Password must contain at least one number');
    }
    
    if (/[^a-zA-Z0-9]/.test(password)) {
      score += 1;
    } else {
      errors.push('Password must contain at least one special character');
    }
    
    // Check for common patterns
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /abc123/i,
      /(.)\1{2,}/ // Repeated characters
    ];
    
    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        errors.push('Password contains common patterns');
        score = Math.max(0, score - 1);
        break;
      }
    }
    
    const strength = score <= 2 ? 'weak' : score <= 4 ? 'medium' : 'strong';
    
    return {
      isValid: errors.length === 0,
      errors,
      score,
      strength
    };
  }

  /**
   * Validate phone number
   * @param {string} phone - Phone number to validate
   * @returns {Object} Validation result
   */
  static validatePhoneNumber(phone) {
    const errors = [];
    
    if (!phone || typeof phone !== 'string') {
      errors.push('Phone number is required');
      return { isValid: false, errors, sanitized: null };
    }
    
    // Remove all non-digit characters for validation
    const digits = phone.replace(/\D/g, '');
    
    if (digits.length < 10) {
      errors.push('Phone number must be at least 10 digits');
    }
    
    if (digits.length > 15) {
      errors.push('Phone number must be less than 15 digits');
    }
    
    // Normalize to E.164 format
    let normalized = phone.trim();
    if (!normalized.startsWith('+')) {
      if (digits.length === 10) {
        normalized = `+1${digits}`; // Assume US number
      } else {
        normalized = `+${digits}`;
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitized: errors.length === 0 ? normalized : null
    };
  }

  /**
   * Validate email address
   * @param {string} email - Email to validate
   * @returns {Object} Validation result
   */
  static validateEmail(email) {
    const errors = [];
    
    if (!email || typeof email !== 'string') {
      return { isValid: true, errors: [], sanitized: null }; // Email is optional
    }
    
    const sanitized = email.trim().toLowerCase();
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitized)) {
      errors.push('Invalid email format');
    }
    
    if (sanitized.length > 255) {
      errors.push('Email must be less than 255 characters');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitized: errors.length === 0 ? sanitized : null
    };
  }
}

/**
 * Rate limiting utilities
 */
class RateLimitManager {
  /**
   * Create rate limit key
   * @param {string} identifier - User identifier (IP, user ID, etc.)
   * @param {string} action - Action being rate limited
   * @returns {string} Rate limit key
   */
  static createKey(identifier, action) {
    return `rate_limit:${action}:${identifier}`;
  }

  /**
   * Check if action is rate limited
   * @param {Object} redisClient - Redis client
   * @param {string} key - Rate limit key
   * @param {number} limit - Request limit
   * @param {number} windowMs - Time window in milliseconds
   * @returns {Promise<Object>} Rate limit status
   */
  static async checkRateLimit(redisClient, key, limit, windowMs) {
    try {
      const current = await redisClient.incr(key);
      
      if (current === 1) {
        await redisClient.expire(key, Math.ceil(windowMs / 1000));
      }
      
      const ttl = await redisClient.ttl(key);
      
      return {
        isLimited: current > limit,
        current,
        limit,
        remaining: Math.max(0, limit - current),
        resetTime: new Date(Date.now() + (ttl * 1000))
      };
    } catch (error) {
      logger.error('Rate limit check failed:', error);
      // Fail open - allow request if Redis is down
      return {
        isLimited: false,
        current: 0,
        limit,
        remaining: limit,
        resetTime: new Date(Date.now() + windowMs)
      };
    }
  }
}

/**
 * Security headers and CSRF protection
 */
class SecurityHeaders {
  /**
   * Get security headers
   * @returns {Object} Security headers
   */
  static getSecurityHeaders() {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
    };
  }

  /**
   * Generate CSRF token
   * @returns {string} CSRF token
   */
  static generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Verify CSRF token
   * @param {string} token - Token to verify
   * @param {string} sessionToken - Session token
   * @returns {boolean} Verification result
   */
  static verifyCSRFToken(token, sessionToken) {
    return crypto.timingSafeEqual(
      Buffer.from(token, 'hex'),
      Buffer.from(sessionToken, 'hex')
    );
  }
}

module.exports = {
  TokenManager,
  CryptoManager,
  ValidationManager,
  RateLimitManager,
  SecurityHeaders
};