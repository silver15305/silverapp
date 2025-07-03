/**
 * Winston Logger Configuration
 * Provides structured logging with different levels and formats
 */

const winston = require('winston');
const path = require('path');
const config = require('./env');

/**
 * Custom log format for better readability
 */
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

/**
 * Console format for development
 */
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    return `${timestamp} [${level}]: ${stack || message}`;
  })
);

/**
 * Create logger instance with appropriate transports
 */
const logger = winston.createLogger({
  level: config.NODE_ENV === 'production' ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: { service: 'silverapp-backend' },
  transports: [
    // Write all logs with level 'error' and below to error.log
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    
    // Write all logs with level 'info' and below to combined.log
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ],
  
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/exceptions.log')
    })
  ],
  
  // Handle unhandled promise rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/rejections.log')
    })
  ]
});

/**
 * Add console transport for development
 */
if (config.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

/**
 * Create logs directory if it doesn't exist
 */
const fs = require('fs');
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Logger utility functions
 */
const loggerUtils = {
  /**
   * Log API request
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {number} responseTime - Response time in milliseconds
   */
  logRequest: (req, res, responseTime) => {
    logger.info('API Request', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id || 'anonymous'
    });
  },

  /**
   * Log authentication events
   * @param {string} event - Event type (login, logout, register, etc.)
   * @param {string} userId - User ID
   * @param {string} ip - IP address
   * @param {Object} additional - Additional data
   */
  logAuth: (event, userId, ip, additional = {}) => {
    logger.info('Authentication Event', {
      event,
      userId,
      ip,
      timestamp: new Date().toISOString(),
      ...additional
    });
  },

  /**
   * Log database operations
   * @param {string} operation - Database operation
   * @param {string} table - Table name
   * @param {Object} data - Operation data
   */
  logDatabase: (operation, table, data = {}) => {
    logger.debug('Database Operation', {
      operation,
      table,
      data: config.NODE_ENV === 'development' ? data : '[REDACTED]'
    });
  },

  /**
   * Log security events
   * @param {string} event - Security event type
   * @param {string} ip - IP address
   * @param {Object} details - Event details
   */
  logSecurity: (event, ip, details = {}) => {
    logger.warn('Security Event', {
      event,
      ip,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
};

module.exports = { logger, loggerUtils };