/**
 * SQL Injection Protection Middleware
 * Detects and prevents SQL injection attempts in request data
 */

const { logger, loggerUtils } = require('../config/logger');
const { AppError } = require('../errors/AppError');

/**
 * Common SQL injection patterns
 */
const SQL_INJECTION_PATTERNS = [
  // Basic SQL injection patterns
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
  
  // SQL comments
  /(--|\#|\/\*|\*\/)/g,
  
  // SQL operators and functions
  /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
  /(\b(OR|AND)\s+['"]\w+['"]?\s*=\s*['"]\w+['"]?)/gi,
  
  // SQL injection with quotes
  /('|(\\')|(;)|(\\;))/g,
  
  // Hex encoding
  /(0x[0-9a-f]+)/gi,
  
  // SQL functions
  /(\b(CONCAT|CHAR|ASCII|SUBSTRING|LENGTH|UPPER|LOWER|REPLACE)\s*\()/gi,
  
  // Database-specific functions
  /(\b(SLEEP|BENCHMARK|WAITFOR|DELAY)\s*\()/gi,
  
  // Information schema
  /(\binformation_schema\b)/gi,
  
  // System tables
  /(\b(sys|mysql|pg_|sqlite_)\w*)/gi,
  
  // SQL wildcards in suspicious contexts
  /(%|_)\s*(LIKE|=)/gi,
  
  // Boolean-based blind SQL injection
  /(\b(TRUE|FALSE)\b.*\b(AND|OR)\b.*\b(TRUE|FALSE)\b)/gi,
  
  // Time-based blind SQL injection
  /(\bIF\s*\(.*,.*SLEEP\(.*\),.*\))/gi,
  
  // UNION-based SQL injection
  /(\bUNION\b.*\bSELECT\b)/gi,
  
  // Error-based SQL injection
  /(\bCONVERT\s*\(.*,.*\))/gi,
  /(\bCAST\s*\(.*AS\s+\w+\))/gi,
  
  // Stacked queries
  /(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))/gi
];

/**
 * XSS patterns that might be used in SQL injection
 */
const XSS_SQL_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi
];

/**
 * Check if string contains SQL injection patterns
 * @param {string} input - Input string to check
 * @returns {Object} Detection result
 */
const detectSQLInjection = (input) => {
  if (typeof input !== 'string') {
    return { detected: false, patterns: [] };
  }

  const detectedPatterns = [];
  
  // Check against SQL injection patterns
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      detectedPatterns.push(pattern.toString());
    }
  }
  
  // Check against XSS patterns that might be used in SQL injection
  for (const pattern of XSS_SQL_PATTERNS) {
    if (pattern.test(input)) {
      detectedPatterns.push(pattern.toString());
    }
  }
  
  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns
  };
};

/**
 * Recursively scan object for SQL injection patterns
 * @param {*} obj - Object to scan
 * @param {string} path - Current path in object
 * @returns {Array} Array of detected issues
 */
const scanObjectForSQLInjection = (obj, path = '') => {
  const issues = [];
  
  if (typeof obj === 'string') {
    const result = detectSQLInjection(obj);
    if (result.detected) {
      issues.push({
        path,
        value: obj,
        patterns: result.patterns
      });
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      const itemPath = path ? `${path}[${index}]` : `[${index}]`;
      issues.push(...scanObjectForSQLInjection(item, itemPath));
    });
  } else if (obj && typeof obj === 'object') {
    Object.keys(obj).forEach(key => {
      const keyPath = path ? `${path}.${key}` : key;
      issues.push(...scanObjectForSQLInjection(obj[key], keyPath));
    });
  }
  
  return issues;
};

/**
 * Sanitize string by removing/escaping dangerous characters
 * @param {string} input - Input string to sanitize
 * @returns {string} Sanitized string
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    // Remove SQL comments
    .replace(/(--|\#|\/\*|\*\/)/g, '')
    // Escape single quotes
    .replace(/'/g, "''")
    // Remove semicolons (to prevent stacked queries)
    .replace(/;/g, '')
    // Remove or escape other dangerous characters
    .replace(/[<>]/g, '')
    .trim();
};

/**
 * Recursively sanitize object
 * @param {*} obj - Object to sanitize
 * @returns {*} Sanitized object
 */
const sanitizeObject = (obj) => {
  if (typeof obj === 'string') {
    return sanitizeInput(obj);
  } else if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  } else if (obj && typeof obj === 'object') {
    const sanitized = {};
    Object.keys(obj).forEach(key => {
      sanitized[key] = sanitizeObject(obj[key]);
    });
    return sanitized;
  }
  
  return obj;
};

/**
 * SQL injection detection middleware
 * @param {Object} options - Middleware options
 * @returns {Function} Express middleware
 */
const sqlInjectionFilter = (options = {}) => {
  const {
    detectOnly = false, // If true, only detect but don't block
    sanitize = false, // If true, sanitize input instead of blocking
    skipPaths = [], // Paths to skip checking
    logOnly = false // If true, only log but don't block
  } = options;
  
  return (req, res, next) => {
    try {
      // Skip certain paths
      if (skipPaths.some(path => req.path.startsWith(path))) {
        return next();
      }
      
      const issues = [];
      
      // Check query parameters
      if (req.query && Object.keys(req.query).length > 0) {
        const queryIssues = scanObjectForSQLInjection(req.query, 'query');
        issues.push(...queryIssues);
      }
      
      // Check request body
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyIssues = scanObjectForSQLInjection(req.body, 'body');
        issues.push(...bodyIssues);
      }
      
      // Check URL parameters
      if (req.params && Object.keys(req.params).length > 0) {
        const paramIssues = scanObjectForSQLInjection(req.params, 'params');
        issues.push(...paramIssues);
      }
      
      // Check headers (specific ones that might contain user input)
      const headersToCheck = ['user-agent', 'referer', 'x-forwarded-for'];
      headersToCheck.forEach(header => {
        if (req.headers[header]) {
          const headerIssues = scanObjectForSQLInjection(req.headers[header], `headers.${header}`);
          issues.push(...headerIssues);
        }
      });
      
      if (issues.length > 0) {
        // Log security event
        loggerUtils.logSecurity('sql_injection_attempt', req.ip, {
          userId: req.user?.id,
          url: req.originalUrl,
          method: req.method,
          userAgent: req.get('User-Agent'),
          issues: issues.map(issue => ({
            path: issue.path,
            patternsCount: issue.patterns.length
          }))
        });
        
        logger.warn('SQL injection attempt detected:', {
          ip: req.ip,
          url: req.originalUrl,
          method: req.method,
          userId: req.user?.id,
          issues: issues
        });
        
        if (logOnly || detectOnly) {
          return next();
        }
        
        if (sanitize) {
          // Sanitize the input
          if (req.query) {
            req.query = sanitizeObject(req.query);
          }
          if (req.body) {
            req.body = sanitizeObject(req.body);
          }
          if (req.params) {
            req.params = sanitizeObject(req.params);
          }
          
          logger.info('Input sanitized due to SQL injection patterns');
          return next();
        }
        
        // Block the request
        return res.status(400).json({
          status: 'error',
          message: 'Invalid input detected',
          error: {
            code: 'INVALID_INPUT',
            details: 'Request contains potentially harmful content'
          }
        });
      }
      
      next();
    } catch (error) {
      logger.error('SQL injection filter error:', error);
      // Continue processing on error to avoid breaking the application
      next();
    }
  };
};

/**
 * Strict SQL injection filter for sensitive endpoints
 */
const strictSQLInjectionFilter = sqlInjectionFilter({
  detectOnly: false,
  sanitize: false,
  logOnly: false
});

/**
 * Logging-only SQL injection filter
 */
const loggingSQLInjectionFilter = sqlInjectionFilter({
  detectOnly: true,
  sanitize: false,
  logOnly: true
});

/**
 * Sanitizing SQL injection filter
 */
const sanitizingSQLInjectionFilter = sqlInjectionFilter({
  detectOnly: false,
  sanitize: true,
  logOnly: false
});

/**
 * Validate specific field for SQL injection
 * @param {string} fieldName - Name of the field
 * @param {boolean} required - Whether field is required
 * @returns {Function} Validation middleware
 */
const validateField = (fieldName, required = false) => {
  return (req, res, next) => {
    const value = req.body[fieldName] || req.query[fieldName] || req.params[fieldName];
    
    if (required && !value) {
      return res.status(400).json({
        status: 'error',
        message: `${fieldName} is required`
      });
    }
    
    if (value) {
      const result = detectSQLInjection(value);
      if (result.detected) {
        loggerUtils.logSecurity('sql_injection_field_validation', req.ip, {
          field: fieldName,
          value: value,
          patterns: result.patterns
        });
        
        return res.status(400).json({
          status: 'error',
          message: `Invalid ${fieldName} format`
        });
      }
    }
    
    next();
  };
};

/**
 * Create custom SQL injection filter with specific patterns
 * @param {Array} customPatterns - Additional patterns to check
 * @param {Object} options - Filter options
 * @returns {Function} Custom filter middleware
 */
const createCustomSQLFilter = (customPatterns = [], options = {}) => {
  const allPatterns = [...SQL_INJECTION_PATTERNS, ...customPatterns];
  
  return (req, res, next) => {
    const issues = [];
    
    const checkWithCustomPatterns = (input) => {
      if (typeof input !== 'string') {
        return { detected: false, patterns: [] };
      }
      
      const detectedPatterns = [];
      for (const pattern of allPatterns) {
        if (pattern.test(input)) {
          detectedPatterns.push(pattern.toString());
        }
      }
      
      return {
        detected: detectedPatterns.length > 0,
        patterns: detectedPatterns
      };
    };
    
    // Use custom detection logic
    const scanWithCustomPatterns = (obj, path = '') => {
      const customIssues = [];
      
      if (typeof obj === 'string') {
        const result = checkWithCustomPatterns(obj);
        if (result.detected) {
          customIssues.push({
            path,
            value: obj,
            patterns: result.patterns
          });
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => {
          const itemPath = path ? `${path}[${index}]` : `[${index}]`;
          customIssues.push(...scanWithCustomPatterns(item, itemPath));
        });
      } else if (obj && typeof obj === 'object') {
        Object.keys(obj).forEach(key => {
          const keyPath = path ? `${path}.${key}` : key;
          customIssues.push(...scanWithCustomPatterns(obj[key], keyPath));
        });
      }
      
      return customIssues;
    };
    
    // Check all request data with custom patterns
    if (req.query) issues.push(...scanWithCustomPatterns(req.query, 'query'));
    if (req.body) issues.push(...scanWithCustomPatterns(req.body, 'body'));
    if (req.params) issues.push(...scanWithCustomPatterns(req.params, 'params'));
    
    if (issues.length > 0) {
      loggerUtils.logSecurity('custom_sql_injection_attempt', req.ip, {
        userId: req.user?.id,
        url: req.originalUrl,
        issues: issues
      });
      
      if (!options.logOnly) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid input detected'
        });
      }
    }
    
    next();
  };
};

module.exports = {
  sqlInjectionFilter,
  strictSQLInjectionFilter,
  loggingSQLInjectionFilter,
  sanitizingSQLInjectionFilter,
  validateField,
  createCustomSQLFilter,
  detectSQLInjection,
  sanitizeInput,
  sanitizeObject
};