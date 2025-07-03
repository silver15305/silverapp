/**
 * SQL Injection Protection Middleware
 * Detects and prevents SQL injection attempts in request data
 */

const { logger, loggerUtils } = require('../config/logger');
const { AppError } = require('../errors/AppError');

/**
 * Enhanced SQL injection patterns with more comprehensive coverage
 */
const SQL_INJECTION_PATTERNS = [
  // Basic SQL injection patterns
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
  
  // SQL comments (various forms)
  /(--|\#|\/\*|\*\/|;--|\s--)/g,
  
  // SQL operators and functions with better detection
  /(\b(OR|AND)\s+[\d'"]\s*[=<>!]+\s*[\d'"])/gi,
  /(\b(OR|AND)\s+['"]\w*['"]?\s*[=<>!]+\s*['"]\w*['"]?)/gi,
  
  // Boolean-based SQL injection (enhanced)
  /(\b(TRUE|FALSE)\b.*\b(AND|OR)\b.*\b(TRUE|FALSE)\b)/gi,
  /(\d+\s*[=<>!]+\s*\d+(\s+(AND|OR)\s+\d+\s*[=<>!]+\s*\d+)*)/gi,
  
  // SQL injection with quotes and escape sequences
  /('|(\\')|(;)|(\\;)|(\\')|(\\")|(%27)|(%22)|(%3B))/g,
  
  // Hex encoding and URL encoding
  /(0x[0-9a-f]+)/gi,
  /(%[0-9a-f]{2}){2,}/gi,
  
  // SQL functions (comprehensive list)
  /(\b(CONCAT|CHAR|ASCII|SUBSTRING|LENGTH|UPPER|LOWER|REPLACE|CAST|CONVERT|COALESCE|ISNULL|NULLIF)\s*\()/gi,
  
  // Database-specific functions
  /(\b(SLEEP|BENCHMARK|WAITFOR|DELAY|PG_SLEEP|DBMS_PIPE\.RECEIVE_MESSAGE)\s*\()/gi,
  
  // Information schema and system tables
  /(\binformation_schema\b)/gi,
  /(\b(sys|mysql|pg_|sqlite_|master|msdb|tempdb)\w*)/gi,
  
  // SQL wildcards in suspicious contexts
  /(%|_)\s*(LIKE|=|IN)/gi,
  
  // Time-based blind SQL injection (enhanced)
  /(\bIF\s*\(.*,.*SLEEP\(.*\),.*\))/gi,
  /(\bWAITFOR\s+DELAY\s+['"][\d:]+['"])/gi,
  
  // UNION-based SQL injection (enhanced)
  /(\bUNION\b.*\bSELECT\b)/gi,
  /(\bUNION\s+ALL\s+SELECT\b)/gi,
  
  // Error-based SQL injection
  /(\bCONVERT\s*\(.*,.*\))/gi,
  /(\bCAST\s*\(.*AS\s+\w+\))/gi,
  
  // Stacked queries
  /(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))/gi,
  
  // Advanced injection techniques
  /(\bLOAD_FILE\s*\()/gi,
  /(\bINTO\s+OUTFILE\b)/gi,
  /(\bINTO\s+DUMPFILE\b)/gi,
  
  // NoSQL injection patterns
  /(\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex)/gi,
  
  // XPath injection
  /(\bor\s+[\d'"]+=[\d'"]+\s+or\s+[\d'"]+=[\d'"]+)/gi,
  
  // LDAP injection
  /(\*\)|\(\||\)\()/g
];

/**
 * XSS patterns that might be used in SQL injection
 */
const XSS_SQL_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
  /<embed\b[^>]*>/gi,
  /expression\s*\(/gi,
  /vbscript:/gi,
  /data:text\/html/gi
];

/**
 * Enhanced detection with context awareness
 * @param {string} input - Input string to check
 * @param {string} context - Context of the input (query, body, header)
 * @returns {Object} Detection result
 */
const detectSQLInjection = (input, context = 'unknown') => {
  if (typeof input !== 'string') {
    return { detected: false, patterns: [], severity: 'none' };
  }

  const detectedPatterns = [];
  let severity = 'none';
  
  // Check against SQL injection patterns
  for (const pattern of SQL_INJECTION_PATTERNS) {
    const matches = input.match(pattern);
    if (matches) {
      detectedPatterns.push({
        pattern: pattern.toString(),
        matches: matches,
        type: 'sql_injection'
      });
      
      // Determine severity based on pattern type
      if (pattern.toString().includes('DROP|DELETE|ALTER')) {
        severity = 'critical';
      } else if (pattern.toString().includes('UNION|SELECT|INSERT')) {
        severity = 'high';
      } else if (severity === 'none') {
        severity = 'medium';
      }
    }
  }
  
  // Check against XSS patterns that might be used in SQL injection
  for (const pattern of XSS_SQL_PATTERNS) {
    const matches = input.match(pattern);
    if (matches) {
      detectedPatterns.push({
        pattern: pattern.toString(),
        matches: matches,
        type: 'xss_sql'
      });
      
      if (severity === 'none') {
        severity = 'medium';
      }
    }
  }
  
  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns,
    severity,
    context
  };
};

/**
 * Recursively scan object for SQL injection patterns
 * @param {*} obj - Object to scan
 * @param {string} path - Current path in object
 * @param {string} context - Context of the scan
 * @returns {Array} Array of detected issues
 */
const scanObjectForSQLInjection = (obj, path = '', context = 'unknown') => {
  const issues = [];
  
  if (typeof obj === 'string') {
    const result = detectSQLInjection(obj, context);
    if (result.detected) {
      issues.push({
        path,
        value: obj.length > 100 ? obj.substring(0, 100) + '...' : obj,
        patterns: result.patterns,
        severity: result.severity,
        context: result.context
      });
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      const itemPath = path ? `${path}[${index}]` : `[${index}]`;
      issues.push(...scanObjectForSQLInjection(item, itemPath, context));
    });
  } else if (obj && typeof obj === 'object') {
    Object.keys(obj).forEach(key => {
      const keyPath = path ? `${path}.${key}` : key;
      issues.push(...scanObjectForSQLInjection(obj[key], keyPath, context));
    });
  }
  
  return issues;
};

/**
 * Enhanced sanitization with multiple layers
 * @param {string} input - Input string to sanitize
 * @returns {string} Sanitized string
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  // Remove SQL comments (multiple forms)
  sanitized = sanitized.replace(/(--|\#|\/\*|\*\/|;--|\s--)/g, '');
  
  // Escape single quotes properly
  sanitized = sanitized.replace(/'/g, "''");
  
  // Remove or neutralize dangerous characters
  sanitized = sanitized.replace(/[<>]/g, '');
  sanitized = sanitized.replace(/;/g, ''); // Remove semicolons to prevent stacked queries
  sanitized = sanitized.replace(/\\/g, ''); // Remove backslashes
  
  // Remove hex encoding attempts
  sanitized = sanitized.replace(/0x[0-9a-f]+/gi, '');
  
  // Remove URL encoding of dangerous characters
  sanitized = sanitized.replace(/%27/gi, ''); // Single quote
  sanitized = sanitized.replace(/%22/gi, ''); // Double quote
  sanitized = sanitized.replace(/%3B/gi, ''); // Semicolon
  sanitized = sanitized.replace(/%2D%2D/gi, ''); // Double dash
  
  // Remove potential XSS vectors
  sanitized = sanitized.replace(/javascript:/gi, '');
  sanitized = sanitized.replace(/vbscript:/gi, '');
  sanitized = sanitized.replace(/on\w+\s*=/gi, '');
  
  // Normalize whitespace
  sanitized = sanitized.replace(/\s+/g, ' ').trim();
  
  return sanitized;
};

/**
 * Recursively sanitize object with enhanced protection
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
      // Also sanitize the key itself
      const sanitizedKey = sanitizeInput(key);
      sanitized[sanitizedKey] = sanitizeObject(obj[key]);
    });
    return sanitized;
  }
  
  return obj;
};

/**
 * Enhanced SQL injection detection middleware
 * @param {Object} options - Middleware options
 * @returns {Function} Express middleware
 */
const sqlInjectionFilter = (options = {}) => {
  const {
    detectOnly = false,
    sanitize = false,
    skipPaths = [],
    logOnly = false,
    blockCritical = true, // Always block critical severity
    allowedSeverity = 'medium' // Block high and critical by default
  } = options;
  
  const severityLevels = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const maxAllowedLevel = severityLevels[allowedSeverity] || 2;
  
  return (req, res, next) => {
    try {
      // Skip certain paths
      if (skipPaths.some(path => req.path.startsWith(path))) {
        return next();
      }
      
      const issues = [];
      
      // Check query parameters
      if (req.query && Object.keys(req.query).length > 0) {
        const queryIssues = scanObjectForSQLInjection(req.query, 'query', 'query');
        issues.push(...queryIssues);
      }
      
      // Check request body
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyIssues = scanObjectForSQLInjection(req.body, 'body', 'body');
        issues.push(...bodyIssues);
      }
      
      // Check URL parameters
      if (req.params && Object.keys(req.params).length > 0) {
        const paramIssues = scanObjectForSQLInjection(req.params, 'params', 'params');
        issues.push(...paramIssues);
      }
      
      // Check specific headers that might contain user input
      const headersToCheck = ['user-agent', 'referer', 'x-forwarded-for', 'x-real-ip'];
      headersToCheck.forEach(header => {
        if (req.headers[header]) {
          const headerIssues = scanObjectForSQLInjection(req.headers[header], `headers.${header}`, 'header');
          issues.push(...headerIssues);
        }
      });
      
      if (issues.length > 0) {
        // Determine the highest severity
        const maxSeverity = Math.max(...issues.map(issue => severityLevels[issue.severity] || 0));
        const shouldBlock = maxSeverity > maxAllowedLevel || (blockCritical && maxSeverity >= severityLevels.critical);
        
        // Enhanced logging with severity and context
        loggerUtils.logSecurity('sql_injection_attempt', req.ip, {
          userId: req.user?.id,
          url: req.originalUrl,
          method: req.method,
          userAgent: req.get('User-Agent'),
          maxSeverity: Object.keys(severityLevels)[maxSeverity],
          issueCount: issues.length,
          issues: issues.map(issue => ({
            path: issue.path,
            severity: issue.severity,
            context: issue.context,
            patternCount: issue.patterns.length
          }))
        });
        
        logger.warn('SQL injection attempt detected:', {
          ip: req.ip,
          url: req.originalUrl,
          method: req.method,
          userId: req.user?.id,
          maxSeverity: Object.keys(severityLevels)[maxSeverity],
          issues: issues.map(issue => ({
            path: issue.path,
            severity: issue.severity,
            context: issue.context,
            valuePreview: issue.value
          }))
        });
        
        if (logOnly || detectOnly) {
          return next();
        }
        
        if (sanitize && !shouldBlock) {
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
          
          logger.info('Input sanitized due to SQL injection patterns', {
            sanitizedPaths: issues.map(i => i.path)
          });
          return next();
        }
        
        if (shouldBlock) {
          // Block the request
          return res.status(400).json({
            status: 'error',
            message: 'Invalid input detected',
            error: {
              code: 'INVALID_INPUT',
              details: 'Request contains potentially harmful content',
              severity: Object.keys(severityLevels)[maxSeverity]
            }
          });
        }
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
  logOnly: false,
  blockCritical: true,
  allowedSeverity: 'low'
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
  logOnly: false,
  allowedSeverity: 'medium'
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
      const result = detectSQLInjection(value, fieldName);
      if (result.detected && result.severity !== 'none') {
        loggerUtils.logSecurity('sql_injection_field_validation', req.ip, {
          field: fieldName,
          value: value.length > 50 ? value.substring(0, 50) + '...' : value,
          severity: result.severity,
          patterns: result.patterns.length
        });
        
        return res.status(400).json({
          status: 'error',
          message: `Invalid ${fieldName} format`,
          error: {
            code: 'INVALID_FIELD',
            field: fieldName,
            severity: result.severity
          }
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
    
    const checkWithCustomPatterns = (input, context) => {
      if (typeof input !== 'string') {
        return { detected: false, patterns: [], severity: 'none' };
      }
      
      const detectedPatterns = [];
      let severity = 'none';
      
      for (const pattern of allPatterns) {
        const matches = input.match(pattern);
        if (matches) {
          detectedPatterns.push({
            pattern: pattern.toString(),
            matches: matches,
            type: customPatterns.includes(pattern) ? 'custom' : 'standard'
          });
          
          if (severity === 'none') {
            severity = 'medium';
          }
        }
      }
      
      return {
        detected: detectedPatterns.length > 0,
        patterns: detectedPatterns,
        severity,
        context
      };
    };
    
    // Use custom detection logic
    const scanWithCustomPatterns = (obj, path = '', context = 'unknown') => {
      const customIssues = [];
      
      if (typeof obj === 'string') {
        const result = checkWithCustomPatterns(obj, context);
        if (result.detected) {
          customIssues.push({
            path,
            value: obj.length > 100 ? obj.substring(0, 100) + '...' : obj,
            patterns: result.patterns,
            severity: result.severity,
            context: result.context
          });
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => {
          const itemPath = path ? `${path}[${index}]` : `[${index}]`;
          customIssues.push(...scanWithCustomPatterns(item, itemPath, context));
        });
      } else if (obj && typeof obj === 'object') {
        Object.keys(obj).forEach(key => {
          const keyPath = path ? `${path}.${key}` : key;
          customIssues.push(...scanWithCustomPatterns(obj[key], keyPath, context));
        });
      }
      
      return customIssues;
    };
    
    // Check all request data with custom patterns
    if (req.query) issues.push(...scanWithCustomPatterns(req.query, 'query', 'query'));
    if (req.body) issues.push(...scanWithCustomPatterns(req.body, 'body', 'body'));
    if (req.params) issues.push(...scanWithCustomPatterns(req.params, 'params', 'params'));
    
    if (issues.length > 0) {
      loggerUtils.logSecurity('custom_sql_injection_attempt', req.ip, {
        userId: req.user?.id,
        url: req.originalUrl,
        issues: issues.map(issue => ({
          path: issue.path,
          severity: issue.severity,
          context: issue.context
        }))
      });
      
      if (!options.logOnly) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid input detected',
          error: {
            code: 'CUSTOM_FILTER_VIOLATION',
            issueCount: issues.length
          }
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