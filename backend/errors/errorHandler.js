/**
 * Global Error Handler Middleware
 * Handles all errors in the application with proper logging and response formatting
 */

const { logger } = require('../config/logger');
const { AppError } = require('./AppError');
const config = require('../config/env');

/**
 * Handle Sequelize validation errors
 * @param {Error} err - Sequelize validation error
 * @returns {AppError} Formatted application error
 */
const handleSequelizeValidationError = (err) => {
  const errors = err.errors.map(error => ({
    field: error.path,
    message: error.message,
    value: error.value
  }));
  
  const message = `Validation failed: ${errors.map(e => e.message).join(', ')}`;
  return new AppError(message, 400);
};

/**
 * Handle Sequelize unique constraint errors
 * @param {Error} err - Sequelize unique constraint error
 * @returns {AppError} Formatted application error
 */
const handleSequelizeUniqueConstraintError = (err) => {
  const field = err.errors[0].path;
  const value = err.errors[0].value;
  const message = `${field} '${value}' already exists`;
  return new AppError(message, 409);
};

/**
 * Handle Sequelize foreign key constraint errors
 * @param {Error} err - Sequelize foreign key constraint error
 * @returns {AppError} Formatted application error
 */
const handleSequelizeForeignKeyConstraintError = (err) => {
  const message = 'Invalid reference to related resource';
  return new AppError(message, 400);
};

/**
 * Handle JWT errors
 * @param {Error} err - JWT error
 * @returns {AppError} Formatted application error
 */
const handleJWTError = (err) => {
  if (err.name === 'JsonWebTokenError') {
    return new AppError('Invalid token', 401);
  }
  if (err.name === 'TokenExpiredError') {
    return new AppError('Token expired', 401);
  }
  return new AppError('Authentication failed', 401);
};

/**
 * Handle Multer errors (file upload)
 * @param {Error} err - Multer error
 * @returns {AppError} Formatted application error
 */
const handleMulterError = (err) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return new AppError('File too large', 400);
  }
  if (err.code === 'LIMIT_FILE_COUNT') {
    return new AppError('Too many files', 400);
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return new AppError('Unexpected file field', 400);
  }
  return new AppError('File upload error', 400);
};

/**
 * Send error response in development
 * @param {Error} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString()
  });
};

/**
 * Send error response in production
 * @param {Error} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      timestamp: new Date().toISOString()
    });
  } else {
    // Programming or other unknown error: don't leak error details
    logger.error('ERROR:', err);
    
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong!',
      timestamp: new Date().toISOString()
    });
  }
};

/**
 * Global error handling middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  
  // Log the error
  logger.error('Global Error Handler:', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id || 'anonymous',
    timestamp: new Date().toISOString()
  });
  
  if (config.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;
    
    // Handle specific error types
    if (err.name === 'SequelizeValidationError') {
      error = handleSequelizeValidationError(error);
    } else if (err.name === 'SequelizeUniqueConstraintError') {
      error = handleSequelizeUniqueConstraintError(error);
    } else if (err.name === 'SequelizeForeignKeyConstraintError') {
      error = handleSequelizeForeignKeyConstraintError(error);
    } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      error = handleJWTError(error);
    } else if (err.name === 'MulterError') {
      error = handleMulterError(error);
    }
    
    sendErrorProd(error, res);
  }
};

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Promise Rejection:', {
    error: err.message,
    stack: err.stack,
    promise: promise
  });
  
  // Close server & exit process
  process.exit(1);
});

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', {
    error: err.message,
    stack: err.stack
  });
  
  // Close server & exit process
  process.exit(1);
});

module.exports = globalErrorHandler;