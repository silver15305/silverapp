/**
 * Async Handler Utility
 * Wraps async functions to catch errors and pass them to error handling middleware
 */

/**
 * Wraps async route handlers to catch errors
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Express middleware function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Wraps async functions with try-catch
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Wrapped function
 */
const catchAsync = (fn) => {
  return async (...args) => {
    try {
      return await fn(...args);
    } catch (error) {
      throw error;
    }
  };
};

/**
 * Creates a promise that resolves after specified delay
 * @param {number} ms - Milliseconds to delay
 * @returns {Promise} Promise that resolves after delay
 */
const delay = (ms) => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

/**
 * Retry async function with exponential backoff
 * @param {Function} fn - Async function to retry
 * @param {number} maxRetries - Maximum number of retries
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise} Promise that resolves with function result
 */
const retryWithBackoff = async (fn, maxRetries = 3, baseDelay = 1000) => {
  let lastError;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt === maxRetries) {
        throw lastError;
      }
      
      const delayTime = baseDelay * Math.pow(2, attempt);
      await delay(delayTime);
    }
  }
};

/**
 * Execute multiple async functions in parallel with error handling
 * @param {Array} functions - Array of async functions
 * @returns {Promise} Promise that resolves with array of results
 */
const parallelAsync = async (functions) => {
  const results = await Promise.allSettled(functions.map(fn => fn()));
  
  const errors = results
    .filter(result => result.status === 'rejected')
    .map(result => result.reason);
  
  if (errors.length > 0) {
    throw new Error(`${errors.length} operations failed: ${errors.map(e => e.message).join(', ')}`);
  }
  
  return results.map(result => result.value);
};

/**
 * Execute async functions in sequence
 * @param {Array} functions - Array of async functions
 * @returns {Promise} Promise that resolves with array of results
 */
const sequentialAsync = async (functions) => {
  const results = [];
  
  for (const fn of functions) {
    const result = await fn();
    results.push(result);
  }
  
  return results;
};

/**
 * Timeout wrapper for async functions
 * @param {Function} fn - Async function to wrap
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise} Promise that resolves with function result or rejects on timeout
 */
const withTimeout = (fn, timeoutMs) => {
  return Promise.race([
    fn(),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Operation timed out')), timeoutMs)
    )
  ]);
};

module.exports = {
  asyncHandler,
  catchAsync,
  delay,
  retryWithBackoff,
  parallelAsync,
  sequentialAsync,
  withTimeout
};