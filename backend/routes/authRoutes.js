/**
 * Authentication Routes
 * Defines all authentication-related API endpoints
 */

const express = require('express');
const {
  register,
  login,
  loginWithOTP,
  sendLoginCode,
  verifyPhone,
  sendVerificationCode,
  refreshToken,
  forgotPassword,
  resetPassword,
  changePassword,
  getMe,
  logout,
  logoutAll
} = require('../controllers/authController');

const { authenticate, authRateLimit, validateRefreshToken } = require('../middleware/auth');
const { validate, authSchemas, customValidations } = require('../middleware/validator');
const { strictSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');

const router = express.Router();

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register new user
 * @access  Public
 */
router.post('/register',
  authRateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.register),
  customValidations.validateUsernameAvailability,
  customValidations.validatePhoneAvailability,
  customValidations.validateEmailAvailability,
  customValidations.validatePasswordStrength,
  register
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login with username/phone and password
 * @access  Public
 */
router.post('/login',
  authRateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.login),
  login
);

/**
 * @route   POST /api/v1/auth/login-otp
 * @desc    Login with phone number and OTP
 * @access  Public
 */
router.post('/login-otp',
  authRateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.loginWithOTP),
  loginWithOTP
);

/**
 * @route   POST /api/v1/auth/send-login-code
 * @desc    Send login code to phone number
 * @access  Public
 */
router.post('/send-login-code',
  authRateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
  strictSQLInjectionFilter,
  validate(authSchemas.sendVerificationCode),
  sendLoginCode
);

/**
 * @route   POST /api/v1/auth/verify-phone
 * @desc    Verify phone number with code
 * @access  Public
 */
router.post('/verify-phone',
  authRateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.verifyPhone),
  verifyPhone
);

/**
 * @route   POST /api/v1/auth/send-verification-code
 * @desc    Send verification code to phone number
 * @access  Public
 */
router.post('/send-verification-code',
  authRateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
  strictSQLInjectionFilter,
  validate(authSchemas.sendVerificationCode),
  sendVerificationCode
);

/**
 * @route   POST /api/v1/auth/refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh-token',
  authRateLimit(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.refreshToken),
  validateRefreshToken,
  refreshToken
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Send password reset code
 * @access  Public
 */
router.post('/forgot-password',
  authRateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
  strictSQLInjectionFilter,
  validate(authSchemas.forgotPassword),
  forgotPassword
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password with verification code
 * @access  Public
 */
router.post('/reset-password',
  authRateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  strictSQLInjectionFilter,
  validate(authSchemas.resetPassword),
  customValidations.validatePasswordStrength,
  resetPassword
);

/**
 * @route   POST /api/v1/auth/change-password
 * @desc    Change password (authenticated user)
 * @access  Private
 */
router.post('/change-password',
  authenticate,
  authRateLimit(5, 60 * 60 * 1000), // 5 attempts per hour
  strictSQLInjectionFilter,
  validate(authSchemas.changePassword),
  customValidations.validatePasswordStrength,
  changePassword
);

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me',
  authenticate,
  getMe
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout',
  authenticate,
  logout
);

/**
 * @route   POST /api/v1/auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all',
  authenticate,
  logoutAll
);

module.exports = router;