/**
 * Authentication Controller
 * Handles user registration, login, verification, and password management
 */

const bcrypt = require('bcryptjs');
const { asyncHandler } = require('../utils/asyncHandler');
const { AppError, ValidationError, AuthenticationError } = require('../errors/AppError');
const { TokenManager } = require('../utils/security');
const { generateNumericCode, removeSensitiveFields } = require('../utils/helpers');
const { logger, loggerUtils } = require('../config/logger');
const smsService = require('../services/sms');
const redisService = require('../services/redis');
const User = require('../models/User');
const config = require('../config/env');

/**
 * Register new user
 * @route POST /api/v1/auth/register
 */
const register = asyncHandler(async (req, res, next) => {
  const {
    username,
    phone_number,
    email,
    password,
    first_name,
    last_name,
    date_of_birth,
    gender
  } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({
    where: {
      [User.sequelize.Sequelize.Op.or]: [
        { username },
        { phone_number },
        ...(email ? [{ email }] : [])
      ]
    }
  });

  if (existingUser) {
    if (existingUser.username === username) {
      return next(new ValidationError('Username is already taken'));
    }
    if (existingUser.phone_number === phone_number) {
      return next(new ValidationError('Phone number is already registered'));
    }
    if (email && existingUser.email === email) {
      return next(new ValidationError('Email is already registered'));
    }
  }

  // Create new user
  const user = await User.create({
    username,
    phone_number,
    email,
    password_hash: password, // Will be hashed by model hook
    first_name,
    last_name,
    date_of_birth,
    gender
  });

  // Generate verification code
  const verificationCode = user.generateVerificationCode();
  await user.save();

  // Send verification SMS
  const smsResult = await smsService.sendVerificationCode(phone_number, verificationCode);
  
  if (!smsResult.success) {
    logger.error('Failed to send verification SMS:', smsResult.error);
    // Don't fail registration if SMS fails, user can request new code
  }

  // Log registration event
  loggerUtils.logAuth('register', user.id, req.ip, {
    username,
    phone_number,
    smsResult: smsResult.success
  });

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully. Please verify your phone number.',
    data: {
      user: removeSensitiveFields(user.toJSON()),
      verification_required: true
    }
  });
});

/**
 * Login with username/phone and password
 * @route POST /api/v1/auth/login
 */
const login = asyncHandler(async (req, res, next) => {
  const { identifier, password } = req.body;

  // Find user by username or phone number
  const user = await User.findByIdentifier(identifier);
  
  if (!user || !(await user.comparePassword(password))) {
    loggerUtils.logSecurity('failed_login_attempt', req.ip, {
      identifier,
      reason: 'invalid_credentials'
    });
    return next(new AuthenticationError('Invalid credentials'));
  }

  // Check if user is active
  if (!user.is_active) {
    return next(new AuthenticationError('Account is deactivated'));
  }

  // Check if phone is verified
  if (!user.phone_verified) {
    return next(new AuthenticationError('Phone number not verified. Please verify your phone number first.'));
  }

  // Generate tokens
  const tokenPayload = { userId: user.id, username: user.username };
  const tokens = TokenManager.generateTokenPair(tokenPayload);

  // Store refresh token
  user.refresh_token = tokens.refreshToken;
  user.refresh_token_expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  await user.updateLastLogin();

  // Log successful login
  loggerUtils.logAuth('login', user.id, req.ip, {
    method: 'password',
    userAgent: req.get('User-Agent')
  });

  res.status(200).json({
    status: 'success',
    message: 'Login successful',
    data: {
      user: removeSensitiveFields(user.toJSON()),
      tokens
    }
  });
});

/**
 * Login with phone number and OTP
 * @route POST /api/v1/auth/login-otp
 */
const loginWithOTP = asyncHandler(async (req, res, next) => {
  const { phone_number, verification_code } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Check if user is active
  if (!user.is_active) {
    return next(new AuthenticationError('Account is deactivated'));
  }

  // Verify OTP
  if (!user.verifyCode(verification_code)) {
    loggerUtils.logSecurity('failed_otp_login', req.ip, {
      phone_number,
      reason: 'invalid_code'
    });
    return next(new AuthenticationError('Invalid or expired verification code'));
  }

  // Clear verification code
  user.clearVerificationCode();
  
  // Mark phone as verified if not already
  if (!user.phone_verified) {
    user.phone_verified = true;
  }

  // Generate tokens
  const tokenPayload = { userId: user.id, username: user.username };
  const tokens = TokenManager.generateTokenPair(tokenPayload);

  // Store refresh token
  user.refresh_token = tokens.refreshToken;
  user.refresh_token_expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  await user.updateLastLogin();

  // Log successful login
  loggerUtils.logAuth('login_otp', user.id, req.ip, {
    method: 'otp',
    userAgent: req.get('User-Agent')
  });

  res.status(200).json({
    status: 'success',
    message: 'Login successful',
    data: {
      user: removeSensitiveFields(user.toJSON()),
      tokens
    }
  });
});

/**
 * Send verification code for login
 * @route POST /api/v1/auth/send-login-code
 */
const sendLoginCode = asyncHandler(async (req, res, next) => {
  const { phone_number } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Check if user is active
  if (!user.is_active) {
    return next(new AuthenticationError('Account is deactivated'));
  }

  // Generate verification code
  const verificationCode = user.generateVerificationCode();
  await user.save();

  // Send login code SMS
  const smsResult = await smsService.sendLoginCode(phone_number, verificationCode);
  
  if (!smsResult.success) {
    logger.error('Failed to send login code SMS:', smsResult.error);
    return next(new AppError('Failed to send verification code', 500));
  }

  // Log code sent event
  loggerUtils.logAuth('login_code_sent', user.id, req.ip, {
    phone_number
  });

  res.status(200).json({
    status: 'success',
    message: 'Login code sent successfully'
  });
});

/**
 * Verify phone number
 * @route POST /api/v1/auth/verify-phone
 */
const verifyPhone = asyncHandler(async (req, res, next) => {
  const { phone_number, verification_code } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Verify code
  if (!user.verifyCode(verification_code)) {
    loggerUtils.logSecurity('failed_phone_verification', req.ip, {
      phone_number,
      reason: 'invalid_code'
    });
    return next(new AuthenticationError('Invalid or expired verification code'));
  }

  // Mark phone as verified
  user.phone_verified = true;
  user.clearVerificationCode();
  await user.save();

  // Log verification event
  loggerUtils.logAuth('phone_verified', user.id, req.ip, {
    phone_number
  });

  res.status(200).json({
    status: 'success',
    message: 'Phone number verified successfully',
    data: {
      user: removeSensitiveFields(user.toJSON())
    }
  });
});

/**
 * Send verification code
 * @route POST /api/v1/auth/send-verification-code
 */
const sendVerificationCode = asyncHandler(async (req, res, next) => {
  const { phone_number } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Generate verification code
  const verificationCode = user.generateVerificationCode();
  await user.save();

  // Send verification SMS
  const smsResult = await smsService.sendVerificationCode(phone_number, verificationCode);
  
  if (!smsResult.success) {
    logger.error('Failed to send verification SMS:', smsResult.error);
    return next(new AppError('Failed to send verification code', 500));
  }

  // Log code sent event
  loggerUtils.logAuth('verification_code_sent', user.id, req.ip, {
    phone_number
  });

  res.status(200).json({
    status: 'success',
    message: 'Verification code sent successfully'
  });
});

/**
 * Refresh access token
 * @route POST /api/v1/auth/refresh-token
 */
const refreshToken = asyncHandler(async (req, res, next) => {
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

  // Find user
  const user = await User.findByPk(decoded.userId);
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Check if stored refresh token matches
  if (user.refresh_token !== refreshToken) {
    return next(new AuthenticationError('Invalid refresh token'));
  }

  // Check if refresh token is expired
  if (user.refresh_token_expires && new Date() > user.refresh_token_expires) {
    return next(new AuthenticationError('Refresh token expired'));
  }

  // Generate new tokens
  const tokenPayload = { userId: user.id, username: user.username };
  const tokens = TokenManager.generateTokenPair(tokenPayload);

  // Update stored refresh token
  user.refresh_token = tokens.refreshToken;
  user.refresh_token_expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  await user.save();

  // Log token refresh
  loggerUtils.logAuth('token_refresh', user.id, req.ip);

  res.status(200).json({
    status: 'success',
    message: 'Token refreshed successfully',
    data: {
      tokens
    }
  });
});

/**
 * Forgot password - send reset code
 * @route POST /api/v1/auth/forgot-password
 */
const forgotPassword = asyncHandler(async (req, res, next) => {
  const { phone_number } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    // Don't reveal if user exists or not
    return res.status(200).json({
      status: 'success',
      message: 'If the phone number is registered, a reset code will be sent'
    });
  }

  // Generate verification code for password reset
  const verificationCode = user.generateVerificationCode();
  await user.save();

  // Send password reset SMS
  const smsResult = await smsService.sendPasswordResetCode(phone_number, verificationCode);
  
  if (!smsResult.success) {
    logger.error('Failed to send password reset SMS:', smsResult.error);
  }

  // Log password reset request
  loggerUtils.logAuth('password_reset_requested', user.id, req.ip, {
    phone_number
  });

  res.status(200).json({
    status: 'success',
    message: 'If the phone number is registered, a reset code will be sent'
  });
});

/**
 * Reset password with verification code
 * @route POST /api/v1/auth/reset-password
 */
const resetPassword = asyncHandler(async (req, res, next) => {
  const { phone_number, verification_code, new_password } = req.body;

  // Find user by phone number
  const user = await User.findByPhoneNumber(phone_number);
  
  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Verify code
  if (!user.verifyCode(verification_code)) {
    loggerUtils.logSecurity('failed_password_reset', req.ip, {
      phone_number,
      reason: 'invalid_code'
    });
    return next(new AuthenticationError('Invalid or expired verification code'));
  }

  // Update password
  user.password_hash = new_password; // Will be hashed by model hook
  user.clearVerificationCode();
  
  // Invalidate all existing refresh tokens
  user.refresh_token = null;
  user.refresh_token_expires = null;
  
  await user.save();

  // Log password reset
  loggerUtils.logAuth('password_reset', user.id, req.ip, {
    phone_number
  });

  res.status(200).json({
    status: 'success',
    message: 'Password reset successfully'
  });
});

/**
 * Change password (authenticated user)
 * @route POST /api/v1/auth/change-password
 */
const changePassword = asyncHandler(async (req, res, next) => {
  const { current_password, new_password } = req.body;
  const user = req.user;

  // Verify current password
  if (!(await user.comparePassword(current_password))) {
    return next(new AuthenticationError('Current password is incorrect'));
  }

  // Update password
  user.password_hash = new_password; // Will be hashed by model hook
  
  // Invalidate all existing refresh tokens except current one
  // This forces re-login on other devices
  await user.save();

  // Log password change
  loggerUtils.logAuth('password_changed', user.id, req.ip);

  res.status(200).json({
    status: 'success',
    message: 'Password changed successfully'
  });
});

/**
 * Get current user profile
 * @route GET /api/v1/auth/me
 */
const getMe = asyncHandler(async (req, res, next) => {
  const user = req.user;

  res.status(200).json({
    status: 'success',
	message: 'User profile retrieved successfully',
    data: {
      user: removeSensitiveFields(user.toJSON())
    }
  });
});

/**
 * Logout user
 * @route POST /api/v1/auth/logout
 */
const logout = asyncHandler(async (req, res, next) => {
  const user = req.user;
  const token = req.token;

  // Blacklist current access token
  if (token) {
    const decoded = TokenManager.decodeToken(token);
    if (decoded && decoded.payload.exp) {
      const ttl = decoded.payload.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0 && redisService.isReady()) {
        await redisService.set(`blacklisted_token:${token}`, 'blacklisted', ttl);
      }
    }
  }

  // Clear refresh token
  user.refresh_token = null;
  user.refresh_token_expires = null;
  await user.save();

  // Log logout
  loggerUtils.logAuth('logout', user.id, req.ip);

  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});

/**
 * Logout from all devices
 * @route POST /api/v1/auth/logout-all
 */
const logoutAll = asyncHandler(async (req, res, next) => {
  const user = req.user;

  // Clear all refresh tokens
  user.refresh_token = null;
  user.refresh_token_expires = null;
  await user.save();

  // Log logout all
  loggerUtils.logAuth('logout_all', user.id, req.ip);

  res.status(200).json({
    status: 'success',
    message: 'Logged out from all devices successfully'
  });
});

module.exports = {
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
};