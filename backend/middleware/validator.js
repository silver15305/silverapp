/**
 * Request Validation Middleware
 * Validates request data using Joi schemas and custom validation rules
 */

const Joi = require('joi');
const { ValidationError } = require('../errors/AppError');
const { logger } = require('../config/logger');
const { ValidationManager } = require('../utils/security');

/**
 * Common validation schemas
 */
const commonSchemas = {
  // User ID validation
  userId: Joi.string().uuid().required(),
  
  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    offset: Joi.number().integer().min(0)
  }),
  
  // Phone number
  phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
  
  // Email (optional)
  email: Joi.string().email().optional().allow('', null),
  
  // Username
  username: Joi.string().alphanum().min(3).max(50).required(),
  
  // Password
  password: Joi.string().min(8).max(128).required(),
  
  // Verification code
  verificationCode: Joi.string().pattern(/^\d{6}$/).required(),
  
  // Names
  firstName: Joi.string().min(1).max(50).required(),
  lastName: Joi.string().min(1).max(50).required(),
  
  // Date of birth
  dateOfBirth: Joi.date().max('now').optional(),
  
  // Gender
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  
  // Bio
  bio: Joi.string().max(500).optional().allow(''),
  
  // Location
  location: Joi.string().max(100).optional().allow(''),
  
  // Website
  website: Joi.string().uri().optional().allow('', null),
  
  // Post content
  postContent: Joi.string().max(5000).optional().allow(''),
  
  // Media URLs
  mediaUrls: Joi.array().items(Joi.string().uri()).max(10).optional(),
  
  // Privacy settings
  privacy: Joi.string().valid('public', 'friends', 'private').default('public'),
  
  // Message content
  messageContent: Joi.string().max(2000).required(),
  
  // Message type
  messageType: Joi.string().valid('text', 'image', 'video', 'audio', 'file', 'location', 'contact', 'sticker', 'gif').default('text')
};

/**
 * Authentication validation schemas
 */
const authSchemas = {
  register: Joi.object({
    username: commonSchemas.username,
    phone_number: commonSchemas.phoneNumber,
    email: commonSchemas.email,
    password: commonSchemas.password,
    first_name: commonSchemas.firstName,
    last_name: commonSchemas.lastName,
    date_of_birth: commonSchemas.dateOfBirth,
    gender: commonSchemas.gender
  }),
  
  login: Joi.object({
    identifier: Joi.string().required(), // username or phone number
    password: commonSchemas.password
  }),
  
  loginWithOTP: Joi.object({
    phone_number: commonSchemas.phoneNumber,
    verification_code: commonSchemas.verificationCode
  }),
  
  verifyPhone: Joi.object({
    phone_number: commonSchemas.phoneNumber,
    verification_code: commonSchemas.verificationCode
  }),
  
  sendVerificationCode: Joi.object({
    phone_number: commonSchemas.phoneNumber
  }),
  
  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),
  
  forgotPassword: Joi.object({
    phone_number: commonSchemas.phoneNumber
  }),
  
  resetPassword: Joi.object({
    phone_number: commonSchemas.phoneNumber,
    verification_code: commonSchemas.verificationCode,
    new_password: commonSchemas.password
  }),
  
  changePassword: Joi.object({
    current_password: commonSchemas.password,
    new_password: commonSchemas.password
  })
};

/**
 * User validation schemas
 */
const userSchemas = {
  updateProfile: Joi.object({
    first_name: commonSchemas.firstName.optional(),
    last_name: commonSchemas.lastName.optional(),
    bio: commonSchemas.bio,
    location: commonSchemas.location,
    website: commonSchemas.website,
    date_of_birth: commonSchemas.dateOfBirth,
    gender: commonSchemas.gender,
    is_private: Joi.boolean().optional()
  }),
  
  updateProfilePicture: Joi.object({
    profile_picture: Joi.string().uri().required()
  }),
  
  updateCoverPicture: Joi.object({
    cover_picture: Joi.string().uri().required()
  }),
  
  searchUsers: Joi.object({
    query: Joi.string().min(1).max(100).required(),
    ...commonSchemas.pagination
  })
};

/**
 * Post validation schemas
 */
const postSchemas = {
  createPost: Joi.object({
    content: commonSchemas.postContent,
    media_urls: commonSchemas.mediaUrls,
    privacy: commonSchemas.privacy,
    location: commonSchemas.location,
    tagged_users: Joi.array().items(commonSchemas.userId).max(20).optional()
  }).or('content', 'media_urls'), // At least one of content or media_urls is required
  
  updatePost: Joi.object({
    content: commonSchemas.postContent,
    media_urls: commonSchemas.mediaUrls,
    privacy: commonSchemas.privacy,
    location: commonSchemas.location,
    tagged_users: Joi.array().items(commonSchemas.userId).max(20).optional()
  }),
  
  createComment: Joi.object({
    content: Joi.string().min(1).max(1000).required(),
    media_urls: Joi.array().items(Joi.string().uri()).max(5).optional()
  }),
  
  getFeed: Joi.object({
    ...commonSchemas.pagination
  }),
  
  getUserPosts: Joi.object({
    userId: commonSchemas.userId,
    ...commonSchemas.pagination
  }),
  
  searchPosts: Joi.object({
    query: Joi.string().min(1).max(100).required(),
    ...commonSchemas.pagination
  })
};

/**
 * Message validation schemas
 */
const messageSchemas = {
  sendMessage: Joi.object({
    receiver_id: commonSchemas.userId,
    content: commonSchemas.messageContent.optional(),
    message_type: commonSchemas.messageType,
    media_url: Joi.string().uri().optional(),
    reply_to_id: commonSchemas.userId.optional(),
    location_data: Joi.object().optional(),
    contact_data: Joi.object().optional()
  }).or('content', 'media_url'), // At least one of content or media_url is required
  
  getConversation: Joi.object({
    conversationId: Joi.string().required(),
    ...commonSchemas.pagination
  }),
  
  getConversations: Joi.object({
    ...commonSchemas.pagination
  }),
  
  markAsRead: Joi.object({
    messageId: commonSchemas.userId
  }),
  
  deleteMessage: Joi.object({
    messageId: commonSchemas.userId
  }),
  
  searchMessages: Joi.object({
    query: Joi.string().min(1).max(100).required(),
    ...commonSchemas.pagination
  })
};

/**
 * Friend validation schemas
 */
const friendSchemas = {
  sendFriendRequest: Joi.object({
    friend_id: commonSchemas.userId
  }),
  
  respondToFriendRequest: Joi.object({
    friend_id: commonSchemas.userId,
    action: Joi.string().valid('accept', 'decline', 'block').required()
  }),
  
  getFriends: Joi.object({
    userId: commonSchemas.userId.optional(),
    ...commonSchemas.pagination
  }),
  
  getFriendRequests: Joi.object({
    type: Joi.string().valid('received', 'sent').default('received'),
    ...commonSchemas.pagination
  }),
  
  removeFriend: Joi.object({
    friend_id: commonSchemas.userId
  }),
  
  blockUser: Joi.object({
    user_id: commonSchemas.userId
  }),
  
  unblockUser: Joi.object({
    user_id: commonSchemas.userId
  })
};

/**
 * Notification validation schemas
 */
const notificationSchemas = {
  getNotifications: Joi.object({
    category: Joi.string().valid('social', 'system', 'promotional', 'security').optional(),
    ...commonSchemas.pagination
  }),
  
  markAsRead: Joi.object({
    notificationId: commonSchemas.userId
  }),
  
  markAllAsRead: Joi.object({
    category: Joi.string().valid('social', 'system', 'promotional', 'security').optional()
  }),
  
  deleteNotification: Joi.object({
    notificationId: commonSchemas.userId
  })
};

/**
 * Create validation middleware
 * @param {Object} schema - Joi validation schema
 * @param {string} source - Source of data to validate ('body', 'query', 'params')
 * @returns {Function} Express middleware
 */
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    try {
      const dataToValidate = req[source];
      
      const { error, value } = schema.validate(dataToValidate, {
        abortEarly: false, // Return all validation errors
        stripUnknown: true, // Remove unknown fields
        convert: true // Convert types when possible
      });
      
      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }));
        
        logger.warn('Validation failed:', {
          url: req.originalUrl,
          method: req.method,
          source,
          errors: validationErrors
        });
        
        return next(new ValidationError(`Validation failed: ${validationErrors.map(e => e.message).join(', ')}`));
      }
      
      // Replace the original data with validated and sanitized data
      req[source] = value;
      next();
    } catch (err) {
      logger.error('Validation middleware error:', err);
      return next(new ValidationError('Validation failed'));
    }
  };
};

/**
 * Custom validation functions
 */
const customValidations = {
  /**
   * Validate username availability
   */
  validateUsernameAvailability: async (req, res, next) => {
    try {
      const { username } = req.body;
      
      if (!username) {
        return next();
      }
      
      const validation = ValidationManager.validateUsername(username);
      if (!validation.isValid) {
        return next(new ValidationError(`Username validation failed: ${validation.errors.join(', ')}`));
      }
      
      // Check if username is already taken
      const User = require('../models/User');
      const existingUser = await User.findOne({ where: { username: validation.sanitized } });
      
      if (existingUser) {
        return next(new ValidationError('Username is already taken'));
      }
      
      // Update request with sanitized username
      req.body.username = validation.sanitized;
      next();
    } catch (error) {
      logger.error('Username validation error:', error);
      return next(new ValidationError('Username validation failed'));
    }
  },
  
  /**
   * Validate phone number availability
   */
  validatePhoneAvailability: async (req, res, next) => {
    try {
      const { phone_number } = req.body;
      
      if (!phone_number) {
        return next();
      }
      
      const validation = ValidationManager.validatePhoneNumber(phone_number);
      if (!validation.isValid) {
        return next(new ValidationError(`Phone number validation failed: ${validation.errors.join(', ')}`));
      }
      
      // Check if phone number is already registered
      const User = require('../models/User');
      const existingUser = await User.findOne({ where: { phone_number: validation.sanitized } });
      
      if (existingUser && req.route.path !== '/verify-phone') {
        return next(new ValidationError('Phone number is already registered'));
      }
      
      // Update request with sanitized phone number
      req.body.phone_number = validation.sanitized;
      next();
    } catch (error) {
      logger.error('Phone validation error:', error);
      return next(new ValidationError('Phone validation failed'));
    }
  },
  
  /**
   * Validate email availability
   */
  validateEmailAvailability: async (req, res, next) => {
    try {
      const { email } = req.body;
      
      if (!email) {
        return next(); // Email is optional
      }
      
      const validation = ValidationManager.validateEmail(email);
      if (!validation.isValid) {
        return next(new ValidationError(`Email validation failed: ${validation.errors.join(', ')}`));
      }
      
      // Check if email is already registered
      const User = require('../models/User');
      const existingUser = await User.findOne({ where: { email: validation.sanitized } });
      
      if (existingUser) {
        return next(new ValidationError('Email is already registered'));
      }
      
      // Update request with sanitized email
      req.body.email = validation.sanitized;
      next();
    } catch (error) {
      logger.error('Email validation error:', error);
      return next(new ValidationError('Email validation failed'));
    }
  },
  
  /**
   * Validate password strength
   */
  validatePasswordStrength: (req, res, next) => {
    try {
      const { password, new_password } = req.body;
      const passwordToValidate = new_password || password;
      
      if (!passwordToValidate) {
        return next();
      }
      
      const validation = ValidationManager.validatePassword(passwordToValidate);
      if (!validation.isValid) {
        return next(new ValidationError(`Password validation failed: ${validation.errors.join(', ')}`));
      }
      
      if (validation.strength === 'weak') {
        return next(new ValidationError('Password is too weak. Please choose a stronger password.'));
      }
      
      next();
    } catch (error) {
      logger.error('Password strength validation error:', error);
      return next(new ValidationError('Password validation failed'));
    }
  },
  
  /**
   * Validate file upload
   */
  validateFileUpload: (allowedTypes = ['image/jpeg', 'image/png', 'image/gif'], maxSize = 10 * 1024 * 1024) => {
    return (req, res, next) => {
      try {
        if (!req.file && !req.files) {
          return next();
        }
        
        const files = req.files || [req.file];
        
        for (const file of files) {
          if (!allowedTypes.includes(file.mimetype)) {
            return next(new ValidationError(`File type ${file.mimetype} is not allowed`));
          }
          
          if (file.size > maxSize) {
            return next(new ValidationError(`File size exceeds maximum allowed size of ${maxSize} bytes`));
          }
        }
        
        next();
      } catch (error) {
        logger.error('File upload validation error:', error);
        return next(new ValidationError('File validation failed'));
      }
    };
  }
};

/**
 * Combine multiple validation middlewares
 * @param {...Function} validators - Validation middlewares to combine
 * @returns {Array} Array of validation middlewares
 */
const combineValidations = (...validators) => {
  return validators;
};

/**
 * Create conditional validation
 * @param {Function} condition - Condition function
 * @param {Function} validator - Validator to apply if condition is true
 * @returns {Function} Conditional validation middleware
 */
const conditionalValidation = (condition, validator) => {
  return (req, res, next) => {
    if (condition(req)) {
      return validator(req, res, next);
    }
    next();
  };
};

module.exports = {
  validate,
  commonSchemas,
  authSchemas,
  userSchemas,
  postSchemas,
  messageSchemas,
  friendSchemas,
  notificationSchemas,
  customValidations,
  combineValidations,
  conditionalValidation
};