/**
 * Push Notification Routes
 * Defines push notification management API endpoints
 */

const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validate } = require('../middleware/validator');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');
const pushService = require('../services/push');
const { logger } = require('../config/logger');
const { AppError } = require('../errors/AppError');
const Joi = require('joi');

const router = express.Router();

// Push notification validation schemas
const pushSchemas = {
  registerToken: Joi.object({
    token: Joi.string().required(),
    provider: Joi.string().valid('xiaomi', 'huawei', 'oppo', 'vivo', 'apns').required(),
    deviceId: Joi.string().required(),
    deviceInfo: Joi.object({
      platform: Joi.string().valid('android', 'ios').required(),
      model: Joi.string().optional(),
      version: Joi.string().optional(),
      appVersion: Joi.string().optional()
    }).optional()
  }),

  removeToken: Joi.object({
    deviceId: Joi.string().required()
  }),

  sendNotification: Joi.object({
    userId: Joi.string().required(),
    title: Joi.string().min(1).max(100).required(),
    body: Joi.string().min(1).max(500).required(),
    data: Joi.object().optional(),
    badge: Joi.number().integer().min(0).optional(),
    sound: Joi.string().optional()
  }),

  testNotification: Joi.object({
    token: Joi.string().required(),
    provider: Joi.string().valid('xiaomi', 'huawei', 'oppo', 'vivo', 'apns').required()
  })
};

/**
 * @route   POST /api/v1/push/register-token
 * @desc    Register device token for push notifications
 * @access  Private
 */
router.post('/register-token',
  authenticate,
  loggingSQLInjectionFilter,
  validate(pushSchemas.registerToken),
  async (req, res, next) => {
    try {
      const { token, provider, deviceId, deviceInfo } = req.body;
      const userId = req.user.id;

      const success = await pushService.storeUserDeviceToken(userId, token, provider, deviceId);

      if (!success) {
        return next(new AppError('Failed to register device token', 500));
      }

      // Log device registration for analytics
      logger.info('Device token registered:', {
        userId,
        provider,
        platform: deviceInfo?.platform,
        model: deviceInfo?.model
      });

      res.status(200).json({
        status: 'success',
        message: 'Device token registered successfully',
        data: {
          provider,
          deviceId,
          registeredAt: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Device token registration failed:', error);
      next(new AppError('Device token registration failed', 500));
    }
  }
);

/**
 * @route   DELETE /api/v1/push/remove-token
 * @desc    Remove device token
 * @access  Private
 */
router.delete('/remove-token',
  authenticate,
  validate(pushSchemas.removeToken),
  async (req, res, next) => {
    try {
      const { deviceId } = req.body;
      const userId = req.user.id;

      const success = await pushService.removeUserDeviceToken(userId, deviceId);

      if (!success) {
        return next(new AppError('Device token not found', 404));
      }

      logger.info('Device token removed:', {
        userId,
        deviceId: deviceId.substring(0, 8) + '...'
      });

      res.status(200).json({
        status: 'success',
        message: 'Device token removed successfully'
      });

    } catch (error) {
      logger.error('Device token removal failed:', error);
      next(new AppError('Device token removal failed', 500));
    }
  }
);

/**
 * @route   GET /api/v1/push/tokens
 * @desc    Get user's registered device tokens
 * @access  Private
 */
router.get('/tokens',
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const tokens = await pushService.getUserDeviceTokens(userId);

      // Format response to hide actual tokens for security
      const formattedTokens = {};
      for (const [provider, tokenList] of Object.entries(tokens)) {
        formattedTokens[provider] = tokenList.map(token => ({
          deviceId: typeof token === 'string' ? 'unknown' : token.deviceId,
          provider: provider,
          registeredAt: typeof token === 'string' ? null : token.updatedAt,
          tokenPreview: (typeof token === 'string' ? token : token.token).substring(0, 8) + '...'
        }));
      }

      res.status(200).json({
        status: 'success',
        data: {
          tokens: formattedTokens,
          totalDevices: Object.values(tokens).reduce((sum, arr) => sum + arr.length, 0)
        }
      });

    } catch (error) {
      logger.error('Failed to get device tokens:', error);
      next(new AppError('Failed to get device tokens', 500));
    }
  }
);

/**
 * @route   POST /api/v1/push/send
 * @desc    Send push notification to specific user (admin only)
 * @access  Private (Admin)
 */
router.post('/send',
  authenticate,
  // requireRole('admin'), // Uncomment when role-based auth is implemented
  loggingSQLInjectionFilter,
  validate(pushSchemas.sendNotification),
  async (req, res, next) => {
    try {
      const { userId, title, body, data, badge, sound } = req.body;

      const notification = {
        title,
        body,
        data: data || {},
        badge,
        sound
      };

      const result = await pushService.sendNotificationToUser(userId, notification);

      if (!result.success) {
        return next(new AppError(`Push notification failed: ${result.error}`, 500));
      }

      logger.info('Push notification sent by admin:', {
        adminId: req.user.id,
        targetUserId: userId,
        title,
        success: result.success
      });

      res.status(200).json({
        status: 'success',
        message: 'Push notification sent successfully',
        data: {
          result: result.summary || result
        }
      });

    } catch (error) {
      logger.error('Admin push notification failed:', error);
      next(new AppError('Push notification failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/push/test
 * @desc    Test push notification to specific device
 * @access  Private
 */
router.post('/test',
  authenticate,
  validate(pushSchemas.testNotification),
  async (req, res, next) => {
    try {
      const { token, provider } = req.body;
      const userId = req.user.id;

      const result = await pushService.testPushNotification(token, provider);

      logger.info('Test push notification requested:', {
        userId,
        provider,
        success: result.success
      });

      res.status(200).json({
        status: 'success',
        message: 'Test notification sent',
        data: {
          provider,
          success: result.success,
          error: result.error || null
        }
      });

    } catch (error) {
      logger.error('Test push notification failed:', error);
      next(new AppError('Test notification failed', 500));
    }
  }
);

/**
 * @route   GET /api/v1/push/stats
 * @desc    Get push service statistics
 * @access  Private
 */
router.get('/stats',
  authenticate,
  async (req, res, next) => {
    try {
      const stats = pushService.getStats();

      res.status(200).json({
        status: 'success',
        data: {
          stats
        }
      });

    } catch (error) {
      logger.error('Failed to get push stats:', error);
      next(new AppError('Failed to get push statistics', 500));
    }
  }
);

/**
 * @route   GET /api/v1/push/health
 * @desc    Check push service health
 * @access  Public
 */
router.get('/health',
  async (req, res, next) => {
    try {
      const isAvailable = pushService.isAvailable();
      const stats = pushService.getStats();

      res.status(200).json({
        status: 'success',
        data: {
          healthy: isAvailable,
          availableProviders: stats.availableProviders,
          supportedPlatforms: stats.supportedPlatforms,
          timestamp: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Push health check failed:', error);
      next(new AppError('Health check failed', 500));
    }
  }
);

module.exports = router;