/**
 * Push Notification Service
 * Comprehensive push notification support for all Android and iOS devices
 * Supports Xiaomi, Huawei, OPPO, Vivo (Android) and APNs (iOS)
 */

const axios = require('axios');
const crypto = require('crypto');
const apn = require('apn');
const PushNotifications = require('node-pushnotifications');
const config = require('../config/env');
const { logger } = require('../config/logger');
const redisService = require('./redis');

/**
 * Push Notification Service Class
 */
class PushService {
  constructor() {
    this.providers = {
      xiaomi: null,
      huawei: null,
      oppo: null,
      vivo: null,
      apns: null
    };
    this.isInitialized = false;
    this.init();
  }

  /**
   * Initialize all push service providers
   */
  init() {
    try {
      // Initialize Xiaomi Push
      if (config.push.xiaomi.appSecret && config.push.xiaomi.packageName) {
        this.providers.xiaomi = {
          appSecret: config.push.xiaomi.appSecret,
          packageName: config.push.xiaomi.packageName,
          baseUrl: 'https://api.xmpush.xiaomi.com'
        };
        logger.info('Xiaomi Push service initialized');
      }

      // Initialize Huawei Push
      if (config.push.huawei.appId && config.push.huawei.appSecret) {
        this.providers.huawei = {
          appId: config.push.huawei.appId,
          appSecret: config.push.huawei.appSecret,
          baseUrl: 'https://push-api.cloud.huawei.com'
        };
        logger.info('Huawei Push service initialized');
      }

      // Initialize OPPO Push
      if (config.push.oppo.appKey && config.push.oppo.masterSecret) {
        this.providers.oppo = {
          appKey: config.push.oppo.appKey,
          masterSecret: config.push.oppo.masterSecret,
          appSecret: config.push.oppo.appSecret,
          baseUrl: 'https://api.push.oppomobile.com'
        };
        logger.info('OPPO Push service initialized');
      }

      // Initialize Vivo Push
      if (config.push.vivo.appId && config.push.vivo.appKey && config.push.vivo.appSecret) {
        this.providers.vivo = {
          appId: config.push.vivo.appId,
          appKey: config.push.vivo.appKey,
          appSecret: config.push.vivo.appSecret,
          baseUrl: 'https://api-push.vivo.com.cn'
        };
        logger.info('Vivo Push service initialized');
      }

      // Initialize Apple Push Notification Service (APNs)
      if (config.push.apns.keyPath && config.push.apns.keyId && config.push.apns.teamId) {
        try {
          this.providers.apns = new apn.Provider({
            token: {
              key: config.push.apns.keyPath,
              keyId: config.push.apns.keyId,
              teamId: config.push.apns.teamId
            },
            production: config.push.apns.production === 'true' // Convert string to boolean
          });
          logger.info('Apple Push Notification Service (APNs) initialized');
        } catch (error) {
          logger.error('Failed to initialize APNs:', error);
        }
      }

      this.isInitialized = true;
      logger.info('Push notification service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize push service:', error);
    }
  }

  /**
   * Check if push service is available
   * @returns {boolean} Service availability
   */
  isAvailable() {
    return this.isInitialized && Object.values(this.providers).some(provider => provider !== null);
  }

  /**
   * Send push notification via Xiaomi
   * @param {Array} tokens - Device tokens
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendXiaomiPush(tokens, notification) {
    try {
      if (!this.providers.xiaomi) {
        throw new Error('Xiaomi Push not configured');
      }

      const { title, body, data = {} } = notification;
      const provider = this.providers.xiaomi;

      const payload = {
        registration_id: tokens.join(','),
        title: title,
        description: body,
        payload: JSON.stringify(data),
        restricted_package_name: provider.packageName,
        pass_through: 0,
        notify_type: 1
      };

      const response = await axios.post(
        `${provider.baseUrl}/v3/message/regid`,
        new URLSearchParams(payload),
        {
          headers: {
            'Authorization': `key=${provider.appSecret}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      logger.info('Xiaomi push sent successfully:', {
        tokens: tokens.length,
        messageId: response.data.data?.id
      });

      return {
        success: true,
        provider: 'xiaomi',
        messageId: response.data.data?.id,
        result: response.data
      };

    } catch (error) {
      logger.error('Xiaomi push failed:', error);
      return {
        success: false,
        provider: 'xiaomi',
        error: error.message
      };
    }
  }

  /**
   * Get Huawei access token
   * @returns {Promise<string>} Access token
   */
  async getHuaweiAccessToken() {
    try {
      const cacheKey = 'huawei_access_token';
      
      // Check cache first
      if (redisService.isReady()) {
        const cachedToken = await redisService.get(cacheKey);
        if (cachedToken) {
          return cachedToken;
        }
      }

      const provider = this.providers.huawei;
      const response = await axios.post(
        'https://oauth-login.cloud.huawei.com/oauth2/v3/token',
        new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: provider.appId,
          client_secret: provider.appSecret
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const accessToken = response.data.access_token;
      const expiresIn = response.data.expires_in;

      // Cache token
      if (redisService.isReady()) {
        await redisService.set(cacheKey, accessToken, expiresIn - 300); // 5 minutes buffer
      }

      return accessToken;

    } catch (error) {
      logger.error('Failed to get Huawei access token:', error);
      throw error;
    }
  }

  /**
   * Send push notification via Huawei
   * @param {Array} tokens - Device tokens
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendHuaweiPush(tokens, notification) {
    try {
      if (!this.providers.huawei) {
        throw new Error('Huawei Push not configured');
      }

      const { title, body, data = {} } = notification;
      const accessToken = await this.getHuaweiAccessToken();

      const message = {
        validate_only: false,
        message: {
          android: {
            notification: {
              title: title,
              body: body
            },
            data: JSON.stringify(data)
          },
          token: tokens
        }
      };

      const response = await axios.post(
        `${this.providers.huawei.baseUrl}/v1/${this.providers.huawei.appId}/messages:send`,
        message,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      logger.info('Huawei push sent successfully:', {
        tokens: tokens.length,
        messageId: response.data.msg_id
      });

      return {
        success: true,
        provider: 'huawei',
        messageId: response.data.msg_id,
        result: response.data
      };

    } catch (error) {
      logger.error('Huawei push failed:', error);
      return {
        success: false,
        provider: 'huawei',
        error: error.message
      };
    }
  }

  /**
   * Get OPPO access token
   * @returns {Promise<string>} Access token
   */
  async getOppoAccessToken() {
    try {
      const cacheKey = 'oppo_access_token';
      
      // Check cache first
      if (redisService.isReady()) {
        const cachedToken = await redisService.get(cacheKey);
        if (cachedToken) {
          return cachedToken;
        }
      }

      const provider = this.providers.oppo;
      const timestamp = Date.now();
      const sign = crypto.createHash('sha256')
        .update(`${provider.appKey}${timestamp}${provider.masterSecret}`)
        .digest('hex');

      const response = await axios.post(
        `${provider.baseUrl}/server/v1/auth`,
        {
          app_key: provider.appKey,
          timestamp: timestamp,
          sign: sign
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.code === 0) {
        const accessToken = response.data.data.auth_token;
        const expiresIn = response.data.data.create_time + 86400; // 24 hours

        // Cache token
        if (redisService.isReady()) {
          await redisService.set(cacheKey, accessToken, 86400 - 300); // 23h 55m
        }

        return accessToken;
      } else {
        throw new Error(`OPPO auth failed: ${response.data.message}`);
      }

    } catch (error) {
      logger.error('Failed to get OPPO access token:', error);
      throw error;
    }
  }

  /**
   * Send push notification via OPPO
   * @param {Array} tokens - Device tokens
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendOppoPush(tokens, notification) {
    try {
      if (!this.providers.oppo) {
        throw new Error('OPPO Push not configured');
      }

      const { title, body, data = {} } = notification;
      const accessToken = await this.getOppoAccessToken();

      const message = {
        message: {
          app_message_id: crypto.randomUUID(),
          title: title,
          content: body,
          click_action_type: 1,
          click_action_activity: '',
          click_action_url: '',
          action_parameters: JSON.stringify(data),
          show_ttl: 86400,
          off_line: true,
          off_line_ttl: 86400
        },
        target_type: 2,
        target_value: tokens.join(';')
      };

      const response = await axios.post(
        `${this.providers.oppo.baseUrl}/server/v1/message/notification/unicast`,
        message,
        {
          headers: {
            'auth_token': accessToken,
            'Content-Type': 'application/json'
          }
        }
      );

      logger.info('OPPO push sent successfully:', {
        tokens: tokens.length,
        messageId: response.data.data?.message_id
      });

      return {
        success: response.data.code === 0,
        provider: 'oppo',
        messageId: response.data.data?.message_id,
        result: response.data
      };

    } catch (error) {
      logger.error('OPPO push failed:', error);
      return {
        success: false,
        provider: 'oppo',
        error: error.message
      };
    }
  }

  /**
   * Get Vivo access token
   * @returns {Promise<string>} Access token
   */
  async getVivoAccessToken() {
    try {
      const cacheKey = 'vivo_access_token';
      
      // Check cache first
      if (redisService.isReady()) {
        const cachedToken = await redisService.get(cacheKey);
        if (cachedToken) {
          return cachedToken;
        }
      }

      const provider = this.providers.vivo;
      const timestamp = Date.now();
      const sign = crypto.createHash('md5')
        .update(`${provider.appId}${provider.appKey}${timestamp}${provider.appSecret}`)
        .digest('hex');

      const response = await axios.post(
        `${provider.baseUrl}/message/auth`,
        {
          appId: provider.appId,
          appKey: provider.appKey,
          timestamp: timestamp,
          sign: sign
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.result === 0) {
        const accessToken = response.data.authToken;

        // Cache token for 23 hours
        if (redisService.isReady()) {
          await redisService.set(cacheKey, accessToken, 82800); // 23 hours
        }

        return accessToken;
      } else {
        throw new Error(`Vivo auth failed: ${response.data.desc}`);
      }

    } catch (error) {
      logger.error('Failed to get Vivo access token:', error);
      throw error;
    }
  }

  /**
   * Send push notification via Vivo
   * @param {Array} tokens - Device tokens
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendVivoPush(tokens, notification) {
    try {
      if (!this.providers.vivo) {
        throw new Error('Vivo Push not configured');
      }

      const { title, body, data = {} } = notification;
      const accessToken = await this.getVivoAccessToken();

      const message = {
        regId: tokens.join(','),
        notifyType: 1,
        title: title,
        content: body,
        timeToLive: 86400,
        skipType: 1,
        skipContent: '',
        networkType: -1,
        classification: 1,
        requestId: crypto.randomUUID(),
        extra: JSON.stringify(data)
      };

      const response = await axios.post(
        `${this.providers.vivo.baseUrl}/message/send`,
        message,
        {
          headers: {
            'authToken': accessToken,
            'Content-Type': 'application/json'
          }
        }
      );

      logger.info('Vivo push sent successfully:', {
        tokens: tokens.length,
        taskId: response.data.taskId
      });

      return {
        success: response.data.result === 0,
        provider: 'vivo',
        messageId: response.data.taskId,
        result: response.data
      };

    } catch (error) {
      logger.error('Vivo push failed:', error);
      return {
        success: false,
        provider: 'vivo',
        error: error.message
      };
    }
  }

  /**
   * Send push notification via Apple Push Notification Service (APNs)
   * @param {Array} tokens - Device tokens
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendApnsPush(tokens, notification) {
    try {
      if (!this.providers.apns) {
        throw new Error('APNs not configured');
      }

      const { title, body, data = {}, badge, sound = 'default' } = notification;

      const apnNotification = new apn.Notification({
        alert: {
          title: title,
          body: body
        },
        badge: badge || 1,
        sound: sound,
        payload: data,
        topic: config.push.apns.bundleId
      });

      const results = [];
      
      // Send to each token individually for better error handling
      for (const token of tokens) {
        try {
          const result = await this.providers.apns.send(apnNotification, token);
          results.push({
            token: token,
            success: result.failed.length === 0,
            sent: result.sent,
            failed: result.failed
          });
        } catch (error) {
          results.push({
            token: token,
            success: false,
            error: error.message
          });
        }
      }

      const successCount = results.filter(r => r.success).length;
      const failedCount = results.length - successCount;

      logger.info('APNs push sent:', {
        total: tokens.length,
        success: successCount,
        failed: failedCount
      });

      return {
        success: successCount > 0,
        provider: 'apns',
        results: results,
        summary: {
          total: tokens.length,
          success: successCount,
          failed: failedCount
        }
      };

    } catch (error) {
      logger.error('APNs push failed:', error);
      return {
        success: false,
        provider: 'apns',
        error: error.message
      };
    }
  }

  /**
   * Send push notification with comprehensive platform support
   * @param {Object} tokens - Device tokens grouped by provider
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendPushNotification(tokens, notification) {
    try {
      if (!this.isAvailable()) {
        throw new Error('Push service not available');
      }

      const results = [];

      // Send to Xiaomi devices
      if (tokens.xiaomi && tokens.xiaomi.length > 0 && this.providers.xiaomi) {
        const result = await this.sendXiaomiPush(tokens.xiaomi, notification);
        results.push(result);
      }

      // Send to Huawei devices
      if (tokens.huawei && tokens.huawei.length > 0 && this.providers.huawei) {
        const result = await this.sendHuaweiPush(tokens.huawei, notification);
        results.push(result);
      }

      // Send to OPPO devices
      if (tokens.oppo && tokens.oppo.length > 0 && this.providers.oppo) {
        const result = await this.sendOppoPush(tokens.oppo, notification);
        results.push(result);
      }

      // Send to Vivo devices
      if (tokens.vivo && tokens.vivo.length > 0 && this.providers.vivo) {
        const result = await this.sendVivoPush(tokens.vivo, notification);
        results.push(result);
      }

      // Send to iOS devices via APNs
      if (tokens.apns && tokens.apns.length > 0 && this.providers.apns) {
        const result = await this.sendApnsPush(tokens.apns, notification);
        results.push(result);
      }

      const successCount = results.filter(r => r.success).length;
      const totalCount = results.length;

      logger.info('Push notifications sent:', {
        total: totalCount,
        success: successCount,
        failed: totalCount - successCount,
        platforms: Object.keys(tokens).filter(platform => tokens[platform] && tokens[platform].length > 0)
      });

      return {
        success: successCount > 0,
        results,
        summary: {
          total: totalCount,
          success: successCount,
          failed: totalCount - successCount,
          platforms: Object.keys(tokens).filter(platform => tokens[platform] && tokens[platform].length > 0)
        }
      };

    } catch (error) {
      logger.error('Push notification failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send notification to user
   * @param {string} userId - User ID
   * @param {Object} notification - Notification data
   * @returns {Promise<Object>} Send result
   */
  async sendNotificationToUser(userId, notification) {
    try {
      // Get user's device tokens from database/cache
      const tokens = await this.getUserDeviceTokens(userId);
      
      if (!tokens || Object.keys(tokens).length === 0) {
        logger.warn(`No device tokens found for user ${userId}`);
        return {
          success: false,
          error: 'No device tokens found'
        };
      }

      return await this.sendPushNotification(tokens, notification);

    } catch (error) {
      logger.error('Failed to send notification to user:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get user device tokens from cache/database
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Device tokens grouped by provider
   */
  async getUserDeviceTokens(userId) {
    try {
      if (!redisService.isReady()) {
        return {};
      }

      const key = `user_device_tokens:${userId}`;
      const tokens = await redisService.get(key, true);
      
      // Convert stored format to arrays of token strings
      const formattedTokens = {};
      
      if (tokens) {
        for (const [provider, tokenData] of Object.entries(tokens)) {
          if (Array.isArray(tokenData) && tokenData.length > 0) {
            formattedTokens[provider] = tokenData.map(item => 
              typeof item === 'string' ? item : item.token
            );
          }
        }
      }
      
      return formattedTokens;

    } catch (error) {
      logger.error('Failed to get user device tokens:', error);
      return {};
    }
  }

  /**
   * Store user device token
   * @param {string} userId - User ID
   * @param {string} token - Device token
   * @param {string} provider - Push provider (xiaomi, huawei, oppo, vivo, apns)
   * @param {string} deviceId - Device ID
   * @returns {Promise<boolean>} Success status
   */
  async storeUserDeviceToken(userId, token, provider, deviceId) {
    try {
      if (!redisService.isReady()) {
        return false;
      }

      // Validate provider
      const validProviders = ['xiaomi', 'huawei', 'oppo', 'vivo', 'apns'];
      if (!validProviders.includes(provider)) {
        logger.error(`Invalid push provider: ${provider}`);
        return false;
      }

      const key = `user_device_tokens:${userId}`;
      const tokens = await redisService.get(key, true) || {};
      
      if (!tokens[provider]) {
        tokens[provider] = [];
      }

      // Remove existing token for this device
      tokens[provider] = tokens[provider].filter(t => 
        (typeof t === 'string' ? t : t.deviceId) !== deviceId
      );
      
      // Add new token
      tokens[provider].push({
        token,
        deviceId,
        provider,
        updatedAt: new Date().toISOString()
      });

      await redisService.set(key, tokens, 86400 * 30); // 30 days

      logger.info('Device token stored successfully:', {
        userId,
        provider,
        deviceId: deviceId.substring(0, 8) + '...' // Log partial device ID for privacy
      });

      return true;

    } catch (error) {
      logger.error('Failed to store device token:', error);
      return false;
    }
  }

  /**
   * Remove user device token
   * @param {string} userId - User ID
   * @param {string} deviceId - Device ID
   * @returns {Promise<boolean>} Success status
   */
  async removeUserDeviceToken(userId, deviceId) {
    try {
      if (!redisService.isReady()) {
        return false;
      }

      const key = `user_device_tokens:${userId}`;
      const tokens = await redisService.get(key, true) || {};
      
      let removed = false;
      for (const provider in tokens) {
        const originalLength = tokens[provider].length;
        tokens[provider] = tokens[provider].filter(t => 
          (typeof t === 'string' ? t : t.deviceId) !== deviceId
        );
        if (tokens[provider].length < originalLength) {
          removed = true;
        }
      }

      if (removed) {
        await redisService.set(key, tokens, 86400 * 30); // 30 days
        logger.info('Device token removed successfully:', {
          userId,
          deviceId: deviceId.substring(0, 8) + '...'
        });
      }

      return removed;

    } catch (error) {
      logger.error('Failed to remove device token:', error);
      return false;
    }
  }

  /**
   * Send bulk notifications
   * @param {Array} notifications - Array of notification objects
   * @returns {Promise<Object>} Send result
   */
  async sendBulkNotifications(notifications) {
    try {
      const results = [];

      for (const notif of notifications) {
        const result = await this.sendNotificationToUser(notif.userId, notif.notification);
        results.push({
          userId: notif.userId,
          ...result
        });
      }

      const successCount = results.filter(r => r.success).length;
      const totalCount = results.length;

      logger.info('Bulk notifications sent:', {
        total: totalCount,
        success: successCount,
        failed: totalCount - successCount
      });

      return {
        success: successCount > 0,
        results,
        summary: {
          total: totalCount,
          success: successCount,
          failed: totalCount - successCount
        }
      };

    } catch (error) {
      logger.error('Bulk notification failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get push service statistics
   * @returns {Object} Service statistics
   */
  getStats() {
    const availableProviders = Object.entries(this.providers)
      .filter(([_, provider]) => provider !== null)
      .map(([name, _]) => name);

    return {
      isAvailable: this.isAvailable(),
      availableProviders,
      totalProviders: availableProviders.length,
      supportedPlatforms: {
        android: availableProviders.filter(p => ['xiaomi', 'huawei', 'oppo', 'vivo'].includes(p)),
        ios: availableProviders.includes('apns') ? ['apns'] : []
      }
    };
  }

  /**
   * Test push notification to specific device
   * @param {string} token - Device token
   * @param {string} provider - Push provider
   * @returns {Promise<Object>} Test result
   */
  async testPushNotification(token, provider) {
    try {
      const testNotification = {
        title: 'SilverApp Test',
        body: 'This is a test notification from SilverApp',
        data: {
          test: true,
          timestamp: new Date().toISOString()
        }
      };

      const tokens = { [provider]: [token] };
      const result = await this.sendPushNotification(tokens, testNotification);

      logger.info('Test push notification sent:', {
        provider,
        token: token.substring(0, 8) + '...',
        success: result.success
      });

      return result;

    } catch (error) {
      logger.error('Test push notification failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

// Create singleton instance
const pushService = new PushService();

module.exports = pushService;