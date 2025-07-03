/**
 * Analytics Service
 * Handles analytics using Chinese analytics services (Baidu Analytics, Tencent Analytics)
 */

const axios = require('axios');
const crypto = require('crypto');
const config = require('../config/env');
const { logger } = require('../config/logger');
const redisService = require('./redis');

/**
 * Analytics Service Class
 */
class AnalyticsService {
  constructor() {
    this.provider = config.analytics.provider || 'baidu';
    this.baiduConfig = config.analytics.baidu;
    this.tencentConfig = config.analytics.tencent;
    this.isInitialized = false;
    this.init();
  }

  /**
   * Initialize analytics service
   */
  init() {
    try {
      if (this.baiduConfig.siteId && this.baiduConfig.token) {
        logger.info('Baidu Analytics service initialized');
      }

      if (this.tencentConfig.appId && this.tencentConfig.secretKey) {
        logger.info('Tencent Analytics service initialized');
      }

      this.isInitialized = true;
      logger.info('Analytics service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize analytics service:', error);
    }
  }

  /**
   * Check if analytics service is available
   * @returns {boolean} Service availability
   */
  isAvailable() {
    return this.isInitialized && (
      (this.baiduConfig.siteId && this.baiduConfig.token) ||
      (this.tencentConfig.appId && this.tencentConfig.secretKey)
    );
  }

  /**
   * Track event using Baidu Analytics
   * @param {Object} eventData - Event data
   * @returns {Promise<Object>} Track result
   */
  async trackBaiduEvent(eventData) {
    try {
      const {
        userId,
        event,
        category,
        action,
        label,
        value,
        customDimensions = {}
      } = eventData;

      const params = {
        v: '1',
        tid: this.baiduConfig.siteId,
        cid: userId || crypto.randomUUID(),
        t: 'event',
        ec: category,
        ea: action,
        el: label,
        ev: value,
        ...customDimensions
      };

      const response = await axios.post(
        'https://hm.baidu.com/hm.gif',
        new URLSearchParams(params),
        {
          headers: {
            'User-Agent': 'SilverApp/1.0',
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      logger.debug('Baidu Analytics event tracked:', {
        event,
        category,
        action,
        userId
      });

      return {
        success: true,
        provider: 'baidu',
        eventId: crypto.randomUUID()
      };

    } catch (error) {
      logger.error('Baidu Analytics tracking failed:', error);
      return {
        success: false,
        provider: 'baidu',
        error: error.message
      };
    }
  }

  /**
   * Track event using Tencent Analytics
   * @param {Object} eventData - Event data
   * @returns {Promise<Object>} Track result
   */
  async trackTencentEvent(eventData) {
    try {
      const {
        userId,
        event,
        category,
        action,
        label,
        value,
        customDimensions = {}
      } = eventData;

      const timestamp = Math.floor(Date.now() / 1000);
      const params = {
        app_id: this.tencentConfig.appId,
        user_id: userId || crypto.randomUUID(),
        event_name: event,
        event_time: timestamp,
        properties: {
          category,
          action,
          label,
          value,
          ...customDimensions
        }
      };

      // Generate signature
      const signature = this.generateTencentSignature(params);
      params.signature = signature;

      const response = await axios.post(
        'https://analytics.qq.com/api/event',
        params,
        {
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'SilverApp/1.0'
          }
        }
      );

      logger.debug('Tencent Analytics event tracked:', {
        event,
        category,
        action,
        userId
      });

      return {
        success: true,
        provider: 'tencent',
        eventId: response.data.event_id
      };

    } catch (error) {
      logger.error('Tencent Analytics tracking failed:', error);
      return {
        success: false,
        provider: 'tencent',
        error: error.message
      };
    }
  }

  /**
   * Generate Tencent Analytics signature
   * @param {Object} params - Parameters to sign
   * @returns {string} Signature
   */
  generateTencentSignature(params) {
    const sortedKeys = Object.keys(params).sort();
    const stringA = sortedKeys
      .filter(key => key !== 'signature')
      .map(key => `${key}=${JSON.stringify(params[key])}`)
      .join('&');
    
    const stringSignTemp = `${stringA}&secret_key=${this.tencentConfig.secretKey}`;
    return crypto.createHash('md5').update(stringSignTemp, 'utf8').digest('hex');
  }

  /**
   * Track event with fallback
   * @param {Object} eventData - Event data
   * @returns {Promise<Object>} Track result
   */
  async trackEvent(eventData) {
    try {
      if (!this.isAvailable()) {
        // Store event locally for later processing
        await this.storeEventLocally(eventData);
        return {
          success: true,
          stored: true,
          message: 'Event stored locally'
        };
      }

      let result;

      if (this.provider === 'baidu' && this.baiduConfig.siteId) {
        result = await this.trackBaiduEvent(eventData);
      } else if (this.provider === 'tencent' && this.tencentConfig.appId) {
        result = await this.trackTencentEvent(eventData);
      } else {
        throw new Error('No analytics provider available');
      }

      // Store successful events in cache for reporting
      if (result.success) {
        await this.cacheEvent(eventData);
      }

      return result;

    } catch (error) {
      logger.error('Event tracking failed:', error);
      
      // Store event locally as fallback
      await this.storeEventLocally(eventData);
      
      return {
        success: false,
        stored: true,
        error: error.message
      };
    }
  }

  /**
   * Store event locally in Redis
   * @param {Object} eventData - Event data
   */
  async storeEventLocally(eventData) {
    try {
      if (!redisService.isReady()) return;

      const key = 'analytics_events_queue';
      const event = {
        ...eventData,
        timestamp: new Date().toISOString(),
        id: crypto.randomUUID()
      };

      await redisService.lpush(key, event);
      
      // Keep only last 1000 events
      await redisService.client.ltrim(key, 0, 999);

    } catch (error) {
      logger.error('Failed to store event locally:', error);
    }
  }

  /**
   * Cache successful event
   * @param {Object} eventData - Event data
   */
  async cacheEvent(eventData) {
    try {
      if (!redisService.isReady()) return;

      const key = `analytics_cache:${new Date().toISOString().split('T')[0]}`;
      const event = {
        ...eventData,
        timestamp: new Date().toISOString()
      };

      await redisService.lpush(key, event);
      await redisService.expire(key, 86400 * 7); // 7 days

    } catch (error) {
      logger.error('Failed to cache event:', error);
    }
  }

  /**
   * Process queued events
   * @returns {Promise<Object>} Process result
   */
  async processQueuedEvents() {
    try {
      if (!redisService.isReady()) return { processed: 0 };

      const key = 'analytics_events_queue';
      const events = await redisService.lrange(key, 0, 99); // Process 100 events at a time
      
      if (!events || events.length === 0) {
        return { processed: 0 };
      }

      let processed = 0;
      let failed = 0;

      for (const event of events) {
        try {
          const eventData = typeof event === 'string' ? JSON.parse(event) : event;
          const result = await this.trackEvent(eventData);
          
          if (result.success && !result.stored) {
            processed++;
            // Remove processed event from queue
            await redisService.rpop(key);
          } else {
            failed++;
          }
        } catch (error) {
          logger.error('Failed to process queued event:', error);
          failed++;
        }
      }

      logger.info('Queued events processed:', { processed, failed });

      return { processed, failed };

    } catch (error) {
      logger.error('Failed to process queued events:', error);
      return { processed: 0, failed: 0 };
    }
  }

  /**
   * Track user action
   * @param {string} userId - User ID
   * @param {string} action - Action name
   * @param {Object} properties - Additional properties
   * @returns {Promise<Object>} Track result
   */
  async trackUserAction(userId, action, properties = {}) {
    return await this.trackEvent({
      userId,
      event: 'user_action',
      category: 'user',
      action,
      label: properties.label || action,
      value: properties.value || 1,
      customDimensions: properties
    });
  }

  /**
   * Track page view
   * @param {string} userId - User ID
   * @param {string} page - Page name
   * @param {Object} properties - Additional properties
   * @returns {Promise<Object>} Track result
   */
  async trackPageView(userId, page, properties = {}) {
    return await this.trackEvent({
      userId,
      event: 'page_view',
      category: 'navigation',
      action: 'view',
      label: page,
      value: 1,
      customDimensions: {
        page,
        ...properties
      }
    });
  }

  /**
   * Track social interaction
   * @param {string} userId - User ID
   * @param {string} interaction - Interaction type (like, share, comment)
   * @param {string} target - Target object (post, comment, etc.)
   * @param {Object} properties - Additional properties
   * @returns {Promise<Object>} Track result
   */
  async trackSocialInteraction(userId, interaction, target, properties = {}) {
    return await this.trackEvent({
      userId,
      event: 'social_interaction',
      category: 'social',
      action: interaction,
      label: target,
      value: 1,
      customDimensions: {
        interaction,
        target,
        ...properties
      }
    });
  }

  /**
   * Track error
   * @param {string} userId - User ID
   * @param {string} error - Error message
   * @param {Object} properties - Additional properties
   * @returns {Promise<Object>} Track result
   */
  async trackError(userId, error, properties = {}) {
    return await this.trackEvent({
      userId,
      event: 'error',
      category: 'error',
      action: 'exception',
      label: error,
      value: 1,
      customDimensions: {
        error,
        ...properties
      }
    });
  }

  /**
   * Get analytics summary
   * @param {string} date - Date (YYYY-MM-DD)
   * @returns {Promise<Object>} Analytics summary
   */
  async getAnalyticsSummary(date = null) {
    try {
      if (!redisService.isReady()) {
        return { error: 'Redis not available' };
      }

      const targetDate = date || new Date().toISOString().split('T')[0];
      const key = `analytics_cache:${targetDate}`;
      
      const events = await redisService.lrange(key, 0, -1, true);
      
      if (!events || events.length === 0) {
        return {
          date: targetDate,
          totalEvents: 0,
          categories: {},
          actions: {},
          users: 0
        };
      }

      const summary = {
        date: targetDate,
        totalEvents: events.length,
        categories: {},
        actions: {},
        users: new Set()
      };

      events.forEach(event => {
        // Count categories
        if (event.category) {
          summary.categories[event.category] = (summary.categories[event.category] || 0) + 1;
        }

        // Count actions
        if (event.action) {
          summary.actions[event.action] = (summary.actions[event.action] || 0) + 1;
        }

        // Count unique users
        if (event.userId) {
          summary.users.add(event.userId);
        }
      });

      summary.users = summary.users.size;

      return summary;

    } catch (error) {
      logger.error('Failed to get analytics summary:', error);
      return { error: error.message };
    }
  }

  /**
   * Start background processing of queued events
   */
  startBackgroundProcessing() {
    // Process queued events every 5 minutes
    setInterval(async () => {
      try {
        await this.processQueuedEvents();
      } catch (error) {
        logger.error('Background event processing failed:', error);
      }
    }, 5 * 60 * 1000);

    logger.info('Analytics background processing started');
  }
}

// Create singleton instance
const analyticsService = new AnalyticsService();

module.exports = analyticsService;