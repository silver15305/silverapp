/**
 * SMS Service
 * Handles SMS sending using Alibaba Cloud SMS and Tencent Cloud SMS for phone verification
 * China-compatible SMS services
 */

const Core = require('@alicloud/pop-core');
const tencentcloud = require('tencentcloud-sdk-nodejs');
const config = require('../config/env');
const { logger } = require('../config/logger');
const redisService = require('./redis');

/**
 * SMS Service Class for China
 */
class SMSService {
  constructor() {
    this.alibabaClient = null;
    this.tencentClient = null;
    this.isInitialized = false;
    this.init();
  }

  /**
   * Initialize SMS clients
   */
  init() {
    try {
      // Initialize Alibaba Cloud SMS client
      if (config.alibabaCloud.accessKeyId && config.alibabaCloud.accessKeySecret) {
        this.alibabaClient = new Core({
          accessKeyId: config.alibabaCloud.accessKeyId,
          accessKeySecret: config.alibabaCloud.accessKeySecret,
          endpoint: 'https://dysmsapi.aliyuncs.com',
          apiVersion: '2017-05-25'
        });
        logger.info('Alibaba Cloud SMS client initialized');
      }

      // Initialize Tencent Cloud SMS client
      if (config.tencentCloud.secretId && config.tencentCloud.secretKey) {
        const SmsClient = tencentcloud.sms.v20210111.Client;
        const clientConfig = {
          credential: {
            secretId: config.tencentCloud.secretId,
            secretKey: config.tencentCloud.secretKey,
          },
          region: config.tencentCloud.region,
          profile: {
            httpProfile: {
              endpoint: "sms.tencentcloudapi.com",
            },
          },
        };
        this.tencentClient = new SmsClient(clientConfig);
        logger.info('Tencent Cloud SMS client initialized');
      }

      this.isInitialized = true;
      logger.info('SMS service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize SMS service:', error);
    }
  }

  /**
   * Check if SMS service is available
   * @returns {boolean} Service availability
   */
  isAvailable() {
    return this.isInitialized && (this.alibabaClient !== null || this.tencentClient !== null);
  }

  /**
   * Send SMS using Alibaba Cloud
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} templateCode - SMS template code
   * @param {Object} templateParam - Template parameters
   * @returns {Promise<Object>} Send result
   */
  async sendSMSAlibaba(phoneNumber, templateCode, templateParam) {
    try {
      if (!this.alibabaClient) {
        throw new Error('Alibaba Cloud SMS client not initialized');
      }

      const params = {
        PhoneNumbers: phoneNumber,
        SignName: config.alibabaCloud.smsSignName,
        TemplateCode: templateCode,
        TemplateParam: JSON.stringify(templateParam)
      };

      const requestOption = {
        method: 'POST'
      };

      const result = await this.alibabaClient.request('SendSms', params, requestOption);
      
      logger.info('Alibaba Cloud SMS sent successfully:', {
        phoneNumber: this.maskPhoneNumber(phoneNumber),
        bizId: result.BizId,
        code: result.Code
      });

      return {
        success: result.Code === 'OK',
        messageId: result.BizId,
        code: result.Code,
        message: result.Message
      };

    } catch (error) {
      logger.error('Alibaba Cloud SMS failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send SMS using Tencent Cloud
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} templateId - SMS template ID
   * @param {Array} templateParamSet - Template parameters
   * @returns {Promise<Object>} Send result
   */
  async sendSMSTencent(phoneNumber, templateId, templateParamSet) {
    try {
      if (!this.tencentClient) {
        throw new Error('Tencent Cloud SMS client not initialized');
      }

      const params = {
        PhoneNumberSet: [phoneNumber],
        SmsSdkAppId: config.tencentCloud.smsAppId,
        SignName: config.tencentCloud.smsSign,
        TemplateId: templateId,
        TemplateParamSet: templateParamSet
      };

      const result = await this.tencentClient.SendSms(params);
      
      if (result.SendStatusSet && result.SendStatusSet.length > 0) {
        const status = result.SendStatusSet[0];
        
        logger.info('Tencent Cloud SMS sent successfully:', {
          phoneNumber: this.maskPhoneNumber(phoneNumber),
          serialNo: status.SerialNo,
          code: status.Code
        });

        return {
          success: status.Code === 'Ok',
          messageId: status.SerialNo,
          code: status.Code,
          message: status.Message
        };
      }

      return {
        success: false,
        error: 'No send status returned'
      };

    } catch (error) {
      logger.error('Tencent Cloud SMS failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send SMS with fallback mechanism
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} message - Message content (for logging)
   * @param {string} code - Verification code
   * @returns {Promise<Object>} Send result
   */
  async sendSMS(phoneNumber, message, code) {
    try {
      // Validate phone number format
      if (!this.isValidPhoneNumber(phoneNumber)) {
        throw new Error('Invalid phone number format');
      }

      // Check rate limiting
      const rateLimitKey = `sms_rate_limit:${phoneNumber}`;
      const rateLimitResult = await this.checkRateLimit(rateLimitKey);
      
      if (rateLimitResult.isLimited) {
        throw new Error('SMS rate limit exceeded');
      }

      let result;

      // Try Alibaba Cloud first
      if (this.alibabaClient) {
        result = await this.sendSMSAlibaba(
          phoneNumber,
          config.alibabaCloud.smsTemplateCode,
          { code: code }
        );
        
        if (result.success) {
          await this.updateRateLimit(rateLimitKey);
          return result;
        }
      }

      // Fallback to Tencent Cloud
      if (this.tencentClient) {
        result = await this.sendSMSTencent(
          phoneNumber,
          config.tencentCloud.smsTemplateId,
          [code]
        );
        
        if (result.success) {
          await this.updateRateLimit(rateLimitKey);
          return result;
        }
      }

      throw new Error('All SMS providers failed');

    } catch (error) {
      logger.error('Failed to send SMS:', {
        phoneNumber: this.maskPhoneNumber(phoneNumber),
        error: error.message
      });

      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send verification code SMS
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} code - Verification code
   * @returns {Promise<Object>} Send result
   */
  async sendVerificationCode(phoneNumber, code) {
    const message = `您的SilverApp验证码是：${code}，10分钟内有效，请勿泄露给他人。`;
    
    try {
      const result = await this.sendSMS(phoneNumber, message, code);
      
      if (result.success) {
        // Store verification attempt
        await this.storeVerificationAttempt(phoneNumber, code);
      }
      
      return result;
    } catch (error) {
      logger.error('Failed to send verification code:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send login code SMS
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} code - Login code
   * @returns {Promise<Object>} Send result
   */
  async sendLoginCode(phoneNumber, code) {
    const message = `您的SilverApp登录验证码是：${code}，5分钟内有效。如非本人操作，请忽略此短信。`;
    
    try {
      const result = await this.sendSMS(phoneNumber, message, code);
      
      if (result.success) {
        // Store login attempt
        await this.storeLoginAttempt(phoneNumber, code);
      }
      
      return result;
    } catch (error) {
      logger.error('Failed to send login code:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send password reset code SMS
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} code - Reset code
   * @returns {Promise<Object>} Send result
   */
  async sendPasswordResetCode(phoneNumber, code) {
    const message = `您的SilverApp密码重置验证码是：${code}，15分钟内有效。如非本人操作，请立即检查账户安全。`;
    
    return await this.sendSMS(phoneNumber, message, code);
  }

  /**
   * Send notification SMS
   * @param {string} phoneNumber - Recipient phone number
   * @param {string} message - Notification message
   * @returns {Promise<Object>} Send result
   */
  async sendNotification(phoneNumber, message) {
    const fullMessage = `SilverApp：${message}`;
    return await this.sendSMS(phoneNumber, fullMessage, '');
  }

  /**
   * Validate phone number format (China mobile numbers)
   * @param {string} phoneNumber - Phone number to validate
   * @returns {boolean} Validation result
   */
  isValidPhoneNumber(phoneNumber) {
    // China mobile number format: +86 followed by 11 digits starting with 1
    const chinaPhoneRegex = /^(\+86)?1[3-9]\d{9}$/;
    return chinaPhoneRegex.test(phoneNumber.replace(/\s/g, ''));
  }

  /**
   * Mask phone number for logging
   * @param {string} phoneNumber - Phone number to mask
   * @returns {string} Masked phone number
   */
  maskPhoneNumber(phoneNumber) {
    if (!phoneNumber || phoneNumber.length < 4) {
      return '****';
    }
    
    const cleaned = phoneNumber.replace(/\D/g, '');
    if (cleaned.length >= 11) {
      return cleaned.substring(0, 3) + '****' + cleaned.slice(-4);
    }
    
    return '****';
  }

  /**
   * Check SMS rate limiting
   * @param {string} key - Rate limit key
   * @returns {Promise<Object>} Rate limit status
   */
  async checkRateLimit(key) {
    try {
      if (!redisService.isReady()) {
        return { isLimited: false };
      }

      const current = await redisService.incr(key);
      
      if (current === 1) {
        await redisService.expire(key, 3600); // 1 hour
      }

      const limit = 5; // 5 SMS per hour per phone number
      
      return {
        isLimited: current > limit,
        current,
        limit,
        remaining: Math.max(0, limit - current)
      };

    } catch (error) {
      logger.error('Rate limit check failed:', error);
      return { isLimited: false };
    }
  }

  /**
   * Update rate limiting counter
   * @param {string} key - Rate limit key
   */
  async updateRateLimit(key) {
    try {
      if (redisService.isReady()) {
        await redisService.incr(key);
      }
    } catch (error) {
      logger.error('Failed to update rate limit:', error);
    }
  }

  /**
   * Store verification attempt for tracking
   * @param {string} phoneNumber - Phone number
   * @param {string} code - Verification code
   */
  async storeVerificationAttempt(phoneNumber, code) {
    try {
      if (!redisService.isReady()) return;

      const key = `verification_attempt:${phoneNumber}`;
      const attemptData = {
        code,
        timestamp: new Date().toISOString(),
        type: 'verification'
      };

      await redisService.set(key, attemptData, 600); // 10 minutes
    } catch (error) {
      logger.error('Failed to store verification attempt:', error);
    }
  }

  /**
   * Store login attempt for tracking
   * @param {string} phoneNumber - Phone number
   * @param {string} code - Login code
   */
  async storeLoginAttempt(phoneNumber, code) {
    try {
      if (!redisService.isReady()) return;

      const key = `login_attempt:${phoneNumber}`;
      const attemptData = {
        code,
        timestamp: new Date().toISOString(),
        type: 'login'
      };

      await redisService.set(key, attemptData, 300); // 5 minutes
    } catch (error) {
      logger.error('Failed to store login attempt:', error);
    }
  }
}

// Create singleton instance
const smsService = new SMSService();

module.exports = smsService;