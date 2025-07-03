/**
 * Environment Configuration
 * Centralizes all environment variable handling with validation
 * Updated for China-compatible services with comprehensive push notification support
 */

const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../../.env') });

/**
 * Validates required environment variables
 * @param {string} key - Environment variable key
 * @param {*} defaultValue - Default value if not found
 * @returns {*} Environment variable value or default
 */
const getEnvVar = (key, defaultValue = null) => {
  const value = process.env[key];
  if (!value && defaultValue === null) {
    throw new Error(`Environment variable ${key} is required but not set`);
  }
  return value || defaultValue;
};

/**
 * Environment configuration object
 */
const config = {
  // Application settings
  NODE_ENV: getEnvVar('NODE_ENV', 'development'),
  PORT: parseInt(getEnvVar('PORT', '3000')),
  API_VERSION: getEnvVar('API_VERSION', 'v1'),

  // Database configuration (Tencent Cloud MySQL)
  database: {
    host: getEnvVar('DB_HOST'),
    port: parseInt(getEnvVar('DB_PORT', '3306')),
    name: getEnvVar('DB_NAME'),
    username: getEnvVar('DB_USER'),
    password: getEnvVar('DB_PASSWORD'),
    dialect: 'mysql',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  },

  // JWT configuration
  jwt: {
    secret: getEnvVar('JWT_SECRET'),
    refreshSecret: getEnvVar('JWT_REFRESH_SECRET'),
    expiresIn: getEnvVar('JWT_EXPIRE', '15m'),
    refreshExpiresIn: getEnvVar('JWT_REFRESH_EXPIRE', '7d')
  },

  // Redis configuration (Tencent Cloud Redis)
  redis: {
    host: getEnvVar('REDIS_HOST', 'localhost'),
    port: parseInt(getEnvVar('REDIS_PORT', '6379')),
    password: getEnvVar('REDIS_PASSWORD', ''),
    db: 0,
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3
  },

  // Alibaba Cloud SMS configuration
  alibabaCloud: {
    accessKeyId: getEnvVar('ALIBABA_ACCESS_KEY_ID'),
    accessKeySecret: getEnvVar('ALIBABA_ACCESS_KEY_SECRET'),
    smsSignName: getEnvVar('ALIBABA_SMS_SIGN_NAME'),
    smsTemplateCode: getEnvVar('ALIBABA_SMS_TEMPLATE_CODE'),
    region: getEnvVar('ALIBABA_REGION', 'cn-hangzhou')
  },

  // Tencent Cloud SMS configuration (backup)
  tencentCloud: {
    secretId: getEnvVar('TENCENT_SECRET_ID'),
    secretKey: getEnvVar('TENCENT_SECRET_KEY'),
    smsAppId: getEnvVar('TENCENT_SMS_APP_ID'),
    smsSign: getEnvVar('TENCENT_SMS_SIGN'),
    smsTemplateId: getEnvVar('TENCENT_SMS_TEMPLATE_ID'),
    region: getEnvVar('TENCENT_REGION', 'ap-beijing')
  },

  // Tencent Cloud COS (Cloud Object Storage) for file uploads
  tencentCOS: {
    secretId: getEnvVar('TENCENT_COS_SECRET_ID'),
    secretKey: getEnvVar('TENCENT_COS_SECRET_KEY'),
    bucket: getEnvVar('TENCENT_COS_BUCKET'),
    region: getEnvVar('TENCENT_COS_REGION', 'ap-beijing'),
    domain: getEnvVar('TENCENT_COS_DOMAIN')
  },

  // Alibaba Cloud OSS (Object Storage Service) for file uploads
  alibabaOSS: {
    accessKeyId: getEnvVar('ALIBABA_OSS_ACCESS_KEY_ID'),
    accessKeySecret: getEnvVar('ALIBABA_OSS_ACCESS_KEY_SECRET'),
    bucket: getEnvVar('ALIBABA_OSS_BUCKET'),
    region: getEnvVar('ALIBABA_OSS_REGION', 'oss-cn-hangzhou'),
    endpoint: getEnvVar('ALIBABA_OSS_ENDPOINT')
  },

  // WeChat Mini Program configuration
  wechat: {
    appId: getEnvVar('WECHAT_APP_ID'),
    appSecret: getEnvVar('WECHAT_APP_SECRET'),
    mchId: getEnvVar('WECHAT_MCH_ID'), // For WeChat Pay
    apiKey: getEnvVar('WECHAT_API_KEY') // For WeChat Pay
  },

  // Alipay configuration
  alipay: {
    appId: getEnvVar('ALIPAY_APP_ID'),
    privateKey: getEnvVar('ALIPAY_PRIVATE_KEY'),
    publicKey: getEnvVar('ALIPAY_PUBLIC_KEY'),
    gateway: getEnvVar('ALIPAY_GATEWAY', 'https://openapi.alipay.com/gateway.do')
  },

  // Security settings
  security: {
    bcryptRounds: parseInt(getEnvVar('BCRYPT_ROUNDS', '12')),
    rateLimitWindowMs: parseInt(getEnvVar('RATE_LIMIT_WINDOW_MS', '900000')),
    rateLimitMaxRequests: parseInt(getEnvVar('RATE_LIMIT_MAX_REQUESTS', '100'))
  },

  // File upload settings
  upload: {
    maxFileSize: parseInt(getEnvVar('MAX_FILE_SIZE', '10485760')), // 10MB
    uploadPath: getEnvVar('UPLOAD_PATH', 'uploads/'),
    provider: getEnvVar('UPLOAD_PROVIDER', 'tencent'), // 'tencent' or 'alibaba'
    cdnDomain: getEnvVar('CDN_DOMAIN')
  },

  // Push notification settings (comprehensive support for all platforms)
  push: {
    provider: getEnvVar('PUSH_PROVIDER', 'xiaomi'), // Primary provider
    
    // Xiaomi Push (Android)
    xiaomi: {
      appSecret: getEnvVar('XIAOMI_PUSH_APP_SECRET'),
      packageName: getEnvVar('XIAOMI_PUSH_PACKAGE_NAME')
    },
    
    // Huawei Push (Android)
    huawei: {
      appId: getEnvVar('HUAWEI_PUSH_APP_ID'),
      appSecret: getEnvVar('HUAWEI_PUSH_APP_SECRET')
    },
    
    // OPPO Push (Android)
    oppo: {
      appKey: getEnvVar('OPPO_PUSH_APP_KEY'),
      masterSecret: getEnvVar('OPPO_PUSH_MASTER_SECRET'),
      appSecret: getEnvVar('OPPO_PUSH_APP_SECRET')
    },
    
    // Vivo Push (Android)
    vivo: {
      appId: getEnvVar('VIVO_PUSH_APP_ID'),
      appKey: getEnvVar('VIVO_PUSH_APP_KEY'),
      appSecret: getEnvVar('VIVO_PUSH_APP_SECRET')
    },
    
    // Apple Push Notification Service (iOS)
    apns: {
      keyPath: getEnvVar('APNS_KEY_PATH'),
      keyId: getEnvVar('APNS_KEY_ID'),
      teamId: getEnvVar('APNS_TEAM_ID'),
      bundleId: getEnvVar('APNS_BUNDLE_ID'),
      production: getEnvVar('APNS_PRODUCTION', 'false') === 'true'
    }
  },

  // Analytics (using Chinese services)
  analytics: {
    provider: getEnvVar('ANALYTICS_PROVIDER', 'baidu'), // 'baidu', 'tencent'
    baidu: {
      siteId: getEnvVar('BAIDU_ANALYTICS_SITE_ID'),
      token: getEnvVar('BAIDU_ANALYTICS_TOKEN')
    },
    tencent: {
      appId: getEnvVar('TENCENT_ANALYTICS_APP_ID'),
      secretKey: getEnvVar('TENCENT_ANALYTICS_SECRET_KEY')
    }
  }
};

module.exports = config;