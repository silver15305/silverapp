/**
 * Cloud Storage Service
 * Handles file uploads using Tencent Cloud COS and Alibaba Cloud OSS
 * China-compatible cloud storage services
 */

const COS = require('cos-nodejs-sdk-v5');
const OSS = require('ali-oss');
const path = require('path');
const crypto = require('crypto');
const config = require('../config/env');
const { logger } = require('../config/logger');

/**
 * Cloud Storage Service Class
 */
class StorageService {
  constructor() {
    this.cosClient = null;
    this.ossClient = null;
    this.provider = config.upload.provider || 'tencent';
    this.isInitialized = false;
    this.init();
  }

  /**
   * Initialize storage clients
   */
  init() {
    try {
      // Initialize Tencent Cloud COS client
      if (config.tencentCOS.secretId && config.tencentCOS.secretKey) {
        this.cosClient = new COS({
          SecretId: config.tencentCOS.secretId,
          SecretKey: config.tencentCOS.secretKey,
          FileParallelLimit: 3,
          ChunkParallelLimit: 8,
          ChunkSize: 1024 * 1024 * 8, // 8MB
        });
        logger.info('Tencent Cloud COS client initialized');
      }

      // Initialize Alibaba Cloud OSS client
      if (config.alibabaOSS.accessKeyId && config.alibabaOSS.accessKeySecret) {
        this.ossClient = new OSS({
          region: config.alibabaOSS.region,
          accessKeyId: config.alibabaOSS.accessKeyId,
          accessKeySecret: config.alibabaOSS.accessKeySecret,
          bucket: config.alibabaOSS.bucket,
        });
        logger.info('Alibaba Cloud OSS client initialized');
      }

      this.isInitialized = true;
      logger.info('Storage service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize storage service:', error);
    }
  }

  /**
   * Check if storage service is available
   * @returns {boolean} Service availability
   */
  isAvailable() {
    return this.isInitialized && (this.cosClient !== null || this.ossClient !== null);
  }

  /**
   * Generate unique file key
   * @param {string} originalName - Original file name
   * @param {string} userId - User ID
   * @param {string} type - File type (avatar, post, message, etc.)
   * @returns {string} Unique file key
   */
  generateFileKey(originalName, userId, type = 'general') {
    const ext = path.extname(originalName);
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    const date = new Date().toISOString().split('T')[0];
    
    return `${type}/${date}/${userId}/${timestamp}_${random}${ext}`;
  }

  /**
   * Upload file to Tencent Cloud COS
   * @param {Buffer} fileBuffer - File buffer
   * @param {string} key - File key
   * @param {string} contentType - File content type
   * @returns {Promise<Object>} Upload result
   */
  async uploadToCOS(fileBuffer, key, contentType) {
    try {
      if (!this.cosClient) {
        throw new Error('Tencent Cloud COS client not initialized');
      }

      const result = await this.cosClient.putObject({
        Bucket: config.tencentCOS.bucket,
        Region: config.tencentCOS.region,
        Key: key,
        Body: fileBuffer,
        ContentType: contentType,
        ACL: 'public-read',
        Headers: {
          'Cache-Control': 'max-age=31536000' // 1 year cache
        }
      });

      const url = config.tencentCOS.domain 
        ? `https://${config.tencentCOS.domain}/${key}`
        : `https://${config.tencentCOS.bucket}.cos.${config.tencentCOS.region}.myqcloud.com/${key}`;

      logger.info('File uploaded to Tencent COS successfully:', {
        key,
        size: fileBuffer.length,
        etag: result.ETag
      });

      return {
        success: true,
        url,
        key,
        provider: 'tencent',
        etag: result.ETag,
        size: fileBuffer.length
      };

    } catch (error) {
      logger.error('Tencent COS upload failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Upload file to Alibaba Cloud OSS
   * @param {Buffer} fileBuffer - File buffer
   * @param {string} key - File key
   * @param {string} contentType - File content type
   * @returns {Promise<Object>} Upload result
   */
  async uploadToOSS(fileBuffer, key, contentType) {
    try {
      if (!this.ossClient) {
        throw new Error('Alibaba Cloud OSS client not initialized');
      }

      const result = await this.ossClient.put(key, fileBuffer, {
        headers: {
          'Content-Type': contentType,
          'Cache-Control': 'max-age=31536000' // 1 year cache
        }
      });

      const url = config.alibabaOSS.endpoint 
        ? `https://${config.alibabaOSS.endpoint}/${key}`
        : result.url;

      logger.info('File uploaded to Alibaba OSS successfully:', {
        key,
        size: fileBuffer.length,
        etag: result.etag
      });

      return {
        success: true,
        url,
        key,
        provider: 'alibaba',
        etag: result.etag,
        size: fileBuffer.length
      };

    } catch (error) {
      logger.error('Alibaba OSS upload failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Upload file with fallback mechanism
   * @param {Buffer} fileBuffer - File buffer
   * @param {string} originalName - Original file name
   * @param {string} userId - User ID
   * @param {string} type - File type
   * @param {string} contentType - File content type
   * @returns {Promise<Object>} Upload result
   */
  async uploadFile(fileBuffer, originalName, userId, type = 'general', contentType) {
    try {
      if (!this.isAvailable()) {
        throw new Error('Storage service not available');
      }

      const key = this.generateFileKey(originalName, userId, type);
      let result;

      // Use primary provider
      if (this.provider === 'tencent' && this.cosClient) {
        result = await this.uploadToCOS(fileBuffer, key, contentType);
        
        if (result.success) {
          return result;
        }
      } else if (this.provider === 'alibaba' && this.ossClient) {
        result = await this.uploadToOSS(fileBuffer, key, contentType);
        
        if (result.success) {
          return result;
        }
      }

      // Fallback to alternative provider
      if (this.provider === 'tencent' && this.ossClient) {
        result = await this.uploadToOSS(fileBuffer, key, contentType);
      } else if (this.provider === 'alibaba' && this.cosClient) {
        result = await this.uploadToCOS(fileBuffer, key, contentType);
      }

      if (result && result.success) {
        return result;
      }

      throw new Error('All storage providers failed');

    } catch (error) {
      logger.error('File upload failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Delete file from Tencent Cloud COS
   * @param {string} key - File key
   * @returns {Promise<Object>} Delete result
   */
  async deleteFromCOS(key) {
    try {
      if (!this.cosClient) {
        throw new Error('Tencent Cloud COS client not initialized');
      }

      await this.cosClient.deleteObject({
        Bucket: config.tencentCOS.bucket,
        Region: config.tencentCOS.region,
        Key: key
      });

      logger.info('File deleted from Tencent COS successfully:', { key });

      return {
        success: true,
        key,
        provider: 'tencent'
      };

    } catch (error) {
      logger.error('Tencent COS delete failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Delete file from Alibaba Cloud OSS
   * @param {string} key - File key
   * @returns {Promise<Object>} Delete result
   */
  async deleteFromOSS(key) {
    try {
      if (!this.ossClient) {
        throw new Error('Alibaba Cloud OSS client not initialized');
      }

      await this.ossClient.delete(key);

      logger.info('File deleted from Alibaba OSS successfully:', { key });

      return {
        success: true,
        key,
        provider: 'alibaba'
      };

    } catch (error) {
      logger.error('Alibaba OSS delete failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Delete file
   * @param {string} key - File key
   * @param {string} provider - Storage provider
   * @returns {Promise<Object>} Delete result
   */
  async deleteFile(key, provider = null) {
    try {
      if (!provider) {
        provider = this.provider;
      }

      let result;

      if (provider === 'tencent' && this.cosClient) {
        result = await this.deleteFromCOS(key);
      } else if (provider === 'alibaba' && this.ossClient) {
        result = await this.deleteFromOSS(key);
      } else {
        throw new Error('Invalid provider or client not available');
      }

      return result;

    } catch (error) {
      logger.error('File delete failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Generate presigned URL for direct upload
   * @param {string} key - File key
   * @param {number} expires - Expiration time in seconds
   * @returns {Promise<Object>} Presigned URL result
   */
  async generatePresignedUrl(key, expires = 3600) {
    try {
      let result;

      if (this.provider === 'tencent' && this.cosClient) {
        const url = this.cosClient.getObjectUrl({
          Bucket: config.tencentCOS.bucket,
          Region: config.tencentCOS.region,
          Key: key,
          Sign: true,
          Expires: expires
        });

        result = {
          success: true,
          url,
          key,
          provider: 'tencent',
          expires: new Date(Date.now() + expires * 1000)
        };

      } else if (this.provider === 'alibaba' && this.ossClient) {
        const url = this.ossClient.signatureUrl(key, {
          expires: expires,
          method: 'PUT'
        });

        result = {
          success: true,
          url,
          key,
          provider: 'alibaba',
          expires: new Date(Date.now() + expires * 1000)
        };

      } else {
        throw new Error('No storage provider available');
      }

      logger.info('Presigned URL generated successfully:', {
        key,
        provider: result.provider,
        expires: result.expires
      });

      return result;

    } catch (error) {
      logger.error('Presigned URL generation failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get file info
   * @param {string} key - File key
   * @param {string} provider - Storage provider
   * @returns {Promise<Object>} File info
   */
  async getFileInfo(key, provider = null) {
    try {
      if (!provider) {
        provider = this.provider;
      }

      let result;

      if (provider === 'tencent' && this.cosClient) {
        const info = await this.cosClient.headObject({
          Bucket: config.tencentCOS.bucket,
          Region: config.tencentCOS.region,
          Key: key
        });

        result = {
          success: true,
          key,
          size: parseInt(info.headers['content-length']),
          contentType: info.headers['content-type'],
          lastModified: new Date(info.headers['last-modified']),
          etag: info.headers.etag,
          provider: 'tencent'
        };

      } else if (provider === 'alibaba' && this.ossClient) {
        const info = await this.ossClient.head(key);

        result = {
          success: true,
          key,
          size: parseInt(info.res.headers['content-length']),
          contentType: info.res.headers['content-type'],
          lastModified: new Date(info.res.headers['last-modified']),
          etag: info.res.headers.etag,
          provider: 'alibaba'
        };

      } else {
        throw new Error('Invalid provider or client not available');
      }

      return result;

    } catch (error) {
      logger.error('Get file info failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * List files in directory
   * @param {string} prefix - Directory prefix
   * @param {number} maxKeys - Maximum number of keys to return
   * @returns {Promise<Object>} File list
   */
  async listFiles(prefix = '', maxKeys = 1000) {
    try {
      let result;

      if (this.provider === 'tencent' && this.cosClient) {
        const data = await this.cosClient.getBucket({
          Bucket: config.tencentCOS.bucket,
          Region: config.tencentCOS.region,
          Prefix: prefix,
          MaxKeys: maxKeys
        });

        result = {
          success: true,
          files: data.Contents.map(item => ({
            key: item.Key,
            size: parseInt(item.Size),
            lastModified: new Date(item.LastModified),
            etag: item.ETag
          })),
          provider: 'tencent'
        };

      } else if (this.provider === 'alibaba' && this.ossClient) {
        const data = await this.ossClient.list({
          prefix: prefix,
          'max-keys': maxKeys
        });

        result = {
          success: true,
          files: data.objects.map(item => ({
            key: item.name,
            size: item.size,
            lastModified: new Date(item.lastModified),
            etag: item.etag
          })),
          provider: 'alibaba'
        };

      } else {
        throw new Error('No storage provider available');
      }

      return result;

    } catch (error) {
      logger.error('List files failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

// Create singleton instance
const storageService = new StorageService();

module.exports = storageService;