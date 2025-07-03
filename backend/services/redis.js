/**
 * Redis Service
 * Handles Redis connection and operations for caching, sessions, and rate limiting
 */

const Redis = require('redis');
const config = require('../config/env');
const { logger } = require('../config/logger');

/**
 * Redis Client Manager
 */
class RedisService {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  /**
   * Initialize Redis connection
   * @returns {Promise<void>}
   */
  async connect() {
    try {
      this.client = Redis.createClient({
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.db,
        retryDelayOnFailover: config.redis.retryDelayOnFailover,
        maxRetriesPerRequest: config.redis.maxRetriesPerRequest,
        lazyConnect: true,
        retryStrategy: (times) => {
          const delay = Math.min(times * 50, 2000);
          logger.warn(`Redis reconnection attempt ${times}, delay: ${delay}ms`);
          return delay;
        }
      });

      // Event listeners
      this.client.on('connect', () => {
        logger.info('Redis client connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
      });

      this.client.on('ready', () => {
        logger.info('Redis client ready');
      });

      this.client.on('error', (error) => {
        logger.error('Redis client error:', error);
        this.isConnected = false;
      });

      this.client.on('end', () => {
        logger.warn('Redis client connection ended');
        this.isConnected = false;
      });

      this.client.on('reconnecting', () => {
        this.reconnectAttempts++;
        logger.info(`Redis client reconnecting (attempt ${this.reconnectAttempts})`);
        
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
          logger.error('Max Redis reconnection attempts reached');
          this.client.disconnect();
        }
      });

      await this.client.connect();
      logger.info('Redis service initialized successfully');

    } catch (error) {
      logger.error('Failed to initialize Redis service:', error);
      throw error;
    }
  }

  /**
   * Disconnect from Redis
   * @returns {Promise<void>}
   */
  async disconnect() {
    try {
      if (this.client && this.isConnected) {
        await this.client.disconnect();
        logger.info('Redis client disconnected');
      }
    } catch (error) {
      logger.error('Error disconnecting Redis client:', error);
    }
  }

  /**
   * Check if Redis is connected
   * @returns {boolean} Connection status
   */
  isReady() {
    return this.isConnected && this.client && this.client.isReady;
  }

  /**
   * Set key-value pair with optional expiration
   * @param {string} key - Redis key
   * @param {*} value - Value to store
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<string>} Redis response
   */
  async set(key, value, ttl = null) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value;
      
      if (ttl) {
        return await this.client.setEx(key, ttl, serializedValue);
      } else {
        return await this.client.set(key, serializedValue);
      }
    } catch (error) {
      logger.error(`Redis SET error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get value by key
   * @param {string} key - Redis key
   * @param {boolean} parseJson - Whether to parse as JSON
   * @returns {Promise<*>} Retrieved value
   */
  async get(key, parseJson = false) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const value = await this.client.get(key);
      
      if (value === null) {
        return null;
      }

      if (parseJson) {
        try {
          return JSON.parse(value);
        } catch (parseError) {
          logger.warn(`Failed to parse JSON for key ${key}:`, parseError);
          return value;
        }
      }

      return value;
    } catch (error) {
      logger.error(`Redis GET error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Delete key
   * @param {string} key - Redis key
   * @returns {Promise<number>} Number of keys deleted
   */
  async del(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.del(key);
    } catch (error) {
      logger.error(`Redis DEL error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Check if key exists
   * @param {string} key - Redis key
   * @returns {Promise<boolean>} Whether key exists
   */
  async exists(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const result = await this.client.exists(key);
      return result === 1;
    } catch (error) {
      logger.error(`Redis EXISTS error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Set expiration for key
   * @param {string} key - Redis key
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Whether expiration was set
   */
  async expire(key, ttl) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const result = await this.client.expire(key, ttl);
      return result === 1;
    } catch (error) {
      logger.error(`Redis EXPIRE error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get time to live for key
   * @param {string} key - Redis key
   * @returns {Promise<number>} TTL in seconds (-1 if no expiration, -2 if key doesn't exist)
   */
  async ttl(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.ttl(key);
    } catch (error) {
      logger.error(`Redis TTL error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Increment key value
   * @param {string} key - Redis key
   * @returns {Promise<number>} New value after increment
   */
  async incr(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.incr(key);
    } catch (error) {
      logger.error(`Redis INCR error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Decrement key value
   * @param {string} key - Redis key
   * @returns {Promise<number>} New value after decrement
   */
  async decr(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.decr(key);
    } catch (error) {
      logger.error(`Redis DECR error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Add item to set
   * @param {string} key - Redis key
   * @param {*} member - Member to add
   * @returns {Promise<number>} Number of members added
   */
  async sadd(key, member) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.sAdd(key, member);
    } catch (error) {
      logger.error(`Redis SADD error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Remove item from set
   * @param {string} key - Redis key
   * @param {*} member - Member to remove
   * @returns {Promise<number>} Number of members removed
   */
  async srem(key, member) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.sRem(key, member);
    } catch (error) {
      logger.error(`Redis SREM error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Check if member exists in set
   * @param {string} key - Redis key
   * @param {*} member - Member to check
   * @returns {Promise<boolean>} Whether member exists in set
   */
  async sismember(key, member) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const result = await this.client.sIsMember(key, member);
      return result === 1;
    } catch (error) {
      logger.error(`Redis SISMEMBER error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get all members of set
   * @param {string} key - Redis key
   * @returns {Promise<Array>} Set members
   */
  async smembers(key) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.sMembers(key);
    } catch (error) {
      logger.error(`Redis SMEMBERS error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Push item to list (left)
   * @param {string} key - Redis key
   * @param {*} value - Value to push
   * @returns {Promise<number>} New length of list
   */
  async lpush(key, value) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value;
      return await this.client.lPush(key, serializedValue);
    } catch (error) {
      logger.error(`Redis LPUSH error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Pop item from list (right)
   * @param {string} key - Redis key
   * @param {boolean} parseJson - Whether to parse as JSON
   * @returns {Promise<*>} Popped value
   */
  async rpop(key, parseJson = false) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const value = await this.client.rPop(key);
      
      if (value === null) {
        return null;
      }

      if (parseJson) {
        try {
          return JSON.parse(value);
        } catch (parseError) {
          logger.warn(`Failed to parse JSON for key ${key}:`, parseError);
          return value;
        }
      }

      return value;
    } catch (error) {
      logger.error(`Redis RPOP error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Get list range
   * @param {string} key - Redis key
   * @param {number} start - Start index
   * @param {number} stop - Stop index
   * @param {boolean} parseJson - Whether to parse items as JSON
   * @returns {Promise<Array>} List items
   */
  async lrange(key, start = 0, stop = -1, parseJson = false) {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      const values = await this.client.lRange(key, start, stop);
      
      if (parseJson) {
        return values.map(value => {
          try {
            return JSON.parse(value);
          } catch (parseError) {
            logger.warn(`Failed to parse JSON item in list ${key}:`, parseError);
            return value;
          }
        });
      }

      return values;
    } catch (error) {
      logger.error(`Redis LRANGE error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Flush all data from current database
   * @returns {Promise<string>} Redis response
   */
  async flushdb() {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      logger.warn('Flushing Redis database');
      return await this.client.flushDb();
    } catch (error) {
      logger.error('Redis FLUSHDB error:', error);
      throw error;
    }
  }

  /**
   * Get Redis info
   * @returns {Promise<string>} Redis info
   */
  async info() {
    try {
      if (!this.isReady()) {
        throw new Error('Redis client not ready');
      }

      return await this.client.info();
    } catch (error) {
      logger.error('Redis INFO error:', error);
      throw error;
    }
  }
}

// Create singleton instance
const redisService = new RedisService();

module.exports = redisService;