/**
 * Secret Rotation Utility
 * Handles JWT secret rotation for enhanced security
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { logger } = require('./config/logger');
const redisService = require('./services/redis');

/**
 * Secret Rotation Manager
 */
class SecretRotationManager {
  constructor() {
    this.rotationInterval = 24 * 60 * 60 * 1000; // 24 hours
    this.gracePeriod = 60 * 60 * 1000; // 1 hour grace period
    this.secretsFile = path.join(__dirname, '../.secrets.json');
  }

  /**
   * Generate new secret
   * @returns {string} New secret
   */
  generateSecret() {
    return crypto.randomBytes(64).toString('hex');
  }

  /**
   * Load secrets from file
   * @returns {Promise<Object>} Secrets object
   */
  async loadSecrets() {
    try {
      const data = await fs.readFile(this.secretsFile, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        // File doesn't exist, create initial secrets
        return await this.createInitialSecrets();
      }
      throw error;
    }
  }

  /**
   * Save secrets to file
   * @param {Object} secrets - Secrets object
   */
  async saveSecrets(secrets) {
    await fs.writeFile(this.secretsFile, JSON.stringify(secrets, null, 2));
  }

  /**
   * Create initial secrets
   * @returns {Promise<Object>} Initial secrets
   */
  async createInitialSecrets() {
    const secrets = {
      current: {
        jwt: this.generateSecret(),
        refresh: this.generateSecret(),
        createdAt: new Date().toISOString()
      },
      previous: null,
      rotationHistory: []
    };

    await this.saveSecrets(secrets);
    logger.info('Initial secrets created');
    return secrets;
  }

  /**
   * Rotate JWT secrets
   * @returns {Promise<Object>} New secrets
   */
  async rotateSecrets() {
    try {
      const secrets = await this.loadSecrets();
      
      // Move current to previous
      const newSecrets = {
        current: {
          jwt: this.generateSecret(),
          refresh: this.generateSecret(),
          createdAt: new Date().toISOString()
        },
        previous: secrets.current,
        rotationHistory: [
          ...secrets.rotationHistory.slice(-9), // Keep last 10 rotations
          {
            rotatedAt: new Date().toISOString(),
            previousSecret: secrets.current?.jwt?.substring(0, 8) + '...' // Log partial for audit
          }
        ]
      };

      await this.saveSecrets(newSecrets);

      // Store rotation info in Redis for distributed systems
      if (redisService.isReady()) {
        await redisService.set('secret_rotation:last', new Date().toISOString(), 86400);
        await redisService.set('secret_rotation:current_id', newSecrets.current.createdAt, 86400);
      }

      logger.info('JWT secrets rotated successfully', {
        rotationTime: newSecrets.current.createdAt,
        previousSecretAge: secrets.current ? 
          Date.now() - new Date(secrets.current.createdAt).getTime() : 0
      });

      return newSecrets;
    } catch (error) {
      logger.error('Secret rotation failed:', error);
      throw error;
    }
  }

  /**
   * Get current secrets
   * @returns {Promise<Object>} Current secrets
   */
  async getCurrentSecrets() {
    const secrets = await this.loadSecrets();
    return secrets.current;
  }

  /**
   * Get previous secrets (for grace period)
   * @returns {Promise<Object|null>} Previous secrets
   */
  async getPreviousSecrets() {
    const secrets = await this.loadSecrets();
    
    if (!secrets.previous) {
      return null;
    }

    // Check if previous secrets are still within grace period
    const previousAge = Date.now() - new Date(secrets.previous.createdAt).getTime();
    if (previousAge > this.gracePeriod) {
      return null;
    }

    return secrets.previous;
  }

  /**
   * Check if rotation is needed
   * @returns {Promise<boolean>} Whether rotation is needed
   */
  async needsRotation() {
    try {
      const secrets = await this.loadSecrets();
      
      if (!secrets.current) {
        return true;
      }

      const age = Date.now() - new Date(secrets.current.createdAt).getTime();
      return age > this.rotationInterval;
    } catch (error) {
      logger.error('Error checking rotation need:', error);
      return false;
    }
  }

  /**
   * Start automatic rotation
   */
  startAutomaticRotation() {
    const checkInterval = 60 * 60 * 1000; // Check every hour

    setInterval(async () => {
      try {
        if (await this.needsRotation()) {
          logger.info('Automatic secret rotation triggered');
          await this.rotateSecrets();
        }
      } catch (error) {
        logger.error('Automatic rotation failed:', error);
      }
    }, checkInterval);

    logger.info('Automatic secret rotation started', {
      checkInterval: checkInterval / 1000 / 60,
      rotationInterval: this.rotationInterval / 1000 / 60 / 60
    });
  }

  /**
   * Validate secret format
   * @param {string} secret - Secret to validate
   * @returns {boolean} Whether secret is valid
   */
  validateSecret(secret) {
    return typeof secret === 'string' && secret.length >= 64;
  }

  /**
   * Get rotation statistics
   * @returns {Promise<Object>} Rotation statistics
   */
  async getRotationStats() {
    try {
      const secrets = await this.loadSecrets();
      
      return {
        currentSecretAge: secrets.current ? 
          Date.now() - new Date(secrets.current.createdAt).getTime() : 0,
        totalRotations: secrets.rotationHistory.length,
        lastRotation: secrets.rotationHistory.length > 0 ? 
          secrets.rotationHistory[secrets.rotationHistory.length - 1].rotatedAt : null,
        nextRotationDue: secrets.current ? 
          new Date(new Date(secrets.current.createdAt).getTime() + this.rotationInterval).toISOString() : null
      };
    } catch (error) {
      logger.error('Error getting rotation stats:', error);
      return null;
    }
  }

  /**
   * Force rotation (manual trigger)
   * @returns {Promise<Object>} New secrets
   */
  async forceRotation() {
    logger.info('Manual secret rotation triggered');
    return await this.rotateSecrets();
  }

  /**
   * Cleanup old secrets
   */
  async cleanupOldSecrets() {
    try {
      const secrets = await this.loadSecrets();
      
      // Remove previous secrets if they're too old
      if (secrets.previous) {
        const previousAge = Date.now() - new Date(secrets.previous.createdAt).getTime();
        if (previousAge > this.gracePeriod * 2) {
          secrets.previous = null;
          await this.saveSecrets(secrets);
          logger.info('Old previous secrets cleaned up');
        }
      }

      // Cleanup Redis keys
      if (redisService.isReady()) {
        const keys = await redisService.client.keys('blacklisted_token:*');
        let cleanedCount = 0;
        
        for (const key of keys) {
          const ttl = await redisService.ttl(key);
          if (ttl <= 0) {
            await redisService.del(key);
            cleanedCount++;
          }
        }
        
        if (cleanedCount > 0) {
          logger.info(`Cleaned up ${cleanedCount} expired blacklisted tokens`);
        }
      }
    } catch (error) {
      logger.error('Error during cleanup:', error);
    }
  }
}

// Create singleton instance
const secretRotationManager = new SecretRotationManager();

/**
 * Initialize secret rotation
 */
async function initializeSecretRotation() {
  try {
    // Ensure secrets exist
    await secretRotationManager.loadSecrets();
    
    // Start automatic rotation
    secretRotationManager.startAutomaticRotation();
    
    // Schedule cleanup
    setInterval(() => {
      secretRotationManager.cleanupOldSecrets();
    }, 6 * 60 * 60 * 1000); // Every 6 hours
    
    logger.info('Secret rotation system initialized');
  } catch (error) {
    logger.error('Failed to initialize secret rotation:', error);
  }
}

module.exports = {
  SecretRotationManager,
  secretRotationManager,
  initializeSecretRotation
};