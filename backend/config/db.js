/**
 * Database Configuration and Connection
 * Sets up Sequelize ORM with MySQL database
 */

const { Sequelize } = require('sequelize');
const config = require('./env');
const { logger } = require('./logger');

/**
 * Create Sequelize instance with configuration
 */
const sequelize = new Sequelize(
  config.database.name,
  config.database.username,
  config.database.password,
  {
    host: config.database.host,
    port: config.database.port,
    dialect: config.database.dialect,
    logging: config.database.logging,
    pool: config.database.pool,
    
    // Additional options for better performance and security
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    },
    
    // Timezone configuration
    timezone: '+00:00',
    
    // Query options
    query: {
      raw: false
    },
    
    // Retry configuration
    retry: {
      max: 3,
      timeout: 5000,
      match: [
        /ETIMEDOUT/,
        /EHOSTUNREACH/,
        /ECONNRESET/,
        /ECONNREFUSED/,
        /TIMEOUT/,
        /ESOCKETTIMEDOUT/,
        /EHOSTUNREACH/,
        /EPIPE/,
        /EAI_AGAIN/,
        /SequelizeConnectionError/,
        /SequelizeConnectionRefusedError/,
        /SequelizeHostNotFoundError/,
        /SequelizeHostNotReachableError/,
        /SequelizeInvalidConnectionError/,
        /SequelizeConnectionTimedOutError/
      ]
    }
  }
);

/**
 * Test database connection
 * @returns {Promise<boolean>} Connection status
 */
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('Database connection established successfully');
    return true;
  } catch (error) {
    logger.error('Unable to connect to database:', error);
    return false;
  }
};

/**
 * Initialize database with models and associations
 * @returns {Promise<void>}
 */
const initializeDatabase = async () => {
  try {
    // Import all models
    const User = require('../models/User');
    const Post = require('../models/Post');
    const Friend = require('../models/Friend');
    const Message = require('../models/Message');
    const Notification = require('../models/Notification');
    const PaymentOrder = require('../models/PaymentOrder');
    const Gift = require('../models/Gift');
    const CurrencyTransaction = require('../models/CurrencyTransaction');

    // Define associations
    setupAssociations();

    // Sync database (create tables if they don't exist)
    if (config.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
      logger.info('Database synchronized successfully');
    } else {
      await sequelize.sync();
      logger.info('Database connection verified');
    }

  } catch (error) {
    logger.error('Database initialization failed:', error);
    throw error;
  }
};

/**
 * Setup model associations
 */
const setupAssociations = () => {
  const User = require('../models/User');
  const Post = require('../models/Post');
  const Friend = require('../models/Friend');
  const Message = require('../models/Message');
  const Notification = require('../models/Notification');
  const PaymentOrder = require('../models/PaymentOrder');
  const Gift = require('../models/Gift');
  const CurrencyTransaction = require('../models/CurrencyTransaction');

  // User associations
  User.hasMany(Post, { foreignKey: 'user_id', as: 'posts' });
  User.hasMany(Notification, { foreignKey: 'user_id', as: 'notifications' });
  User.hasMany(PaymentOrder, { foreignKey: 'userId', as: 'paymentOrders' });
  User.hasMany(Gift, { foreignKey: 'senderId', as: 'sentGifts' });
  User.hasMany(Gift, { foreignKey: 'recipientId', as: 'receivedGifts' });
  User.hasMany(CurrencyTransaction, { foreignKey: 'userId', as: 'currencyTransactions' });
  
  // Friend associations
  User.belongsToMany(User, {
    through: Friend,
    as: 'friends',
    foreignKey: 'user_id',
    otherKey: 'friend_id'
  });

  // Post associations
  Post.belongsTo(User, { foreignKey: 'user_id', as: 'author' });
  Post.hasMany(Post, { foreignKey: 'parent_id', as: 'comments' });
  Post.belongsTo(Post, { foreignKey: 'parent_id', as: 'parent' });

  // Message associations
  Message.belongsTo(User, { foreignKey: 'sender_id', as: 'sender' });
  Message.belongsTo(User, { foreignKey: 'receiver_id', as: 'receiver' });

  // Notification associations
  Notification.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
  Notification.belongsTo(User, { foreignKey: 'from_user_id', as: 'fromUser' });

  // PaymentOrder associations
  PaymentOrder.belongsTo(User, { foreignKey: 'userId', as: 'user' });

  // Gift associations
  Gift.belongsTo(User, { foreignKey: 'senderId', as: 'sender' });
  Gift.belongsTo(User, { foreignKey: 'recipientId', as: 'recipient' });

  // CurrencyTransaction associations
  CurrencyTransaction.belongsTo(User, { foreignKey: 'userId', as: 'user' });

  logger.info('Model associations established');
};

/**
 * Close database connection gracefully
 * @returns {Promise<void>}
 */
const closeConnection = async () => {
  try {
    await sequelize.close();
    logger.info('Database connection closed successfully');
  } catch (error) {
    logger.error('Error closing database connection:', error);
  }
};

/**
 * Handle database connection events
 */
sequelize.addHook('beforeConnect', () => {
  logger.debug('Attempting to connect to database...');
});

sequelize.addHook('afterConnect', () => {
  logger.debug('Database connection established');
});

sequelize.addHook('beforeDisconnect', () => {
  logger.debug('Disconnecting from database...');
});

module.exports = {
  sequelize,
  testConnection,
  initializeDatabase,
  closeConnection
};