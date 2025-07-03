/**
 * Server Entry Point
 * Initializes database, services, and starts the HTTP server
 * Updated for China-compatible services with comprehensive push notification support
 */

const http = require('http');
const app = require('./app');
const config = require('./config/env');
const { logger } = require('./config/logger');
const { initializeDatabase, testConnection } = require('./config/db');
const redisService = require('./services/redis');
const socketService = require('./services/socket');
const smsService = require('./services/sms');
const storageService = require('./services/storage');
const pushService = require('./services/push');
const paymentService = require('./services/payment');
const analyticsService = require('./services/analytics');
const { initializeSecretRotation } = require('./secret_rotation');

/**
 * Normalize port number
 * @param {string|number} val - Port value
 * @returns {number|string|boolean} Normalized port
 */
function normalizePort(val) {
  const port = parseInt(val, 10);

  if (isNaN(port)) {
    return val; // Named pipe
  }

  if (port >= 0) {
    return port; // Port number
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event
 * @param {Error} error - Server error
 */
function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  const bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;

  switch (error.code) {
    case 'EACCES':
      logger.error(`${bind} requires elevated privileges`);
      process.exit(1);
      break;
    case 'EADDRINUSE':
      logger.error(`${bind} is already in use`);
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event
 */
function onListening() {
  const addr = server.address();
  const bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
  logger.info(`Server listening on ${bind}`);
  logger.info(`Environment: ${config.NODE_ENV}`);
  logger.info(`API Version: ${config.API_VERSION}`);
  logger.info('🇨🇳 China-compatible services enabled');
}

/**
 * Initialize all services
 */
async function initializeServices() {
  try {
    logger.info('Initializing services...');

    // Test database connection
    logger.info('Testing database connection...');
    const dbConnected = await testConnection();
    if (!dbConnected) {
      throw new Error('Database connection failed');
    }

    // Initialize database (create tables, associations)
    logger.info('Initializing database...');
    await initializeDatabase();

    // Initialize Redis service
    logger.info('Initializing Redis service...');
    try {
      await redisService.connect();
    } catch (error) {
      logger.warn('Redis connection failed, continuing without Redis:', error.message);
    }

    // Initialize secret rotation system
    logger.info('Initializing secret rotation...');
    await initializeSecretRotation();

    // Check SMS service availability
    logger.info('Checking SMS service...');
    if (smsService.isAvailable()) {
      logger.info('SMS service is available (Alibaba Cloud + Tencent Cloud)');
    } else {
      logger.warn('SMS service is not configured');
    }

    // Check storage service availability
    logger.info('Checking storage service...');
    if (storageService.isAvailable()) {
      logger.info('Storage service is available (Tencent COS + Alibaba OSS)');
    } else {
      logger.warn('Storage service is not configured');
    }

    // Check push notification service availability
    logger.info('Checking push notification service...');
    if (pushService.isAvailable()) {
      const stats = pushService.getStats();
      logger.info('Push notification service is available:', {
        providers: stats.availableProviders,
        android: stats.supportedPlatforms.android,
        ios: stats.supportedPlatforms.ios
      });
    } else {
      logger.warn('Push notification service is not configured');
    }

    // Check payment service availability
    logger.info('Checking payment service...');
    if (paymentService.isAvailable()) {
      logger.info('Payment service is available (WeChat Pay + Alipay)');
    } else {
      logger.warn('Payment service is not configured');
    }

    // Check analytics service availability
    logger.info('Checking analytics service...');
    if (analyticsService.isAvailable()) {
      logger.info('Analytics service is available (Baidu + Tencent)');
      // Start background processing for analytics
      analyticsService.startBackgroundProcessing();
    } else {
      logger.warn('Analytics service is not configured');
    }

    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Service initialization failed:', error);
    throw error;
  }
}

/**
 * Start the server
 */
async function startServer() {
  try {
    // Initialize services first
    await initializeServices();

    // Get port from environment and store in Express
    const port = normalizePort(config.PORT);
    app.set('port', port);

    // Create HTTP server
    const server = http.createServer(app);

    // Initialize Socket.IO
    logger.info('Initializing Socket.IO...');
    socketService.initialize(server);

    // Listen on provided port, on all network interfaces
    server.listen(port);
    server.on('error', onError);
    server.on('listening', onListening);

    // Store server reference for graceful shutdown
    app.server = server;

    // Log startup success
    logger.info('🚀 SilverApp Backend started successfully! (China Edition)');
    logger.info(`📱 API available at: http://localhost:${port}/api/${config.API_VERSION}`);
    logger.info(`🏥 Health check: http://localhost:${port}/health`);
    logger.info('🔐 JWT secret rotation enabled');
    logger.info('☁️  Multi-cloud storage ready (Tencent + Alibaba)');
    logger.info('💰 Payment systems ready (WeChat Pay + Alipay)');
    logger.info('📊 Analytics tracking enabled (Baidu + Tencent)');
    logger.info('📲 Push notifications ready (Xiaomi + Huawei + OPPO + Vivo + APNs)');
    
    return server;
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', err);
  process.exit(1);
});

/**
 * Graceful shutdown
 */
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);

  try {
    // Close Redis connection
    if (redisService.isReady()) {
      logger.info('Closing Redis connection...');
      await redisService.disconnect();
    }

    // Close database connection
    logger.info('Closing database connection...');
    const { closeConnection } = require('./config/db');
    await closeConnection();

    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start the server if this file is run directly
if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };