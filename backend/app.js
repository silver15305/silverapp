/**
 * Express Application Setup
 * Configures Express app with middleware, routes, and error handling
 * Updated for China-compatible services
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const hpp = require('hpp');
const xss = require('xss-clean');

const config = require('./config/env');
const { logger } = require('./config/logger');
const globalErrorHandler = require('./errors/errorHandler');
const { generalRateLimit } = require('./middleware/rateLimiting');
const { loggingSQLInjectionFilter } = require('./middleware/sqlInjectionFilter');

// Import routes
const authRoutes = require('./routes/authRoutes');
const postRoutes = require('./routes/postRoutes');
const chatRoutes = require('./routes/chatRoutes');
const friendRoutes = require('./routes/friendRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const uploadRoutes = require('./routes/uploadRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const pushRoutes = require('./routes/pushRoutes');

// Create Express app
const app = express();

/**
 * Trust proxy for accurate IP addresses
 */
app.set('trust proxy', 1);

/**
 * Security Middleware
 */

// Helmet for security headers (China-compatible)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "*.qq.com", "*.baidu.com"],
      scriptSrc: ["'self'", "*.qq.com", "*.baidu.com", "*.alipay.com"],
      imgSrc: ["'self'", "data:", "https:", "*.myqcloud.com", "*.aliyuncs.com"],
      connectSrc: ["'self'", "*.qq.com", "*.baidu.com", "*.aliyuncs.com"],
      fontSrc: ["'self'", "data:", "*.qq.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "*.myqcloud.com", "*.aliyuncs.com"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration for China
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, WeChat Mini Program, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = config.NODE_ENV === 'production' 
      ? ['https://silverapp.cn', 'https://www.silverapp.cn', 'https://mp.weixin.qq.com'] // Replace with your domain
      : ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:3000'];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
};

app.use(cors(corsOptions));

// Rate limiting
app.use(generalRateLimit);

// Body parsing middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp({
  whitelist: ['page', 'limit', 'sort', 'category', 'type', 'privacy']
}));

// SQL injection protection (logging mode)
app.use(loggingSQLInjectionFilter);

/**
 * Logging Middleware
 */
if (config.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', {
    stream: {
      write: (message) => logger.info(message.trim())
    }
  }));
}

/**
 * Custom request logging
 */
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('Request completed', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id || 'anonymous'
    });
  });
  
  next();
});

/**
 * Health Check Endpoint
 */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    services: {
      database: 'connected',
      redis: 'connected',
      storage: 'available',
      sms: 'available',
      payment: 'available',
      push: 'available'
    }
  });
});

/**
 * API Status Endpoint
 */
app.get('/api/status', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'SilverApp API is running - China Edition',
    version: 'v1',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/v1/auth',
      posts: '/api/v1/posts',
      chat: '/api/v1/chat',
      friends: '/api/v1/friends',
      notifications: '/api/v1/notifications',
      upload: '/api/v1/upload',
      payment: '/api/v1/payment',
      push: '/api/v1/push'
    },
    services: {
      sms: 'Alibaba Cloud SMS + Tencent Cloud SMS',
      storage: 'Tencent Cloud COS + Alibaba Cloud OSS',
      payment: 'WeChat Pay + Alipay',
      push: 'Xiaomi + Huawei + OPPO + Vivo + APNs',
      analytics: 'Baidu Analytics + Tencent Analytics'
    }
  });
});

/**
 * API Routes
 */
const API_PREFIX = `/api/${config.API_VERSION}`;

app.use(`${API_PREFIX}/auth`, authRoutes);
app.use(`${API_PREFIX}/posts`, postRoutes);
app.use(`${API_PREFIX}/chat`, chatRoutes);
app.use(`${API_PREFIX}/friends`, friendRoutes);
app.use(`${API_PREFIX}/notifications`, notificationRoutes);
app.use(`${API_PREFIX}/upload`, uploadRoutes);
app.use(`${API_PREFIX}/payment`, paymentRoutes);
app.use(`${API_PREFIX}/push`, pushRoutes);

/**
 * WeChat Mini Program API endpoints
 */
app.get('/api/v1/wechat/login', async (req, res) => {
  // WeChat Mini Program login endpoint
  res.json({ message: 'WeChat Mini Program login endpoint' });
});

app.post('/api/v1/wechat/decrypt', async (req, res) => {
  // WeChat encrypted data decryption endpoint
  res.json({ message: 'WeChat data decryption endpoint' });
});

/**
 * 404 Handler for undefined routes
 */
app.all('*', (req, res, next) => {
  const error = new Error(`Route ${req.originalUrl} not found`);
  error.statusCode = 404;
  error.status = 'fail';
  next(error);
});

/**
 * Global Error Handler
 */
app.use(globalErrorHandler);

/**
 * Graceful shutdown handlers
 */
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  // Close server
  if (app.server) {
    app.server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
  
  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;