/**
 * Payment Routes
 * Defines payment API endpoints using WeChat Pay and Alipay
 */

const express = require('express');
const { authenticate } = require('../middleware/auth');
const { validate } = require('../middleware/validator');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');
const paymentService = require('../services/payment');
const { logger } = require('../config/logger');
const { AppError } = require('../errors/AppError');
const Joi = require('joi');

const router = express.Router();

// Payment validation schemas
const paymentSchemas = {
  createOrder: Joi.object({
    amount: Joi.number().positive().required(),
    description: Joi.string().min(1).max(200).required(),
    provider: Joi.string().valid('wechat', 'alipay').default('wechat'),
    orderType: Joi.string().valid('premium', 'gift', 'boost').required(),
    returnUrl: Joi.string().uri().optional(),
    notifyUrl: Joi.string().uri().optional()
  }),

  queryOrder: Joi.object({
    outTradeNo: Joi.string().required(),
    provider: Joi.string().valid('wechat', 'alipay').required()
  }),

  refundOrder: Joi.object({
    outTradeNo: Joi.string().required(),
    refundAmount: Joi.number().positive().required(),
    refundReason: Joi.string().min(1).max(200).required(),
    provider: Joi.string().valid('wechat', 'alipay').required()
  })
};

/**
 * @route   POST /api/v1/payment/create-order
 * @desc    Create payment order
 * @access  Private
 */
router.post('/create-order',
  authenticate,
  loggingSQLInjectionFilter,
  validate(paymentSchemas.createOrder),
  async (req, res, next) => {
    try {
      const { amount, description, provider, orderType, returnUrl, notifyUrl } = req.body;
      const userId = req.user.id;

      // Generate unique order number
      const outTradeNo = `${orderType}_${userId}_${Date.now()}`;

      const orderData = {
        outTradeNo,
        totalFee: Math.round(amount * 100), // Convert to cents for WeChat
        totalAmount: amount.toFixed(2), // Keep decimal for Alipay
        body: description,
        subject: description,
        openid: req.user.wechat_openid, // For WeChat Pay
        tradeType: 'JSAPI',
        notifyUrl: notifyUrl || `${req.protocol}://${req.get('host')}/api/v1/payment/callback/${provider}`,
        returnUrl: returnUrl || `${req.protocol}://${req.get('host')}/payment/success`
      };

      const result = await paymentService.createPaymentOrder(orderData, provider);

      if (!result.success) {
        return next(new AppError('Payment order creation failed: ' + result.error, 500));
      }

      // Store order in database (you would implement this)
      // await PaymentOrder.create({
      //   userId,
      //   outTradeNo,
      //   amount,
      //   description,
      //   provider,
      //   orderType,
      //   status: 'pending'
      // });

      logger.info('Payment order created:', {
        userId,
        outTradeNo,
        amount,
        provider,
        orderType
      });

      res.status(201).json({
        status: 'success',
        message: 'Payment order created successfully',
        data: {
          outTradeNo,
          provider: result.provider,
          payUrl: result.payUrl,
          prepayId: result.prepayId,
          codeUrl: result.codeUrl
        }
      });

    } catch (error) {
      logger.error('Payment order creation failed:', error);
      next(new AppError('Payment order creation failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/payment/callback/wechat
 * @desc    WeChat Pay callback
 * @access  Public
 */
router.post('/callback/wechat',
  async (req, res, next) => {
    try {
      const xmlData = req.body;

      const verification = paymentService.verifyWechatCallback(xmlData);

      if (!verification.isValid) {
        logger.error('WeChat Pay callback verification failed');
        return res.status(400).send('<xml><return_code><![CDATA[FAIL]]></return_code><return_msg><![CDATA[Signature verification failed]]></return_msg></xml>');
      }

      const { outTradeNo, transactionId, totalFee } = verification;

      // Update order status in database
      // await PaymentOrder.update(
      //   { 
      //     status: 'paid',
      //     transactionId,
      //     paidAt: new Date()
      //   },
      //   { where: { outTradeNo } }
      // );

      logger.info('WeChat Pay callback processed:', {
        outTradeNo,
        transactionId,
        totalFee
      });

      // Process the successful payment (grant premium features, etc.)
      await processSuccessfulPayment(outTradeNo, 'wechat');

      res.status(200).send('<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>');

    } catch (error) {
      logger.error('WeChat Pay callback processing failed:', error);
      res.status(500).send('<xml><return_code><![CDATA[FAIL]]></return_code><return_msg><![CDATA[Internal error]]></return_msg></xml>');
    }
  }
);

/**
 * @route   POST /api/v1/payment/callback/alipay
 * @desc    Alipay callback
 * @access  Public
 */
router.post('/callback/alipay',
  async (req, res, next) => {
    try {
      const params = req.body;

      const verification = paymentService.verifyAlipayCallback(params);

      if (!verification.isValid) {
        logger.error('Alipay callback verification failed');
        return res.status(200).send('failure');
      }

      const { outTradeNo, tradeNo, totalAmount } = verification;

      // Update order status in database
      // await PaymentOrder.update(
      //   { 
      //     status: 'paid',
      //     transactionId: tradeNo,
      //     paidAt: new Date()
      //   },
      //   { where: { outTradeNo } }
      // );

      logger.info('Alipay callback processed:', {
        outTradeNo,
        tradeNo,
        totalAmount
      });

      // Process the successful payment
      await processSuccessfulPayment(outTradeNo, 'alipay');

      res.status(200).send('success');

    } catch (error) {
      logger.error('Alipay callback processing failed:', error);
      res.status(200).send('failure');
    }
  }
);

/**
 * @route   GET /api/v1/payment/query/:outTradeNo
 * @desc    Query payment order status
 * @access  Private
 */
router.get('/query/:outTradeNo',
  authenticate,
  async (req, res, next) => {
    try {
      const { outTradeNo } = req.params;
      const { provider } = req.query;

      if (!provider) {
        return next(new AppError('Provider is required', 400));
      }

      let result;
      if (provider === 'wechat') {
        result = await paymentService.queryWechatOrder(outTradeNo);
      } else if (provider === 'alipay') {
        result = await paymentService.queryAlipayOrder(outTradeNo);
      } else {
        return next(new AppError('Invalid provider', 400));
      }

      if (!result.success) {
        return next(new AppError('Order query failed: ' + result.error, 500));
      }

      res.status(200).json({
        status: 'success',
        data: {
          outTradeNo,
          provider,
          tradeState: result.tradeState,
          tradeStatus: result.tradeStatus,
          orderData: result.data
        }
      });

    } catch (error) {
      logger.error('Payment order query failed:', error);
      next(new AppError('Payment order query failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/payment/refund
 * @desc    Refund payment order
 * @access  Private
 */
router.post('/refund',
  authenticate,
  loggingSQLInjectionFilter,
  validate(paymentSchemas.refundOrder),
  async (req, res, next) => {
    try {
      const { outTradeNo, refundAmount, refundReason, provider } = req.body;
      const userId = req.user.id;

      // Verify order belongs to user and is refundable
      // const order = await PaymentOrder.findOne({
      //   where: { outTradeNo, userId, status: 'paid' }
      // });
      // 
      // if (!order) {
      //   return next(new AppError('Order not found or not refundable', 404));
      // }

      const outRefundNo = `refund_${outTradeNo}_${Date.now()}`;

      let result;
      if (provider === 'wechat') {
        result = await paymentService.refundWechatOrder({
          outTradeNo,
          outRefundNo,
          totalFee: Math.round(refundAmount * 100), // Original amount in cents
          refundFee: Math.round(refundAmount * 100), // Refund amount in cents
          refundDesc: refundReason
        });
      } else {
        return next(new AppError('Alipay refund not implemented yet', 501));
      }

      if (!result.success) {
        return next(new AppError('Refund failed: ' + result.error, 500));
      }

      // Update order status in database
      // await PaymentOrder.update(
      //   { 
      //     status: 'refunded',
      //     refundId: result.refundId,
      //     refundedAt: new Date(),
      //     refundReason
      //   },
      //   { where: { outTradeNo } }
      // );

      logger.info('Payment refund processed:', {
        userId,
        outTradeNo,
        outRefundNo,
        refundAmount,
        provider
      });

      res.status(200).json({
        status: 'success',
        message: 'Refund processed successfully',
        data: {
          outTradeNo,
          outRefundNo,
          refundId: result.refundId,
          provider: result.provider
        }
      });

    } catch (error) {
      logger.error('Payment refund failed:', error);
      next(new AppError('Payment refund failed', 500));
    }
  }
);

/**
 * @route   GET /api/v1/payment/orders
 * @desc    Get user payment orders
 * @access  Private
 */
router.get('/orders',
  authenticate,
  async (req, res, next) => {
    try {
      const { page = 1, limit = 20, status } = req.query;
      const userId = req.user.id;

      // This would fetch from your PaymentOrder model
      // const whereClause = { userId };
      // if (status) {
      //   whereClause.status = status;
      // }
      // 
      // const orders = await PaymentOrder.findAll({
      //   where: whereClause,
      //   order: [['createdAt', 'DESC']],
      //   limit: parseInt(limit),
      //   offset: (page - 1) * limit
      // });

      // Mock response for now
      const orders = [];

      res.status(200).json({
        status: 'success',
        data: {
          orders,
          pagination: {
            currentPage: parseInt(page),
            totalItems: orders.length,
            itemsPerPage: parseInt(limit),
            hasNextPage: orders.length === parseInt(limit)
          }
        }
      });

    } catch (error) {
      logger.error('Get payment orders failed:', error);
      next(new AppError('Failed to get payment orders', 500));
    }
  }
);

/**
 * Process successful payment
 * @param {string} outTradeNo - Order trade number
 * @param {string} provider - Payment provider
 */
async function processSuccessfulPayment(outTradeNo, provider) {
  try {
    // Extract order info from trade number
    const [orderType, userId] = outTradeNo.split('_');

    // Grant premium features based on order type
    switch (orderType) {
      case 'premium':
        // Grant premium membership
        // await User.update(
        //   { isPremium: true, premiumExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) },
        //   { where: { id: userId } }
        // );
        break;
      case 'gift':
        // Process gift
        break;
      case 'boost':
        // Process post boost
        break;
    }

    logger.info('Payment processed successfully:', {
      outTradeNo,
      provider,
      orderType,
      userId
    });

  } catch (error) {
    logger.error('Payment processing failed:', error);
  }
}

module.exports = router;