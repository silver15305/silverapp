/**
 * Payment Processing Service
 * Handles business logic for payment processing and user feature updates
 */

const { logger } = require('../config/logger');
const User = require('../models/User');

/**
 * Payment Processing Service Class
 */
class PaymentProcessor {
  /**
   * Process successful payment and update user features
   * @param {string} outTradeNo - Order trade number
   * @param {string} provider - Payment provider
   * @param {Object} paymentData - Additional payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processSuccessfulPayment(outTradeNo, provider, paymentData = {}) {
    try {
      // Extract order info from trade number
      const orderParts = outTradeNo.split('_');
      if (orderParts.length < 3) {
        throw new Error('Invalid order trade number format');
      }
      
      const [orderType, userId, timestamp] = orderParts;
      const amount = paymentData.amount || paymentData.totalFee || paymentData.totalAmount;

      logger.info('Processing successful payment:', {
        outTradeNo,
        provider,
        orderType,
        userId,
        amount
      });

      // Create payment order record
      const PaymentOrder = require('../models/PaymentOrder');
      if (PaymentOrder) {
        await PaymentOrder.create({
          userId,
          outTradeNo,
          amount: parseFloat(amount) || 0,
          provider,
          orderType,
          status: 'paid',
          transactionId: paymentData.transactionId || paymentData.tradeNo,
          paidAt: new Date(),
          paymentData: paymentData
        });
      }

      // Process based on order type
      const result = await this.processOrderType(orderType, userId, amount, paymentData);

      logger.info('Payment processed successfully:', {
        outTradeNo,
        provider,
        orderType,
        userId,
        result
      });

      return {
        success: true,
        orderType,
        userId,
        result
      };

    } catch (error) {
      logger.error('Payment processing failed:', {
        outTradeNo,
        provider,
        error: error.message
      });

      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Process specific order types
   * @param {string} orderType - Type of order
   * @param {string} userId - User ID
   * @param {number} amount - Payment amount
   * @param {Object} paymentData - Payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processOrderType(orderType, userId, amount, paymentData) {
    switch (orderType) {
      case 'premium':
        return await this.processPremiumSubscription(userId, amount, paymentData);
      
      case 'gift':
        return await this.processGift(userId, amount, paymentData);
      
      case 'boost':
        return await this.processPostBoost(userId, amount, paymentData);
      
      case 'coins':
        return await this.processVirtualCurrency(userId, amount, paymentData);
      
      default:
        throw new Error(`Unknown order type: ${orderType}`);
    }
  }

  /**
   * Process premium subscription
   * @param {string} userId - User ID
   * @param {number} amount - Payment amount
   * @param {Object} paymentData - Payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processPremiumSubscription(userId, amount, paymentData) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Determine subscription duration based on amount
      let durationDays = 30; // Default 1 month
      if (amount >= 100) { // Assuming 100 yuan for yearly
        durationDays = 365;
      } else if (amount >= 50) { // Assuming 50 yuan for 6 months
        durationDays = 180;
      }

      // Calculate expiration date
      const currentExpiry = user.premium_expires_at || new Date();
      const newExpiry = new Date(Math.max(currentExpiry.getTime(), Date.now()) + (durationDays * 24 * 60 * 60 * 1000));

      // Update user premium status
      await user.update({
        is_premium: true,
        premium_expires_at: newExpiry,
        premium_type: durationDays >= 365 ? 'yearly' : durationDays >= 180 ? 'biannual' : 'monthly'
      });

      logger.info('Premium subscription activated:', {
        userId,
        durationDays,
        expiresAt: newExpiry
      });

      return {
        type: 'premium_subscription',
        durationDays,
        expiresAt: newExpiry,
        premiumType: user.premium_type
      };

    } catch (error) {
      logger.error('Premium subscription processing failed:', error);
      throw error;
    }
  }

  /**
   * Process gift purchase
   * @param {string} userId - User ID
   * @param {number} amount - Payment amount
   * @param {Object} paymentData - Payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processGift(userId, amount, paymentData) {
    try {
      // Extract gift details from payment data
      const { recipientId, giftType, message } = paymentData;

      if (!recipientId) {
        throw new Error('Recipient ID is required for gift processing');
      }

      const recipient = await User.findByPk(recipientId);
      if (!recipient) {
        throw new Error('Gift recipient not found');
      }

      // Create gift record
      const Gift = require('../models/Gift');
      if (Gift) {
        await Gift.create({
          senderId: userId,
          recipientId,
          giftType,
          amount,
          message,
          status: 'delivered'
        });
      }

      // Process gift effects (e.g., premium time, virtual currency)
      let giftResult = {};
      if (giftType === 'premium') {
        giftResult = await this.processPremiumSubscription(recipientId, amount, paymentData);
      } else if (giftType === 'coins') {
        giftResult = await this.processVirtualCurrency(recipientId, amount, paymentData);
      }

      logger.info('Gift processed successfully:', {
        senderId: userId,
        recipientId,
        giftType,
        amount
      });

      return {
        type: 'gift',
        giftType,
        recipientId,
        giftResult
      };

    } catch (error) {
      logger.error('Gift processing failed:', error);
      throw error;
    }
  }

  /**
   * Process post boost
   * @param {string} userId - User ID
   * @param {number} amount - Payment amount
   * @param {Object} paymentData - Payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processPostBoost(userId, amount, paymentData) {
    try {
      const { postId, boostDuration } = paymentData;

      if (!postId) {
        throw new Error('Post ID is required for boost processing');
      }

      const Post = require('../models/Post');
      const post = await Post.findByPk(postId);
      
      if (!post) {
        throw new Error('Post not found');
      }

      if (post.user_id !== userId) {
        throw new Error('User can only boost their own posts');
      }

      // Calculate boost duration based on amount
      let durationHours = Math.floor(amount / 5) * 24; // 5 yuan per day
      if (boostDuration) {
        durationHours = parseInt(boostDuration);
      }

      const boostExpiry = new Date(Date.now() + (durationHours * 60 * 60 * 1000));

      // Update post boost status
      await post.update({
        is_boosted: true,
        boost_expires_at: boostExpiry,
        boost_amount: amount
      });

      logger.info('Post boost activated:', {
        userId,
        postId,
        durationHours,
        expiresAt: boostExpiry
      });

      return {
        type: 'post_boost',
        postId,
        durationHours,
        expiresAt: boostExpiry
      };

    } catch (error) {
      logger.error('Post boost processing failed:', error);
      throw error;
    }
  }

  /**
   * Process virtual currency purchase
   * @param {string} userId - User ID
   * @param {number} amount - Payment amount
   * @param {Object} paymentData - Payment data
   * @returns {Promise<Object>} Processing result
   */
  static async processVirtualCurrency(userId, amount, paymentData) {
    try {
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Calculate coins based on amount (1 yuan = 10 coins)
      const coinsToAdd = Math.floor(amount * 10);
      const currentCoins = user.virtual_currency || 0;
      const newCoins = currentCoins + coinsToAdd;

      // Update user's virtual currency
      await user.update({
        virtual_currency: newCoins
      });

      // Create transaction record
      const CurrencyTransaction = require('../models/CurrencyTransaction');
      if (CurrencyTransaction) {
        await CurrencyTransaction.create({
          userId,
          type: 'purchase',
          amount: coinsToAdd,
          balanceBefore: currentCoins,
          balanceAfter: newCoins,
          description: `Purchased ${coinsToAdd} coins`,
          paymentAmount: amount
        });
      }

      logger.info('Virtual currency processed:', {
        userId,
        coinsAdded: coinsToAdd,
        newBalance: newCoins
      });

      return {
        type: 'virtual_currency',
        coinsAdded: coinsToAdd,
        newBalance: newCoins
      };

    } catch (error) {
      logger.error('Virtual currency processing failed:', error);
      throw error;
    }
  }

  /**
   * Process refund
   * @param {string} outTradeNo - Original order trade number
   * @param {number} refundAmount - Refund amount
   * @param {string} reason - Refund reason
   * @returns {Promise<Object>} Processing result
   */
  static async processRefund(outTradeNo, refundAmount, reason) {
    try {
      // Find the original payment order
      const PaymentOrder = require('../models/PaymentOrder');
      if (!PaymentOrder) {
        throw new Error('PaymentOrder model not available');
      }

      const order = await PaymentOrder.findOne({
        where: { outTradeNo, status: 'paid' }
      });

      if (!order) {
        throw new Error('Original payment order not found');
      }

      // Update order status
      await order.update({
        status: 'refunded',
        refundAmount,
        refundReason: reason,
        refundedAt: new Date()
      });

      // Reverse the effects based on order type
      const reverseResult = await this.reverseOrderEffects(order, refundAmount);

      logger.info('Refund processed successfully:', {
        outTradeNo,
        refundAmount,
        reason,
        reverseResult
      });

      return {
        success: true,
        outTradeNo,
        refundAmount,
        reverseResult
      };

    } catch (error) {
      logger.error('Refund processing failed:', error);
      throw error;
    }
  }

  /**
   * Reverse order effects for refunds
   * @param {Object} order - Original order
   * @param {number} refundAmount - Refund amount
   * @returns {Promise<Object>} Reverse result
   */
  static async reverseOrderEffects(order, refundAmount) {
    try {
      const { orderType, userId } = order;

      switch (orderType) {
        case 'premium':
          return await this.reversePremiumSubscription(userId, refundAmount);
        
        case 'coins':
          return await this.reverseVirtualCurrency(userId, refundAmount);
        
        case 'boost':
          return await this.reversePostBoost(order);
        
        default:
          logger.warn(`No reverse logic for order type: ${orderType}`);
          return { type: orderType, reversed: false };
      }

    } catch (error) {
      logger.error('Error reversing order effects:', error);
      throw error;
    }
  }

  /**
   * Reverse premium subscription
   * @param {string} userId - User ID
   * @param {number} refundAmount - Refund amount
   * @returns {Promise<Object>} Reverse result
   */
  static async reversePremiumSubscription(userId, refundAmount) {
    const user = await User.findByPk(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Calculate days to remove based on refund amount
    const daysToRemove = Math.floor(refundAmount / 3); // Assuming 3 yuan per day

    if (user.premium_expires_at) {
      const newExpiry = new Date(user.premium_expires_at.getTime() - (daysToRemove * 24 * 60 * 60 * 1000));
      
      // If new expiry is in the past, remove premium status
      if (newExpiry <= new Date()) {
        await user.update({
          is_premium: false,
          premium_expires_at: null,
          premium_type: null
        });
      } else {
        await user.update({
          premium_expires_at: newExpiry
        });
      }
    }

    return {
      type: 'premium_reversal',
      daysRemoved: daysToRemove,
      newExpiryDate: user.premium_expires_at
    };
  }

  /**
   * Reverse virtual currency
   * @param {string} userId - User ID
   * @param {number} refundAmount - Refund amount
   * @returns {Promise<Object>} Reverse result
   */
  static async reverseVirtualCurrency(userId, refundAmount) {
    const user = await User.findByPk(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const coinsToRemove = Math.floor(refundAmount * 10);
    const currentCoins = user.virtual_currency || 0;
    const newCoins = Math.max(0, currentCoins - coinsToRemove);

    await user.update({
      virtual_currency: newCoins
    });

    return {
      type: 'currency_reversal',
      coinsRemoved: coinsToRemove,
      newBalance: newCoins
    };
  }

  /**
   * Reverse post boost
   * @param {Object} order - Original order
   * @returns {Promise<Object>} Reverse result
   */
  static async reversePostBoost(order) {
    const { paymentData } = order;
    const { postId } = paymentData || {};

    if (!postId) {
      return { type: 'boost_reversal', reversed: false, reason: 'No post ID found' };
    }

    const Post = require('../models/Post');
    const post = await Post.findByPk(postId);

    if (post && post.is_boosted) {
      await post.update({
        is_boosted: false,
        boost_expires_at: null,
        boost_amount: null
      });

      return {
        type: 'boost_reversal',
        postId,
        reversed: true
      };
    }

    return {
      type: 'boost_reversal',
      postId,
      reversed: false,
      reason: 'Post not found or not boosted'
    };
  }
}

module.exports = PaymentProcessor;