/**
 * PaymentOrder Model
 * Defines the payment order schema for tracking payment transactions
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * PaymentOrder model definition
 */
const PaymentOrder = sequelize.define('PaymentOrder', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  outTradeNo: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    comment: 'Unique order number for payment tracking'
  },
  
  amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0.01
    },
    comment: 'Payment amount in yuan'
  },
  
  description: {
    type: DataTypes.STRING(500),
    allowNull: false,
    comment: 'Order description'
  },
  
  provider: {
    type: DataTypes.ENUM('wechat', 'alipay'),
    allowNull: false,
    comment: 'Payment provider used'
  },
  
  orderType: {
    type: DataTypes.ENUM('premium', 'gift', 'boost', 'coins'),
    allowNull: false,
    comment: 'Type of order/purchase'
  },
  
  status: {
    type: DataTypes.ENUM('pending', 'paid', 'failed', 'cancelled', 'refunded'),
    defaultValue: 'pending',
    allowNull: false
  },
  
  transactionId: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Payment provider transaction ID'
  },
  
  paidAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  refundId: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Refund transaction ID'
  },
  
  refundedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  refundAmount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: true,
    validate: {
      min: 0
    }
  },
  
  refundReason: {
    type: DataTypes.STRING(500),
    allowNull: true
  },
  
  paymentData: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional payment-specific data (recipient, post ID, etc.)'
  },
  
  metadata: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional metadata for analytics and tracking'
  }
}, {
  tableName: 'payment_orders',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      fields: ['userId']
    },
    {
      unique: true,
      fields: ['outTradeNo']
    },
    {
      fields: ['status']
    },
    {
      fields: ['provider']
    },
    {
      fields: ['orderType']
    },
    {
      fields: ['transactionId']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['userId', 'status']
    },
    {
      fields: ['userId', 'created_at']
    }
  ],
  
  // Hooks for maintaining data integrity
  hooks: {
    beforeUpdate: (order) => {
      if (order.changed('status')) {
        if (order.status === 'paid' && !order.paidAt) {
          order.paidAt = new Date();
        }
        
        if (order.status === 'refunded' && !order.refundedAt) {
          order.refundedAt = new Date();
        }
      }
    }
  },
  
  // Scopes for common queries
  scopes: {
    paid: {
      where: {
        status: 'paid'
      }
    },
    
    pending: {
      where: {
        status: 'pending'
      }
    },
    
    refunded: {
      where: {
        status: 'refunded'
      }
    },
    
    byProvider: (provider) => ({
      where: {
        provider: provider
      }
    }),
    
    byOrderType: (orderType) => ({
      where: {
        orderType: orderType
      }
    }),
    
    recent: {
      order: [['created_at', 'DESC']]
    }
  }
});

/**
 * Instance methods
 */

/**
 * Mark order as paid
 * @param {string} transactionId - Payment provider transaction ID
 */
PaymentOrder.prototype.markAsPaid = async function(transactionId) {
  this.status = 'paid';
  this.transactionId = transactionId;
  this.paidAt = new Date();
  await this.save();
};

/**
 * Mark order as failed
 * @param {string} reason - Failure reason
 */
PaymentOrder.prototype.markAsFailed = async function(reason) {
  this.status = 'failed';
  if (!this.metadata) {
    this.metadata = {};
  }
  this.metadata.failureReason = reason;
  await this.save();
};

/**
 * Process refund
 * @param {number} refundAmount - Amount to refund
 * @param {string} reason - Refund reason
 * @param {string} refundId - Refund transaction ID
 */
PaymentOrder.prototype.processRefund = async function(refundAmount, reason, refundId) {
  this.status = 'refunded';
  this.refundAmount = refundAmount;
  this.refundReason = reason;
  this.refundId = refundId;
  this.refundedAt = new Date();
  await this.save();
};

/**
 * Check if order can be refunded
 * @returns {boolean} Whether order can be refunded
 */
PaymentOrder.prototype.canBeRefunded = function() {
  return this.status === 'paid' && !this.refundedAt;
};

/**
 * Get order summary
 * @returns {Object} Order summary
 */
PaymentOrder.prototype.getSummary = function() {
  return {
    id: this.id,
    outTradeNo: this.outTradeNo,
    amount: this.amount,
    description: this.description,
    provider: this.provider,
    orderType: this.orderType,
    status: this.status,
    createdAt: this.created_at,
    paidAt: this.paidAt
  };
};

/**
 * Class methods
 */

/**
 * Find order by trade number
 * @param {string} outTradeNo - Order trade number
 * @returns {Promise<PaymentOrder|null>} Payment order
 */
PaymentOrder.findByTradeNo = async function(outTradeNo) {
  return await PaymentOrder.findOne({
    where: { outTradeNo }
  });
};

/**
 * Get user orders
 * @param {string} userId - User ID
 * @param {Object} options - Query options
 * @returns {Promise<PaymentOrder[]>} User orders
 */
PaymentOrder.getUserOrders = async function(userId, options = {}) {
  const {
    status,
    orderType,
    limit = 20,
    offset = 0
  } = options;
  
  const whereClause = { userId };
  if (status) whereClause.status = status;
  if (orderType) whereClause.orderType = orderType;
  
  return await PaymentOrder.findAll({
    where: whereClause,
    order: [['created_at', 'DESC']],
    limit,
    offset
  });
};

/**
 * Get order statistics
 * @param {string} userId - User ID (optional)
 * @returns {Promise<Object>} Order statistics
 */
PaymentOrder.getStatistics = async function(userId = null) {
  const whereClause = userId ? { userId } : {};
  
  const stats = await PaymentOrder.findAll({
    where: whereClause,
    attributes: [
      'status',
      'orderType',
      [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
      [sequelize.fn('SUM', sequelize.col('amount')), 'totalAmount']
    ],
    group: ['status', 'orderType'],
    raw: true
  });
  
  return stats.reduce((acc, stat) => {
    const key = `${stat.status}_${stat.orderType}`;
    acc[key] = {
      count: parseInt(stat.count),
      totalAmount: parseFloat(stat.totalAmount) || 0
    };
    return acc;
  }, {});
};

module.exports = PaymentOrder;