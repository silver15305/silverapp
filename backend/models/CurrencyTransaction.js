/**
 * CurrencyTransaction Model
 * Defines the virtual currency transaction schema
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * CurrencyTransaction model definition
 */
const CurrencyTransaction = sequelize.define('CurrencyTransaction', {
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
  
  type: {
    type: DataTypes.ENUM('purchase', 'gift', 'spend', 'refund', 'bonus'),
    allowNull: false
  },
  
  amount: {
    type: DataTypes.INTEGER,
    allowNull: false,
    comment: 'Amount of virtual currency (can be negative for spending)'
  },
  
  balanceBefore: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  balanceAfter: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  description: {
    type: DataTypes.STRING(500),
    allowNull: true
  },
  
  paymentAmount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: true,
    comment: 'Real money amount for purchases'
  },
  
  relatedId: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'Related entity ID (gift ID, order ID, etc.)'
  }
}, {
  tableName: 'currency_transactions',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  indexes: [
    {
      fields: ['userId']
    },
    {
      fields: ['type']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['userId', 'created_at']
    }
  ]
});

module.exports = CurrencyTransaction;