/**
 * Gift Model
 * Defines the gift schema for tracking gifts between users
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * Gift model definition
 */
const Gift = sequelize.define('Gift', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  senderId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  recipientId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  giftType: {
    type: DataTypes.ENUM('premium', 'coins', 'sticker'),
    allowNull: false
  },
  
  amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  message: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 500]
    }
  },
  
  status: {
    type: DataTypes.ENUM('pending', 'delivered', 'claimed'),
    defaultValue: 'pending',
    allowNull: false
  },
  
  deliveredAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  claimedAt: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  tableName: 'gifts',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  indexes: [
    {
      fields: ['senderId']
    },
    {
      fields: ['recipientId']
    },
    {
      fields: ['status']
    },
    {
      fields: ['giftType']
    },
    {
      fields: ['created_at']
    }
  ]
});

module.exports = Gift;