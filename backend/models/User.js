/**
 * User Model
 * Defines the user schema and methods for authentication and profile management
 */

const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const { sequelize } = require('../config/db');
const config = require('../config/env');

/**
 * User model definition
 */
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  username: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true,
    validate: {
      len: [3, 50],
      isAlphanumeric: true
    }
  },
  
  email: {
    type: DataTypes.STRING(255),
    allowNull: true, // Email is optional
    unique: true,
    validate: {
      isEmail: true
    }
  },
  
  phone_number: {
    type: DataTypes.STRING(20),
    allowNull: false, // Phone number is mandatory
    unique: true,
    validate: {
      is: /^\+?[1-9]\d{1,14}$/ // E.164 format
    }
  },
  
  password_hash: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      len: [60, 255] // bcrypt hash length
    }
  },
  
  first_name: {
    type: DataTypes.STRING(50),
    allowNull: false,
    validate: {
      len: [1, 50],
      notEmpty: true
    }
  },
  
  last_name: {
    type: DataTypes.STRING(50),
    allowNull: false,
    validate: {
      len: [1, 50],
      notEmpty: true
    }
  },
  
  date_of_birth: {
    type: DataTypes.DATEONLY,
    allowNull: true,
    validate: {
      isDate: true,
      isBefore: new Date().toISOString().split('T')[0] // Must be in the past
    }
  },
  
  gender: {
    type: DataTypes.ENUM('male', 'female', 'other', 'prefer_not_to_say'),
    allowNull: true,
    defaultValue: 'prefer_not_to_say'
  },
  
  profile_picture: {
    type: DataTypes.STRING(500),
    allowNull: true,
    validate: {
      isUrl: true
    }
  },
  
  cover_picture: {
    type: DataTypes.STRING(500),
    allowNull: true,
    validate: {
      isUrl: true
    }
  },
  
  bio: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 500]
    }
  },
  
  location: {
    type: DataTypes.STRING(100),
    allowNull: true,
    validate: {
      len: [0, 100]
    }
  },
  
  website: {
    type: DataTypes.STRING(255),
    allowNull: true,
    validate: {
      isUrl: true
    }
  },
  
  is_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  phone_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    allowNull: false
  },
  
  is_private: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  last_login: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  login_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false
  },
  
  refresh_token: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  
  refresh_token_expires: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  verification_code: {
    type: DataTypes.STRING(10),
    allowNull: true
  },
  
  verification_code_expires: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  password_reset_token: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  
  password_reset_expires: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  two_factor_enabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  two_factor_secret: {
    type: DataTypes.STRING(255),
    allowNull: true
  }
}, {
  tableName: 'users',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      unique: true,
      fields: ['username']
    },
    {
      unique: true,
      fields: ['email']
    },
    {
      unique: true,
      fields: ['phone_number']
    },
    {
      fields: ['is_active']
    },
    {
      fields: ['phone_verified']
    },
    {
      fields: ['created_at']
    }
  ],
  
  // Hooks for password hashing and validation
  hooks: {
    beforeCreate: async (user) => {
      if (user.password_hash) {
        user.password_hash = await bcrypt.hash(user.password_hash, config.security.bcryptRounds);
      }
    },
    
    beforeUpdate: async (user) => {
      if (user.changed('password_hash')) {
        user.password_hash = await bcrypt.hash(user.password_hash, config.security.bcryptRounds);
      }
    }
  }
});

/**
 * Instance methods
 */

/**
 * Compare password with hash
 * @param {string} password - Plain text password
 * @returns {Promise<boolean>} Password match result
 */
User.prototype.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password_hash);
};

/**
 * Generate verification code
 * @returns {string} 6-digit verification code
 */
User.prototype.generateVerificationCode = function() {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  this.verification_code = code;
  this.verification_code_expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  return code;
};

/**
 * Verify verification code
 * @param {string} code - Verification code to check
 * @returns {boolean} Verification result
 */
User.prototype.verifyCode = function(code) {
  if (!this.verification_code || !this.verification_code_expires) {
    return false;
  }
  
  if (new Date() > this.verification_code_expires) {
    return false;
  }
  
  return this.verification_code === code;
};

/**
 * Clear verification code
 */
User.prototype.clearVerificationCode = function() {
  this.verification_code = null;
  this.verification_code_expires = null;
};

/**
 * Get full name
 * @returns {string} Full name
 */
User.prototype.getFullName = function() {
  return `${this.first_name} ${this.last_name}`;
};

/**
 * Get public profile data
 * @returns {Object} Public profile information
 */
User.prototype.getPublicProfile = function() {
  return {
    id: this.id,
    username: this.username,
    first_name: this.first_name,
    last_name: this.last_name,
    profile_picture: this.profile_picture,
    cover_picture: this.cover_picture,
    bio: this.bio,
    location: this.location,
    website: this.website,
    is_verified: this.is_verified,
    is_private: this.is_private,
    created_at: this.created_at
  };
};

/**
 * Update last login
 */
User.prototype.updateLastLogin = async function() {
  this.last_login = new Date();
  this.login_count += 1;
  await this.save();
};

/**
 * Class methods
 */

/**
 * Find user by username or phone number
 * @param {string} identifier - Username or phone number
 * @returns {Promise<User|null>} User instance or null
 */
User.findByIdentifier = async function(identifier) {
  return await User.findOne({
    where: {
      [sequelize.Sequelize.Op.or]: [
        { username: identifier },
        { phone_number: identifier }
      ]
    }
  });
};

/**
 * Find user by phone number
 * @param {string} phoneNumber - Phone number
 * @returns {Promise<User|null>} User instance or null
 */
User.findByPhoneNumber = async function(phoneNumber) {
  return await User.findOne({
    where: { phone_number: phoneNumber }
  });
};

/**
 * Find user by email
 * @param {string} email - Email address
 * @returns {Promise<User|null>} User instance or null
 */
User.findByEmail = async function(email) {
  return await User.findOne({
    where: { email: email }
  });
};

/**
 * Search users by name or username
 * @param {string} query - Search query
 * @param {number} limit - Result limit
 * @returns {Promise<User[]>} Array of users
 */
User.searchUsers = async function(query, limit = 20) {
  return await User.findAll({
    where: {
      [sequelize.Sequelize.Op.and]: [
        { is_active: true },
        {
          [sequelize.Sequelize.Op.or]: [
            { username: { [sequelize.Sequelize.Op.like]: `%${query}%` } },
            { first_name: { [sequelize.Sequelize.Op.like]: `%${query}%` } },
            { last_name: { [sequelize.Sequelize.Op.like]: `%${query}%` } }
          ]
        }
      ]
    },
    attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified'],
    limit: limit,
    order: [['created_at', 'DESC']]
  });
};

module.exports = User;