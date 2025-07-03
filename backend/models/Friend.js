/**
 * Friend Model
 * Defines the friendship relationship schema and methods
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * Friend model definition
 */
const Friend = sequelize.define('Friend', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  friend_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  status: {
    type: DataTypes.ENUM('pending', 'accepted', 'blocked', 'declined'),
    defaultValue: 'pending',
    allowNull: false
  },
  
  requested_by: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    comment: 'User who initiated the friend request'
  },
  
  requested_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
    allowNull: false
  },
  
  accepted_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  blocked_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  blocked_by: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    comment: 'User who blocked the relationship'
  },
  
  is_close_friend: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'Indicates if this is a close friend relationship'
  },
  
  interaction_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    },
    comment: 'Number of interactions between friends'
  },
  
  last_interaction: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Last time friends interacted'
  },
  
  notes: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 500]
    },
    comment: 'Private notes about the friend'
  }
}, {
  tableName: 'friends',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      unique: true,
      fields: ['user_id', 'friend_id'],
      name: 'unique_friendship'
    },
    {
      fields: ['user_id']
    },
    {
      fields: ['friend_id']
    },
    {
      fields: ['status']
    },
    {
      fields: ['requested_by']
    },
    {
      fields: ['requested_at']
    },
    {
      fields: ['accepted_at']
    },
    {
      fields: ['is_close_friend']
    },
    {
      fields: ['user_id', 'status']
    },
    {
      fields: ['friend_id', 'status']
    }
  ],
  
  // Validation to prevent self-friendship
  validate: {
    notSelfFriend() {
      if (this.user_id === this.friend_id) {
        throw new Error('Users cannot be friends with themselves');
      }
    }
  },
  
  // Hooks for maintaining data integrity
  hooks: {
    beforeCreate: (friendship) => {
      // Ensure consistent ordering for friendship pairs
      if (friendship.user_id > friendship.friend_id) {
        const temp = friendship.user_id;
        friendship.user_id = friendship.friend_id;
        friendship.friend_id = temp;
      }
    },
    
    beforeUpdate: (friendship) => {
      if (friendship.changed('status')) {
        if (friendship.status === 'accepted' && !friendship.accepted_at) {
          friendship.accepted_at = new Date();
        }
        
        if (friendship.status === 'blocked' && !friendship.blocked_at) {
          friendship.blocked_at = new Date();
        }
      }
    }
  },
  
  // Scopes for common queries
  scopes: {
    accepted: {
      where: {
        status: 'accepted'
      }
    },
    
    pending: {
      where: {
        status: 'pending'
      }
    },
    
    blocked: {
      where: {
        status: 'blocked'
      }
    },
    
    closeFriends: {
      where: {
        status: 'accepted',
        is_close_friend: true
      }
    },
    
    withUsers: {
      include: [
        {
          model: sequelize.models.User,
          as: 'user',
          attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified']
        },
        {
          model: sequelize.models.User,
          as: 'friend',
          attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified']
        }
      ]
    }
  }
});

/**
 * Instance methods
 */

/**
 * Accept friend request
 */
Friend.prototype.accept = async function() {
  this.status = 'accepted';
  this.accepted_at = new Date();
  await this.save();
};

/**
 * Decline friend request
 */
Friend.prototype.decline = async function() {
  this.status = 'declined';
  await this.save();
};

/**
 * Block user
 * @param {string} blockedBy - ID of user who is blocking
 */
Friend.prototype.block = async function(blockedBy) {
  this.status = 'blocked';
  this.blocked_at = new Date();
  this.blocked_by = blockedBy;
  await this.save();
};

/**
 * Unblock user
 */
Friend.prototype.unblock = async function() {
  this.status = 'declined';
  this.blocked_at = null;
  this.blocked_by = null;
  await this.save();
};

/**
 * Toggle close friend status
 */
Friend.prototype.toggleCloseFriend = async function() {
  this.is_close_friend = !this.is_close_friend;
  await this.save();
};

/**
 * Update interaction
 */
Friend.prototype.updateInteraction = async function() {
  this.interaction_count += 1;
  this.last_interaction = new Date();
  await this.save();
};

/**
 * Class methods
 */

/**
 * Send friend request
 * @param {string} userId - User sending the request
 * @param {string} friendId - User receiving the request
 * @returns {Promise<Friend>} Friend instance
 */
Friend.sendRequest = async function(userId, friendId) {
  // Check if friendship already exists
  const existingFriendship = await Friend.findExistingFriendship(userId, friendId);
  
  if (existingFriendship) {
    if (existingFriendship.status === 'blocked') {
      throw new Error('Cannot send friend request to blocked user');
    }
    if (existingFriendship.status === 'pending') {
      throw new Error('Friend request already sent');
    }
    if (existingFriendship.status === 'accepted') {
      throw new Error('Users are already friends');
    }
  }
  
  // Create new friend request
  const [user1, user2] = userId < friendId ? [userId, friendId] : [friendId, userId];
  
  return await Friend.create({
    user_id: user1,
    friend_id: user2,
    requested_by: userId,
    status: 'pending'
  });
};

/**
 * Find existing friendship between two users
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {Promise<Friend|null>} Friend instance or null
 */
Friend.findExistingFriendship = async function(userId1, userId2) {
  const [user1, user2] = userId1 < userId2 ? [userId1, userId2] : [userId2, userId1];
  
  return await Friend.findOne({
    where: {
      user_id: user1,
      friend_id: user2
    }
  });
};

/**
 * Get user's friends
 * @param {string} userId - User ID
 * @param {number} limit - Number of friends to fetch
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Friend[]>} Array of friendships
 */
Friend.getUserFriends = async function(userId, limit = 50, offset = 0) {
  return await Friend.scope(['accepted', 'withUsers']).findAll({
    where: {
      [sequelize.Sequelize.Op.or]: [
        { user_id: userId },
        { friend_id: userId }
      ]
    },
    order: [['accepted_at', 'DESC']],
    limit: limit,
    offset: offset
  });
};

/**
 * Get pending friend requests for a user
 * @param {string} userId - User ID
 * @returns {Promise<Friend[]>} Array of pending requests
 */
Friend.getPendingRequests = async function(userId) {
  return await Friend.scope(['pending', 'withUsers']).findAll({
    where: {
      [sequelize.Sequelize.Op.or]: [
        { user_id: userId, requested_by: { [sequelize.Sequelize.Op.ne]: userId } },
        { friend_id: userId, requested_by: { [sequelize.Sequelize.Op.ne]: userId } }
      ]
    },
    order: [['requested_at', 'DESC']]
  });
};

/**
 * Get sent friend requests
 * @param {string} userId - User ID
 * @returns {Promise<Friend[]>} Array of sent requests
 */
Friend.getSentRequests = async function(userId) {
  return await Friend.scope(['pending', 'withUsers']).findAll({
    where: {
      requested_by: userId
    },
    order: [['requested_at', 'DESC']]
  });
};

/**
 * Check if users are friends
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {Promise<boolean>} Friendship status
 */
Friend.areFriends = async function(userId1, userId2) {
  const friendship = await Friend.findExistingFriendship(userId1, userId2);
  return friendship && friendship.status === 'accepted';
};

/**
 * Check if user is blocked
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {Promise<boolean>} Block status
 */
Friend.isBlocked = async function(userId1, userId2) {
  const friendship = await Friend.findExistingFriendship(userId1, userId2);
  return friendship && friendship.status === 'blocked';
};

/**
 * Get mutual friends between two users
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {Promise<string[]>} Array of mutual friend IDs
 */
Friend.getMutualFriends = async function(userId1, userId2) {
  const user1Friends = await Friend.getUserFriends(userId1);
  const user2Friends = await Friend.getUserFriends(userId2);
  
  const user1FriendIds = user1Friends.map(f => 
    f.user_id === userId1 ? f.friend_id : f.user_id
  );
  const user2FriendIds = user2Friends.map(f => 
    f.user_id === userId2 ? f.friend_id : f.user_id
  );
  
  return user1FriendIds.filter(id => user2FriendIds.includes(id));
};

/**
 * Get friend suggestions for a user
 * @param {string} userId - User ID
 * @param {number} limit - Number of suggestions
 * @returns {Promise<Object[]>} Array of suggested users
 */
Friend.getFriendSuggestions = async function(userId, limit = 10) {
  // This would implement friend suggestion algorithm
  // Based on mutual friends, contacts, etc.
  // Placeholder implementation
  const User = sequelize.models.User;
  
  return await User.findAll({
    where: {
      id: { [sequelize.Sequelize.Op.ne]: userId },
      is_active: true
    },
    attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified'],
    limit: limit,
    order: sequelize.literal('RAND()')
  });
};

module.exports = Friend;