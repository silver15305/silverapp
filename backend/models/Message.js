/**
 * Message Model
 * Defines the messaging schema for chat functionality
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * Message model definition
 */
const Message = sequelize.define('Message', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  sender_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  receiver_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
  },
  
  conversation_id: {
    type: DataTypes.STRING(255),
    allowNull: false,
    comment: 'Unique identifier for the conversation between two users'
  },
  
  content: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 2000] // Maximum 2000 characters
    }
  },
  
  message_type: {
    type: DataTypes.ENUM('text', 'image', 'video', 'audio', 'file', 'location', 'contact', 'sticker', 'gif'),
    defaultValue: 'text',
    allowNull: false
  },
  
  media_url: {
    type: DataTypes.STRING(500),
    allowNull: true,
    validate: {
      isUrl: true
    },
    comment: 'URL for media messages (images, videos, files, etc.)'
  },
  
  media_metadata: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional metadata for media files (size, duration, dimensions, etc.)'
  },
  
  reply_to_id: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'messages',
      key: 'id'
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    comment: 'ID of the message being replied to'
  },
  
  is_read: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  read_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_delivered: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  delivered_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_edited: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  edited_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_deleted: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  deleted_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  deleted_for: {
    type: DataTypes.ENUM('sender', 'receiver', 'both'),
    allowNull: true,
    comment: 'Who deleted the message'
  },
  
  is_forwarded: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  forwarded_from: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'messages',
      key: 'id'
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    comment: 'Original message ID if this is a forwarded message'
  },
  
  reactions: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: {},
    comment: 'Message reactions (emoji reactions with user IDs)'
  },
  
  mentions: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: [],
    comment: 'Array of user IDs mentioned in the message'
  },
  
  location_data: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Location data for location messages (lat, lng, address)'
  },
  
  contact_data: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Contact information for contact messages'
  },
  
  expires_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'For disappearing messages'
  },
  
  is_pinned: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  pinned_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  encryption_key: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Encryption key for end-to-end encrypted messages'
  }
}, {
  tableName: 'messages',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      fields: ['sender_id']
    },
    {
      fields: ['receiver_id']
    },
    {
      fields: ['conversation_id']
    },
    {
      fields: ['reply_to_id']
    },
    {
      fields: ['is_read']
    },
    {
      fields: ['is_delivered']
    },
    {
      fields: ['is_deleted']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['conversation_id', 'created_at']
    },
    {
      fields: ['sender_id', 'receiver_id', 'created_at']
    },
    {
      fields: ['receiver_id', 'is_read']
    },
    {
      fields: ['expires_at']
    }
  ],
  
  // Validation
  validate: {
    notSelfMessage() {
      if (this.sender_id === this.receiver_id) {
        throw new Error('Users cannot send messages to themselves');
      }
    },
    
    hasContent() {
      if (!this.content && !this.media_url && this.message_type === 'text') {
        throw new Error('Text messages must have content');
      }
    }
  },
  
  // Hooks for maintaining data integrity
  hooks: {
    beforeCreate: (message) => {
      // Generate conversation ID if not provided
      if (!message.conversation_id) {
        const [user1, user2] = message.sender_id < message.receiver_id ? 
          [message.sender_id, message.receiver_id] : 
          [message.receiver_id, message.sender_id];
        message.conversation_id = `${user1}_${user2}`;
      }
    },
    
    beforeUpdate: (message) => {
      if (message.changed('content') || message.changed('media_url')) {
        message.is_edited = true;
        message.edited_at = new Date();
      }
      
      if (message.changed('is_read') && message.is_read && !message.read_at) {
        message.read_at = new Date();
      }
      
      if (message.changed('is_delivered') && message.is_delivered && !message.delivered_at) {
        message.delivered_at = new Date();
      }
    }
  },
  
  // Scopes for common queries
  scopes: {
    active: {
      where: {
        is_deleted: false
      }
    },
    
    unread: {
      where: {
        is_read: false
      }
    },
    
    delivered: {
      where: {
        is_delivered: true
      }
    },
    
    withSender: {
      include: [{
        model: sequelize.models.User,
        as: 'sender',
        attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture']
      }]
    },
    
    withReceiver: {
      include: [{
        model: sequelize.models.User,
        as: 'receiver',
        attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture']
      }]
    },
    
    withUsers: {
      include: [
        {
          model: sequelize.models.User,
          as: 'sender',
          attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture']
        },
        {
          model: sequelize.models.User,
          as: 'receiver',
          attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture']
        }
      ]
    }
  }
});

/**
 * Instance methods
 */

/**
 * Mark message as read
 */
Message.prototype.markAsRead = async function() {
  if (!this.is_read) {
    this.is_read = true;
    this.read_at = new Date();
    await this.save();
  }
};

/**
 * Mark message as delivered
 */
Message.prototype.markAsDelivered = async function() {
  if (!this.is_delivered) {
    this.is_delivered = true;
    this.delivered_at = new Date();
    await this.save();
  }
};

/**
 * Delete message for user
 * @param {string} userId - User ID who is deleting
 */
Message.prototype.deleteForUser = async function(userId) {
  if (userId === this.sender_id && userId === this.receiver_id) {
    // Delete for both (shouldn't happen but handle it)
    this.deleted_for = 'both';
  } else if (userId === this.sender_id) {
    this.deleted_for = this.deleted_for === 'receiver' ? 'both' : 'sender';
  } else if (userId === this.receiver_id) {
    this.deleted_for = this.deleted_for === 'sender' ? 'both' : 'receiver';
  }
  
  if (this.deleted_for === 'both') {
    this.is_deleted = true;
    this.deleted_at = new Date();
  }
  
  await this.save();
};

/**
 * Add reaction to message
 * @param {string} userId - User ID adding reaction
 * @param {string} emoji - Emoji reaction
 */
Message.prototype.addReaction = async function(userId, emoji) {
  const reactions = this.reactions || {};
  if (!reactions[emoji]) {
    reactions[emoji] = [];
  }
  
  if (!reactions[emoji].includes(userId)) {
    reactions[emoji].push(userId);
    this.reactions = reactions;
    await this.save();
  }
};

/**
 * Remove reaction from message
 * @param {string} userId - User ID removing reaction
 * @param {string} emoji - Emoji reaction
 */
Message.prototype.removeReaction = async function(userId, emoji) {
  const reactions = this.reactions || {};
  if (reactions[emoji]) {
    reactions[emoji] = reactions[emoji].filter(id => id !== userId);
    if (reactions[emoji].length === 0) {
      delete reactions[emoji];
    }
    this.reactions = reactions;
    await this.save();
  }
};

/**
 * Check if message is visible to user
 * @param {string} userId - User ID to check
 * @returns {boolean} Visibility status
 */
Message.prototype.isVisibleToUser = function(userId) {
  if (this.is_deleted) {
    return false;
  }
  
  if (this.deleted_for === 'both') {
    return false;
  }
  
  if (userId === this.sender_id && this.deleted_for === 'sender') {
    return false;
  }
  
  if (userId === this.receiver_id && this.deleted_for === 'receiver') {
    return false;
  }
  
  return userId === this.sender_id || userId === this.receiver_id;
};

/**
 * Get message preview for conversation list
 * @returns {string} Message preview
 */
Message.prototype.getPreview = function() {
  if (this.message_type === 'text') {
    return this.content && this.content.length > 50 ? 
      this.content.substring(0, 50) + '...' : 
      this.content || '';
  }
  
  const typeMap = {
    image: '📷 Photo',
    video: '🎥 Video',
    audio: '🎵 Audio',
    file: '📎 File',
    location: '📍 Location',
    contact: '👤 Contact',
    sticker: '😊 Sticker',
    gif: '🎬 GIF'
  };
  
  return typeMap[this.message_type] || 'Message';
};

/**
 * Class methods
 */

/**
 * Get conversation messages
 * @param {string} conversationId - Conversation ID
 * @param {string} userId - User requesting messages
 * @param {number} limit - Number of messages to fetch
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Message[]>} Array of messages
 */
Message.getConversationMessages = async function(conversationId, userId, limit = 50, offset = 0) {
  return await Message.scope(['active', 'withUsers']).findAll({
    where: {
      conversation_id: conversationId,
      [sequelize.Sequelize.Op.or]: [
        { deleted_for: null },
        { deleted_for: { [sequelize.Sequelize.Op.ne]: userId === this.sender_id ? 'sender' : 'receiver' } }
      ]
    },
    order: [['created_at', 'DESC']],
    limit: limit,
    offset: offset
  });
};

/**
 * Get user conversations
 * @param {string} userId - User ID
 * @param {number} limit - Number of conversations to fetch
 * @returns {Promise<Object[]>} Array of conversations with last message
 */
Message.getUserConversations = async function(userId, limit = 20) {
  const conversations = await sequelize.query(`
    SELECT 
      m.conversation_id,
      m.id as last_message_id,
      m.content as last_message_content,
      m.message_type as last_message_type,
      m.created_at as last_message_time,
      m.sender_id as last_sender_id,
      u1.username as other_user_username,
      u1.first_name as other_user_first_name,
      u1.last_name as other_user_last_name,
      u1.profile_picture as other_user_profile_picture,
      u1.is_verified as other_user_verified,
      (SELECT COUNT(*) FROM messages m2 
       WHERE m2.conversation_id = m.conversation_id 
       AND m2.receiver_id = :userId 
       AND m2.is_read = false 
       AND m2.is_deleted = false) as unread_count
    FROM messages m
    INNER JOIN (
      SELECT conversation_id, MAX(created_at) as max_time
      FROM messages 
      WHERE (sender_id = :userId OR receiver_id = :userId)
      AND is_deleted = false
      GROUP BY conversation_id
    ) latest ON m.conversation_id = latest.conversation_id AND m.created_at = latest.max_time
    LEFT JOIN users u1 ON (
      CASE 
        WHEN m.sender_id = :userId THEN u1.id = m.receiver_id
        ELSE u1.id = m.sender_id
      END
    )
    ORDER BY m.created_at DESC
    LIMIT :limit
  `, {
    replacements: { userId, limit },
    type: sequelize.QueryTypes.SELECT
  });
  
  return conversations;
};

/**
 * Mark conversation as read
 * @param {string} conversationId - Conversation ID
 * @param {string} userId - User ID marking as read
 */
Message.markConversationAsRead = async function(conversationId, userId) {
  await Message.update(
    { 
      is_read: true, 
      read_at: new Date() 
    },
    {
      where: {
        conversation_id: conversationId,
        receiver_id: userId,
        is_read: false
      }
    }
  );
};

/**
 * Get unread message count for user
 * @param {string} userId - User ID
 * @returns {Promise<number>} Unread message count
 */
Message.getUnreadCount = async function(userId) {
  return await Message.count({
    where: {
      receiver_id: userId,
      is_read: false,
      is_deleted: false
    }
  });
};

/**
 * Search messages
 * @param {string} userId - User ID searching
 * @param {string} query - Search query
 * @param {number} limit - Number of results
 * @returns {Promise<Message[]>} Array of messages
 */
Message.searchMessages = async function(userId, query, limit = 20) {
  return await Message.scope(['active', 'withUsers']).findAll({
    where: {
      [sequelize.Sequelize.Op.and]: [
        {
          [sequelize.Sequelize.Op.or]: [
            { sender_id: userId },
            { receiver_id: userId }
          ]
        },
        {
          content: {
            [sequelize.Sequelize.Op.like]: `%${query}%`
          }
        }
      ]
    },
    order: [['created_at', 'DESC']],
    limit: limit
  });
};

/**
 * Generate conversation ID for two users
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {string} Conversation ID
 */
Message.generateConversationId = function(userId1, userId2) {
  const [user1, user2] = userId1 < userId2 ? [userId1, userId2] : [userId2, userId1];
  return `${user1}_${user2}`;
};

/**
 * Clean up expired messages
 */
Message.cleanupExpiredMessages = async function() {
  await Message.update(
    { 
      is_deleted: true, 
      deleted_at: new Date(),
      content: null,
      media_url: null
    },
    {
      where: {
        expires_at: {
          [sequelize.Sequelize.Op.lt]: new Date()
        },
        is_deleted: false
      }
    }
  );
};

module.exports = Message;