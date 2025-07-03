/**
 * Notification Model
 * Defines the notification schema for user notifications
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * Notification model definition
 */
const Notification = sequelize.define('Notification', {
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
    onUpdate: 'CASCADE',
    comment: 'User who receives the notification'
  },
  
  from_user_id: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    comment: 'User who triggered the notification'
  },
  
  type: {
    type: DataTypes.ENUM(
      'like', 'comment', 'share', 'follow', 'friend_request', 
      'friend_accept', 'mention', 'message', 'post_tag', 
      'birthday', 'memory', 'event', 'group_invite', 'system'
    ),
    allowNull: false
  },
  
  title: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      len: [1, 255]
    }
  },
  
  message: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 1000]
    }
  },
  
  data: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional data related to the notification (post_id, comment_id, etc.)'
  },
  
  action_url: {
    type: DataTypes.STRING(500),
    allowNull: true,
    comment: 'URL to navigate when notification is clicked'
  },
  
  icon: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Icon identifier for the notification'
  },
  
  image_url: {
    type: DataTypes.STRING(500),
    allowNull: true,
    validate: {
      isUrl: true
    },
    comment: 'Image URL for rich notifications'
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
  
  is_seen: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'Whether notification has been seen in the notification list'
  },
  
  seen_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_clicked: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  clicked_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  priority: {
    type: DataTypes.ENUM('low', 'normal', 'high', 'urgent'),
    defaultValue: 'normal',
    allowNull: false
  },
  
  category: {
    type: DataTypes.ENUM('social', 'system', 'promotional', 'security'),
    defaultValue: 'social',
    allowNull: false
  },
  
  is_push_sent: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'Whether push notification was sent'
  },
  
  push_sent_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_email_sent: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'Whether email notification was sent'
  },
  
  email_sent_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  is_sms_sent: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'Whether SMS notification was sent'
  },
  
  sms_sent_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  
  expires_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the notification expires and should be hidden'
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
  
  metadata: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional metadata for analytics and tracking'
  }
}, {
  tableName: 'notifications',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      fields: ['user_id']
    },
    {
      fields: ['from_user_id']
    },
    {
      fields: ['type']
    },
    {
      fields: ['is_read']
    },
    {
      fields: ['is_seen']
    },
    {
      fields: ['priority']
    },
    {
      fields: ['category']
    },
    {
      fields: ['is_deleted']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['expires_at']
    },
    {
      fields: ['user_id', 'is_read']
    },
    {
      fields: ['user_id', 'is_seen']
    },
    {
      fields: ['user_id', 'created_at']
    },
    {
      fields: ['user_id', 'type', 'created_at']
    }
  ],
  
  // Hooks for maintaining data integrity
  hooks: {
    beforeUpdate: (notification) => {
      if (notification.changed('is_read') && notification.is_read && !notification.read_at) {
        notification.read_at = new Date();
      }
      
      if (notification.changed('is_seen') && notification.is_seen && !notification.seen_at) {
        notification.seen_at = new Date();
      }
      
      if (notification.changed('is_clicked') && notification.is_clicked && !notification.clicked_at) {
        notification.clicked_at = new Date();
      }
    }
  },
  
  // Scopes for common queries
  scopes: {
    active: {
      where: {
        is_deleted: false,
        [sequelize.Sequelize.Op.or]: [
          { expires_at: null },
          { expires_at: { [sequelize.Sequelize.Op.gt]: new Date() } }
        ]
      }
    },
    
    unread: {
      where: {
        is_read: false
      }
    },
    
    unseen: {
      where: {
        is_seen: false
      }
    },
    
    byPriority: (priority) => ({
      where: {
        priority: priority
      }
    }),
    
    byCategory: (category) => ({
      where: {
        category: category
      }
    }),
    
    byType: (type) => ({
      where: {
        type: type
      }
    }),
    
    withFromUser: {
      include: [{
        model: sequelize.models.User,
        as: 'fromUser',
        attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified']
      }]
    },
    
    recent: {
      order: [['created_at', 'DESC']]
    }
  }
});

/**
 * Instance methods
 */

/**
 * Mark notification as read
 */
Notification.prototype.markAsRead = async function() {
  if (!this.is_read) {
    this.is_read = true;
    this.read_at = new Date();
    await this.save();
  }
};

/**
 * Mark notification as seen
 */
Notification.prototype.markAsSeen = async function() {
  if (!this.is_seen) {
    this.is_seen = true;
    this.seen_at = new Date();
    await this.save();
  }
};

/**
 * Mark notification as clicked
 */
Notification.prototype.markAsClicked = async function() {
  if (!this.is_clicked) {
    this.is_clicked = true;
    this.clicked_at = new Date();
    
    // Also mark as read and seen when clicked
    if (!this.is_read) {
      this.is_read = true;
      this.read_at = new Date();
    }
    
    if (!this.is_seen) {
      this.is_seen = true;
      this.seen_at = new Date();
    }
    
    await this.save();
  }
};

/**
 * Soft delete notification
 */
Notification.prototype.softDelete = async function() {
  this.is_deleted = true;
  this.deleted_at = new Date();
  await this.save();
};

/**
 * Check if notification is expired
 * @returns {boolean} Expiration status
 */
Notification.prototype.isExpired = function() {
  return this.expires_at && new Date() > this.expires_at;
};

/**
 * Get notification display text
 * @returns {string} Display text
 */
Notification.prototype.getDisplayText = function() {
  return this.message || this.title;
};

/**
 * Mark push notification as sent
 */
Notification.prototype.markPushSent = async function() {
  this.is_push_sent = true;
  this.push_sent_at = new Date();
  await this.save();
};

/**
 * Mark email notification as sent
 */
Notification.prototype.markEmailSent = async function() {
  this.is_email_sent = true;
  this.email_sent_at = new Date();
  await this.save();
};

/**
 * Mark SMS notification as sent
 */
Notification.prototype.markSmsSent = async function() {
  this.is_sms_sent = true;
  this.sms_sent_at = new Date();
  await this.save();
};

/**
 * Class methods
 */

/**
 * Create notification
 * @param {Object} notificationData - Notification data
 * @returns {Promise<Notification>} Created notification
 */
Notification.createNotification = async function(notificationData) {
  const {
    userId,
    fromUserId,
    type,
    title,
    message,
    data,
    actionUrl,
    priority = 'normal',
    category = 'social',
    expiresAt
  } = notificationData;
  
  return await Notification.create({
    user_id: userId,
    from_user_id: fromUserId,
    type,
    title,
    message,
    data,
    action_url: actionUrl,
    priority,
    category,
    expires_at: expiresAt
  });
};

/**
 * Get user notifications
 * @param {string} userId - User ID
 * @param {number} limit - Number of notifications to fetch
 * @param {number} offset - Offset for pagination
 * @param {string} category - Filter by category
 * @returns {Promise<Notification[]>} Array of notifications
 */
Notification.getUserNotifications = async function(userId, limit = 20, offset = 0, category = null) {
  const whereClause = {
    user_id: userId
  };
  
  if (category) {
    whereClause.category = category;
  }
  
  return await Notification.scope(['active', 'withFromUser', 'recent']).findAll({
    where: whereClause,
    limit: limit,
    offset: offset
  });
};

/**
 * Get unread notification count
 * @param {string} userId - User ID
 * @param {string} category - Filter by category
 * @returns {Promise<number>} Unread count
 */
Notification.getUnreadCount = async function(userId, category = null) {
  const whereClause = {
    user_id: userId,
    is_read: false,
    is_deleted: false,
    [sequelize.Sequelize.Op.or]: [
      { expires_at: null },
      { expires_at: { [sequelize.Sequelize.Op.gt]: new Date() } }
    ]
  };
  
  if (category) {
    whereClause.category = category;
  }
  
  return await Notification.count({ where: whereClause });
};

/**
 * Get unseen notification count
 * @param {string} userId - User ID
 * @returns {Promise<number>} Unseen count
 */
Notification.getUnseenCount = async function(userId) {
  return await Notification.count({
    where: {
      user_id: userId,
      is_seen: false,
      is_deleted: false,
      [sequelize.Sequelize.Op.or]: [
        { expires_at: null },
        { expires_at: { [sequelize.Sequelize.Op.gt]: new Date() } }
      ]
    }
  });
};

/**
 * Mark all notifications as read for user
 * @param {string} userId - User ID
 * @param {string} category - Filter by category
 */
Notification.markAllAsRead = async function(userId, category = null) {
  const whereClause = {
    user_id: userId,
    is_read: false
  };
  
  if (category) {
    whereClause.category = category;
  }
  
  await Notification.update(
    { 
      is_read: true, 
      read_at: new Date() 
    },
    { where: whereClause }
  );
};

/**
 * Mark all notifications as seen for user
 * @param {string} userId - User ID
 */
Notification.markAllAsSeen = async function(userId) {
  await Notification.update(
    { 
      is_seen: true, 
      seen_at: new Date() 
    },
    {
      where: {
        user_id: userId,
        is_seen: false
      }
    }
  );
};

/**
 * Delete old notifications
 * @param {number} daysOld - Days old threshold
 */
Notification.deleteOldNotifications = async function(daysOld = 30) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysOld);
  
  await Notification.update(
    { 
      is_deleted: true, 
      deleted_at: new Date() 
    },
    {
      where: {
        created_at: {
          [sequelize.Sequelize.Op.lt]: cutoffDate
        },
        is_deleted: false
      }
    }
  );
};

/**
 * Clean up expired notifications
 */
Notification.cleanupExpiredNotifications = async function() {
  await Notification.update(
    { 
      is_deleted: true, 
      deleted_at: new Date() 
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

/**
 * Get notification statistics for user
 * @param {string} userId - User ID
 * @returns {Promise<Object>} Notification statistics
 */
Notification.getUserStats = async function(userId) {
  const stats = await Notification.findAll({
    where: {
      user_id: userId,
      is_deleted: false
    },
    attributes: [
      'category',
      [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
      [sequelize.fn('SUM', sequelize.literal('CASE WHEN is_read = false THEN 1 ELSE 0 END')), 'unread'],
      [sequelize.fn('SUM', sequelize.literal('CASE WHEN is_seen = false THEN 1 ELSE 0 END')), 'unseen']
    ],
    group: ['category'],
    raw: true
  });
  
  return stats.reduce((acc, stat) => {
    acc[stat.category] = {
      total: parseInt(stat.total),
      unread: parseInt(stat.unread),
      unseen: parseInt(stat.unseen)
    };
    return acc;
  }, {});
};

/**
 * Create friend request notification
 * @param {string} userId - User receiving notification
 * @param {string} fromUserId - User sending friend request
 * @returns {Promise<Notification>} Created notification
 */
Notification.createFriendRequestNotification = async function(userId, fromUserId) {
  return await Notification.createNotification({
    userId,
    fromUserId,
    type: 'friend_request',
    title: 'New Friend Request',
    message: 'sent you a friend request',
    actionUrl: `/friends/requests`,
    priority: 'normal',
    category: 'social'
  });
};

/**
 * Create like notification
 * @param {string} userId - Post owner
 * @param {string} fromUserId - User who liked
 * @param {string} postId - Post ID
 * @returns {Promise<Notification>} Created notification
 */
Notification.createLikeNotification = async function(userId, fromUserId, postId) {
  return await Notification.createNotification({
    userId,
    fromUserId,
    type: 'like',
    title: 'Post Liked',
    message: 'liked your post',
    data: { post_id: postId },
    actionUrl: `/posts/${postId}`,
    priority: 'low',
    category: 'social'
  });
};

/**
 * Create comment notification
 * @param {string} userId - Post owner
 * @param {string} fromUserId - User who commented
 * @param {string} postId - Post ID
 * @param {string} commentId - Comment ID
 * @returns {Promise<Notification>} Created notification
 */
Notification.createCommentNotification = async function(userId, fromUserId, postId, commentId) {
  return await Notification.createNotification({
    userId,
    fromUserId,
    type: 'comment',
    title: 'New Comment',
    message: 'commented on your post',
    data: { post_id: postId, comment_id: commentId },
    actionUrl: `/posts/${postId}#comment-${commentId}`,
    priority: 'normal',
    category: 'social'
  });
};

module.exports = Notification;