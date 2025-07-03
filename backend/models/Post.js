/**
 * Post Model
 * Defines the post schema for social media posts, comments, and interactions
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * Post model definition
 */
const Post = sequelize.define('Post', {
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
  
  content: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 5000] // Maximum 5000 characters
    }
  },
  
  media_urls: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: [],
    comment: 'Array of media URLs (images, videos)'
  },
  
  media_type: {
    type: DataTypes.ENUM('none', 'image', 'video', 'mixed'),
    defaultValue: 'none',
    allowNull: false
  },
  
  post_type: {
    type: DataTypes.ENUM('post', 'comment', 'share'),
    defaultValue: 'post',
    allowNull: false
  },
  
  parent_id: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'posts',
      key: 'id'
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    comment: 'For comments and shares - references the original post'
  },
  
  shared_post_id: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'posts',
      key: 'id'
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    comment: 'For shared posts - references the shared post'
  },
  
  privacy: {
    type: DataTypes.ENUM('public', 'friends', 'private'),
    defaultValue: 'public',
    allowNull: false
  },
  
  location: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  
  tagged_users: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: [],
    comment: 'Array of user IDs tagged in the post'
  },
  
  hashtags: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: [],
    comment: 'Array of hashtags used in the post'
  },
  
  likes_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  comments_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  shares_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    }
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
  
  is_reported: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  report_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  
  is_pinned: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  
  scheduled_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'For scheduled posts'
  },
  
  is_published: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    allowNull: false
  }
}, {
  tableName: 'posts',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  
  // Indexes for better performance
  indexes: [
    {
      fields: ['user_id']
    },
    {
      fields: ['parent_id']
    },
    {
      fields: ['shared_post_id']
    },
    {
      fields: ['post_type']
    },
    {
      fields: ['privacy']
    },
    {
      fields: ['is_deleted']
    },
    {
      fields: ['is_published']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['likes_count']
    },
    {
      fields: ['comments_count']
    },
    {
      fields: ['user_id', 'created_at']
    },
    {
      fields: ['parent_id', 'created_at']
    }
  ],
  
  // Hooks for maintaining data integrity
  hooks: {
    beforeUpdate: (post) => {
      if (post.changed('content') || post.changed('media_urls')) {
        post.is_edited = true;
        post.edited_at = new Date();
      }
    },
    
    beforeDestroy: (post) => {
      post.is_deleted = true;
      post.deleted_at = new Date();
    }
  },
  
  // Scopes for common queries
  scopes: {
    published: {
      where: {
        is_published: true,
        is_deleted: false
      }
    },
    
    public: {
      where: {
        privacy: 'public',
        is_published: true,
        is_deleted: false
      }
    },
    
    posts: {
      where: {
        post_type: 'post'
      }
    },
    
    comments: {
      where: {
        post_type: 'comment'
      }
    },
    
    withAuthor: {
      include: [{
        model: sequelize.models.User,
        as: 'author',
        attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified']
      }]
    }
  }
});

/**
 * Instance methods
 */

/**
 * Increment likes count
 */
Post.prototype.incrementLikes = async function() {
  this.likes_count += 1;
  await this.save();
};

/**
 * Decrement likes count
 */
Post.prototype.decrementLikes = async function() {
  if (this.likes_count > 0) {
    this.likes_count -= 1;
    await this.save();
  }
};

/**
 * Increment comments count
 */
Post.prototype.incrementComments = async function() {
  this.comments_count += 1;
  await this.save();
};

/**
 * Decrement comments count
 */
Post.prototype.decrementComments = async function() {
  if (this.comments_count > 0) {
    this.comments_count -= 1;
    await this.save();
  }
};

/**
 * Increment shares count
 */
Post.prototype.incrementShares = async function() {
  this.shares_count += 1;
  await this.save();
};

/**
 * Check if user can view this post with complete privacy logic
 * @param {string} userId - User ID to check
 * @returns {Promise<boolean>} Whether user can view the post
 */
Post.prototype.canUserView = async function(userId) {
  if (this.is_deleted || !this.is_published) {
    return false;
  }
  
  if (this.privacy === 'public') {
    return true;
  }
  
  if (this.privacy === 'private' && this.user_id !== userId) {
    return false;
  }
  
  // Handle 'friends' privacy
  if (this.privacy === 'friends') {
    // Post owner can always view their own posts
    if (this.user_id === userId) {
      return true;
    }
    
    // Check if viewer is friends with post owner
    const Friend = sequelize.models.Friend;
    if (Friend) {
      const areFriends = await Friend.areFriends(userId, this.user_id);
      return areFriends;
    }
    
    // If Friend model is not available, deny access for safety
    return false;
  }
  
  return true;
};

/**
 * Get post summary for notifications
 * @returns {string} Post summary
 */
Post.prototype.getSummary = function() {
  if (this.content) {
    return this.content.length > 50 ? 
      this.content.substring(0, 50) + '...' : 
      this.content;
  }
  
  if (this.media_urls && this.media_urls.length > 0) {
    return `Shared ${this.media_type === 'image' ? 'a photo' : 'a video'}`;
  }
  
  return 'Shared a post';
};

/**
 * Extract hashtags from content
 * @returns {Array} Array of hashtags
 */
Post.prototype.extractHashtags = function() {
  if (!this.content) return [];
  
  const hashtagRegex = /#[\w]+/g;
  const hashtags = this.content.match(hashtagRegex) || [];
  return hashtags.map(tag => tag.toLowerCase());
};

/**
 * Extract mentions from content
 * @returns {Array} Array of mentioned usernames
 */
Post.prototype.extractMentions = function() {
  if (!this.content) return [];
  
  const mentionRegex = /@[\w]+/g;
  const mentions = this.content.match(mentionRegex) || [];
  return mentions.map(mention => mention.substring(1).toLowerCase());
};

/**
 * Class methods
 */

/**
 * Get feed posts for a user with complete privacy logic
 * @param {string} userId - User ID
 * @param {number} limit - Number of posts to fetch
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Post[]>} Array of posts
 */
Post.getFeedPosts = async function(userId, limit = 20, offset = 0) {
  const Friend = sequelize.models.Friend;
  
  // Get user's friend IDs
  let friendIds = [];
  if (Friend) {
    try {
      const friendships = await Friend.getUserFriends(userId);
      friendIds = friendships.map(friendship => 
        friendship.user_id === userId ? friendship.friend_id : friendship.user_id
      );
    } catch (error) {
      console.error('Error getting friends for feed:', error);
    }
  }
  
  // Build where clause for feed posts
  const whereClause = {
    post_type: 'post',
    [sequelize.Sequelize.Op.or]: [
      // Public posts
      { privacy: 'public' },
      // User's own posts
      { user_id: userId },
      // Friends' posts (only if user has friends)
      ...(friendIds.length > 0 ? [{
        privacy: 'friends',
        user_id: { [sequelize.Sequelize.Op.in]: friendIds }
      }] : [])
    ]
  };
  
  return await Post.scope(['published', 'withAuthor']).findAll({
    where: whereClause,
    order: [['created_at', 'DESC']],
    limit: limit,
    offset: offset
  });
};

/**
 * Get user's posts with complete privacy logic
 * @param {string} userId - User ID
 * @param {string} viewerId - Viewer's user ID
 * @param {number} limit - Number of posts to fetch
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Post[]>} Array of posts
 */
Post.getUserPosts = async function(userId, viewerId, limit = 20, offset = 0) {
  const whereClause = {
    user_id: userId,
    post_type: 'post',
    is_deleted: false,
    is_published: true
  };
  
  // If viewing own posts, show all privacy levels
  if (userId !== viewerId) {
    const Friend = sequelize.models.Friend;
    let areFriends = false;
    
    // Check if viewer is friends with the user
    if (Friend && viewerId) {
      try {
        areFriends = await Friend.areFriends(viewerId, userId);
      } catch (error) {
        console.error('Error checking friendship for user posts:', error);
      }
    }
    
    // Determine which privacy levels the viewer can see
    if (areFriends) {
      // Friends can see public and friends posts
      whereClause.privacy = { [sequelize.Sequelize.Op.in]: ['public', 'friends'] };
    } else {
      // Non-friends can only see public posts
      whereClause.privacy = 'public';
    }
  }
  
  return await Post.scope('withAuthor').findAll({
    where: whereClause,
    order: [['created_at', 'DESC']],
    limit: limit,
    offset: offset
  });
};

/**
 * Get post comments
 * @param {string} postId - Post ID
 * @param {number} limit - Number of comments to fetch
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Post[]>} Array of comments
 */
Post.getComments = async function(postId, limit = 20, offset = 0) {
  return await Post.scope('withAuthor').findAll({
    where: {
      parent_id: postId,
      post_type: 'comment',
      is_deleted: false,
      is_published: true
    },
    order: [['created_at', 'ASC']],
    limit: limit,
    offset: offset
  });
};

/**
 * Search posts by content
 * @param {string} query - Search query
 * @param {number} limit - Number of posts to fetch
 * @returns {Promise<Post[]>} Array of posts
 */
Post.searchPosts = async function(query, limit = 20) {
  return await Post.scope(['published', 'public', 'withAuthor']).findAll({
    where: {
      post_type: 'post',
      content: {
        [sequelize.Sequelize.Op.like]: `%${query}%`
      }
    },
    order: [['created_at', 'DESC']],
    limit: limit
  });
};

module.exports = Post;