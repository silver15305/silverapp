/**
 * Post Controller
 * Handles post creation, retrieval, updates, likes, comments, and social interactions
 */

const { asyncHandler } = require('../utils/asyncHandler');
const { AppError, ValidationError, NotFoundError, AuthorizationError } = require('../errors/AppError');
const { paginate, removeSensitiveFields } = require('../utils/helpers');
const { logger } = require('../config/logger');
const Post = require('../models/Post');
const User = require('../models/User');
const Notification = require('../models/Notification');

/**
 * Create new post
 * @route POST /api/v1/posts
 */
const createPost = asyncHandler(async (req, res, next) => {
  const {
    content,
    media_urls,
    privacy,
    location,
    tagged_users
  } = req.body;
  
  const userId = req.user.id;

  // Determine media type
  let media_type = 'none';
  if (media_urls && media_urls.length > 0) {
    const hasImages = media_urls.some(url => /\.(jpg|jpeg|png|gif|webp)$/i.test(url));
    const hasVideos = media_urls.some(url => /\.(mp4|avi|mov|wmv|flv|webm)$/i.test(url));
    
    if (hasImages && hasVideos) {
      media_type = 'mixed';
    } else if (hasImages) {
      media_type = 'image';
    } else if (hasVideos) {
      media_type = 'video';
    }
  }

  // Extract hashtags from content
  const hashtags = content ? content.match(/#[\w]+/g) || [] : [];

  // Create post
  const post = await Post.create({
    user_id: userId,
    content,
    media_urls: media_urls || [],
    media_type,
    privacy: privacy || 'public',
    location,
    tagged_users: tagged_users || [],
    hashtags: hashtags.map(tag => tag.toLowerCase())
  });

  // Fetch post with author details
  const createdPost = await Post.scope('withAuthor').findByPk(post.id);

  // Create notifications for tagged users
  if (tagged_users && tagged_users.length > 0) {
    for (const taggedUserId of tagged_users) {
      if (taggedUserId !== userId) {
        await Notification.createNotification({
          userId: taggedUserId,
          fromUserId: userId,
          type: 'post_tag',
          title: 'Tagged in Post',
          message: 'tagged you in a post',
          data: { post_id: post.id },
          actionUrl: `/posts/${post.id}`,
          priority: 'normal',
          category: 'social'
        });
      }
    }
  }

  logger.info(`Post created by user ${userId}`, { postId: post.id });

  res.status(201).json({
    status: 'success',
    message: 'Post created successfully',
    data: {
      post: createdPost
    }
  });
});

/**
 * Get user feed
 * @route GET /api/v1/posts/feed
 */
const getFeed = asyncHandler(async (req, res, next) => {
  const { page = 1, limit = 20 } = req.query;
  const userId = req.user.id;
  const offset = (page - 1) * limit;

  // Get feed posts (public posts + user's own posts + friends' posts)
  const posts = await Post.getFeedPosts(userId, parseInt(limit), offset);

  res.status(200).json({
    status: 'success',
    data: {
      posts,
      pagination: {
        currentPage: parseInt(page),
        totalItems: posts.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: posts.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get single post
 * @route GET /api/v1/posts/:id
 */
const getPost = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const userId = req.user?.id;

  const post = await Post.scope('withAuthor').findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!post.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  res.status(200).json({
    status: 'success',
    data: {
      post
    }
  });
});

/**
 * Get user posts
 * @route GET /api/v1/posts/user/:userId
 */
const getUserPosts = asyncHandler(async (req, res, next) => {
  const { userId } = req.params;
  const { page = 1, limit = 20 } = req.query;
  const viewerId = req.user?.id;
  const offset = (page - 1) * limit;

  // Check if user exists
  const user = await User.findByPk(userId);
  if (!user) {
    return next(new NotFoundError('User not found'));
  }

  const posts = await Post.getUserPosts(userId, viewerId, parseInt(limit), offset);

  res.status(200).json({
    status: 'success',
    data: {
      posts,
      pagination: {
        currentPage: parseInt(page),
        totalItems: posts.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: posts.length === parseInt(limit)
      }
    }
  });
});

/**
 * Update post
 * @route PUT /api/v1/posts/:id
 */
const updatePost = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const {
    content,
    media_urls,
    privacy,
    location,
    tagged_users
  } = req.body;
  const userId = req.user.id;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user owns the post
  if (post.user_id !== userId) {
    return next(new AuthorizationError('You can only edit your own posts'));
  }

  // Update media type if media_urls changed
  let media_type = post.media_type;
  if (media_urls !== undefined) {
    media_type = 'none';
    if (media_urls && media_urls.length > 0) {
      const hasImages = media_urls.some(url => /\.(jpg|jpeg|png|gif|webp)$/i.test(url));
      const hasVideos = media_urls.some(url => /\.(mp4|avi|mov|wmv|flv|webm)$/i.test(url));
      
      if (hasImages && hasVideos) {
        media_type = 'mixed';
      } else if (hasImages) {
        media_type = 'image';
      } else if (hasVideos) {
        media_type = 'video';
      }
    }
  }

  // Extract hashtags from content
  const hashtags = content ? content.match(/#[\w]+/g) || [] : post.hashtags;

  // Update post
  await post.update({
    content: content !== undefined ? content : post.content,
    media_urls: media_urls !== undefined ? media_urls : post.media_urls,
    media_type,
    privacy: privacy !== undefined ? privacy : post.privacy,
    location: location !== undefined ? location : post.location,
    tagged_users: tagged_users !== undefined ? tagged_users : post.tagged_users,
    hashtags: hashtags.map(tag => tag.toLowerCase())
  });

  // Fetch updated post with author details
  const updatedPost = await Post.scope('withAuthor').findByPk(post.id);

  logger.info(`Post updated by user ${userId}`, { postId: post.id });

  res.status(200).json({
    status: 'success',
    message: 'Post updated successfully',
    data: {
      post: updatedPost
    }
  });
});

/**
 * Delete post
 * @route DELETE /api/v1/posts/:id
 */
const deletePost = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user owns the post or is admin
  if (post.user_id !== userId && req.user.role !== 'admin') {
    return next(new AuthorizationError('You can only delete your own posts'));
  }

  // Soft delete
  await post.update({
    is_deleted: true,
    deleted_at: new Date()
  });

  logger.info(`Post deleted by user ${userId}`, { postId: post.id });

  res.status(200).json({
    status: 'success',
    message: 'Post deleted successfully'
  });
});

/**
 * Like/Unlike post
 * @route POST /api/v1/posts/:id/like
 */
const toggleLike = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!post.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  // Check if user already liked the post (this would be in a separate likes table in production)
  // For now, we'll use Redis to track likes
  const likeKey = `post_like:${id}:${userId}`;
  const isLiked = await require('../services/redis').exists(likeKey);

  if (isLiked) {
    // Unlike
    await require('../services/redis').del(likeKey);
    await post.decrementLikes();
    
    res.status(200).json({
      status: 'success',
      message: 'Post unliked',
      data: {
        liked: false,
        likes_count: post.likes_count
      }
    });
  } else {
    // Like
    await require('../services/redis').set(likeKey, '1', 86400 * 30); // 30 days
    await post.incrementLikes();

    // Create notification for post owner
    if (post.user_id !== userId) {
      await Notification.createLikeNotification(post.user_id, userId, post.id);
    }

    res.status(200).json({
      status: 'success',
      message: 'Post liked',
      data: {
        liked: true,
        likes_count: post.likes_count
      }
    });
  }

  logger.info(`Post ${isLiked ? 'unliked' : 'liked'} by user ${userId}`, { postId: id });
});

/**
 * Create comment
 * @route POST /api/v1/posts/:id/comments
 */
const createComment = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { content, media_urls } = req.body;
  const userId = req.user.id;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!post.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  // Determine media type for comment
  let media_type = 'none';
  if (media_urls && media_urls.length > 0) {
    const hasImages = media_urls.some(url => /\.(jpg|jpeg|png|gif|webp)$/i.test(url));
    const hasVideos = media_urls.some(url => /\.(mp4|avi|mov|wmv|flv|webm)$/i.test(url));
    
    if (hasImages && hasVideos) {
      media_type = 'mixed';
    } else if (hasImages) {
      media_type = 'image';
    } else if (hasVideos) {
      media_type = 'video';
    }
  }

  // Create comment
  const comment = await Post.create({
    user_id: userId,
    parent_id: id,
    post_type: 'comment',
    content,
    media_urls: media_urls || [],
    media_type,
    privacy: 'public' // Comments inherit post privacy
  });

  // Increment comments count on parent post
  await post.incrementComments();

  // Fetch comment with author details
  const createdComment = await Post.scope('withAuthor').findByPk(comment.id);

  // Create notification for post owner
  if (post.user_id !== userId) {
    await Notification.createCommentNotification(post.user_id, userId, post.id, comment.id);
  }

  logger.info(`Comment created by user ${userId}`, { postId: id, commentId: comment.id });

  res.status(201).json({
    status: 'success',
    message: 'Comment created successfully',
    data: {
      comment: createdComment
    }
  });
});

/**
 * Get post comments
 * @route GET /api/v1/posts/:id/comments
 */
const getComments = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { page = 1, limit = 20 } = req.query;
  const userId = req.user?.id;
  const offset = (page - 1) * limit;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!post.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  const comments = await Post.getComments(id, parseInt(limit), offset);

  res.status(200).json({
    status: 'success',
    data: {
      comments,
      pagination: {
        currentPage: parseInt(page),
        totalItems: comments.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: comments.length === parseInt(limit)
      }
    }
  });
});

/**
 * Share post
 * @route POST /api/v1/posts/:id/share
 */
const sharePost = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { content, privacy } = req.body;
  const userId = req.user.id;

  const originalPost = await Post.findByPk(id);

  if (!originalPost) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!originalPost.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  // Create share post
  const sharePost = await Post.create({
    user_id: userId,
    post_type: 'share',
    shared_post_id: id,
    content: content || '',
    privacy: privacy || 'public'
  });

  // Increment shares count on original post
  await originalPost.incrementShares();

  // Fetch share post with author details
  const createdShare = await Post.scope('withAuthor').findByPk(sharePost.id);

  logger.info(`Post shared by user ${userId}`, { originalPostId: id, sharePostId: sharePost.id });

  res.status(201).json({
    status: 'success',
    message: 'Post shared successfully',
    data: {
      post: createdShare
    }
  });
});

/**
 * Search posts
 * @route GET /api/v1/posts/search
 */
const searchPosts = asyncHandler(async (req, res, next) => {
  const { query, page = 1, limit = 20 } = req.query;

  if (!query || query.trim().length === 0) {
    return next(new ValidationError('Search query is required'));
  }

  const posts = await Post.searchPosts(query.trim(), parseInt(limit));

  res.status(200).json({
    status: 'success',
    data: {
      posts,
      query: query.trim(),
      pagination: {
        currentPage: parseInt(page),
        totalItems: posts.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: posts.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get trending hashtags
 * @route GET /api/v1/posts/trending-hashtags
 */
const getTrendingHashtags = asyncHandler(async (req, res, next) => {
  const { limit = 10 } = req.query;

  // This would typically be calculated from a separate hashtags table
  // For now, we'll return a mock response
  const trendingHashtags = [
    { hashtag: '#silverapp', count: 1250 },
    { hashtag: '#socialmedia', count: 890 },
    { hashtag: '#technology', count: 675 },
    { hashtag: '#mobile', count: 543 },
    { hashtag: '#flutter', count: 432 }
  ].slice(0, parseInt(limit));

  res.status(200).json({
    status: 'success',
    data: {
      hashtags: trendingHashtags
    }
  });
});

/**
 * Report post
 * @route POST /api/v1/posts/:id/report
 */
const reportPost = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { reason, description } = req.body;
  const userId = req.user.id;

  const post = await Post.findByPk(id);

  if (!post) {
    return next(new NotFoundError('Post not found'));
  }

  // Check if user can view this post
  if (!post.canUserView(userId)) {
    return next(new AuthorizationError('Access denied'));
  }

  // Update post report status
  await post.update({
    is_reported: true,
    report_count: post.report_count + 1
  });

  // Log the report (in production, this would be stored in a reports table)
  logger.warn(`Post reported by user ${userId}`, {
    postId: id,
    reason,
    description,
    reportedBy: userId
  });

  res.status(200).json({
    status: 'success',
    message: 'Post reported successfully'
  });
});

module.exports = {
  createPost,
  getFeed,
  getPost,
  getUserPosts,
  updatePost,
  deletePost,
  toggleLike,
  createComment,
  getComments,
  sharePost,
  searchPosts,
  getTrendingHashtags,
  reportPost
};