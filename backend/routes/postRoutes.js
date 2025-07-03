/**
 * Post Routes
 * Defines all post-related API endpoints
 */

const express = require('express');
const {
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
} = require('../controllers/postController');

const { authenticate, optionalAuth } = require('../middleware/auth');
const { validate, postSchemas } = require('../middleware/validator');
const { postRateLimit, searchRateLimit } = require('../middleware/rateLimiting');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');

const router = express.Router();

/**
 * @route   POST /api/v1/posts
 * @desc    Create new post
 * @access  Private
 */
router.post('/',
  authenticate,
  postRateLimit,
  loggingSQLInjectionFilter,
  validate(postSchemas.createPost),
  createPost
);

/**
 * @route   GET /api/v1/posts/feed
 * @desc    Get user feed
 * @access  Private
 */
router.get('/feed',
  authenticate,
  validate(postSchemas.getFeed, 'query'),
  getFeed
);

/**
 * @route   GET /api/v1/posts/search
 * @desc    Search posts
 * @access  Public
 */
router.get('/search',
  optionalAuth,
  searchRateLimit,
  validate(postSchemas.searchPosts, 'query'),
  searchPosts
);

/**
 * @route   GET /api/v1/posts/trending-hashtags
 * @desc    Get trending hashtags
 * @access  Public
 */
router.get('/trending-hashtags',
  getTrendingHashtags
);

/**
 * @route   GET /api/v1/posts/user/:userId
 * @desc    Get user posts
 * @access  Public
 */
router.get('/user/:userId',
  optionalAuth,
  validate(postSchemas.getUserPosts, 'query'),
  getUserPosts
);

/**
 * @route   GET /api/v1/posts/:id
 * @desc    Get single post
 * @access  Public
 */
router.get('/:id',
  optionalAuth,
  getPost
);

/**
 * @route   PUT /api/v1/posts/:id
 * @desc    Update post
 * @access  Private
 */
router.put('/:id',
  authenticate,
  loggingSQLInjectionFilter,
  validate(postSchemas.updatePost),
  updatePost
);

/**
 * @route   DELETE /api/v1/posts/:id
 * @desc    Delete post
 * @access  Private
 */
router.delete('/:id',
  authenticate,
  deletePost
);

/**
 * @route   POST /api/v1/posts/:id/like
 * @desc    Like/Unlike post
 * @access  Private
 */
router.post('/:id/like',
  authenticate,
  toggleLike
);

/**
 * @route   POST /api/v1/posts/:id/comments
 * @desc    Create comment
 * @access  Private
 */
router.post('/:id/comments',
  authenticate,
  loggingSQLInjectionFilter,
  validate(postSchemas.createComment),
  createComment
);

/**
 * @route   GET /api/v1/posts/:id/comments
 * @desc    Get post comments
 * @access  Public
 */
router.get('/:id/comments',
  optionalAuth,
  getComments
);

/**
 * @route   POST /api/v1/posts/:id/share
 * @desc    Share post
 * @access  Private
 */
router.post('/:id/share',
  authenticate,
  postRateLimit,
  loggingSQLInjectionFilter,
  sharePost
);

/**
 * @route   POST /api/v1/posts/:id/report
 * @desc    Report post
 * @access  Private
 */
router.post('/:id/report',
  authenticate,
  reportPost
);

module.exports = router;