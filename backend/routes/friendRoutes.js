/**
 * Friend Routes
 * Defines all friend and social connection API endpoints
 */

const express = require('express');
const {
  sendFriendRequest,
  respondToFriendRequest,
  getFriends,
  getFriendRequests,
  removeFriend,
  blockUser,
  unblockUser,
  getBlockedUsers,
  toggleCloseFriend,
  getMutualFriends,
  getFriendSuggestions,
  searchUsers
} = require('../controllers/friendController');

const { authenticate } = require('../middleware/auth');
const { validate, friendSchemas, userSchemas } = require('../middleware/validator');
const { friendRequestRateLimit, searchRateLimit } = require('../middleware/rateLimiting');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');

const router = express.Router();

/**
 * @route   POST /api/v1/friends/request
 * @desc    Send friend request
 * @access  Private
 */
router.post('/request',
  authenticate,
  friendRequestRateLimit,
  validate(friendSchemas.sendFriendRequest),
  sendFriendRequest
);

/**
 * @route   PUT /api/v1/friends/request/:friendId
 * @desc    Respond to friend request (accept/decline/block)
 * @access  Private
 */
router.put('/request/:friendId',
  authenticate,
  validate(friendSchemas.respondToFriendRequest),
  respondToFriendRequest
);

/**
 * @route   GET /api/v1/friends
 * @desc    Get friends list
 * @access  Private
 */
router.get('/',
  authenticate,
  validate(friendSchemas.getFriends, 'query'),
  getFriends
);

/**
 * @route   GET /api/v1/friends/requests
 * @desc    Get friend requests
 * @access  Private
 */
router.get('/requests',
  authenticate,
  validate(friendSchemas.getFriendRequests, 'query'),
  getFriendRequests
);

/**
 * @route   GET /api/v1/friends/suggestions
 * @desc    Get friend suggestions
 * @access  Private
 */
router.get('/suggestions',
  authenticate,
  getFriendSuggestions
);

/**
 * @route   GET /api/v1/friends/blocked
 * @desc    Get blocked users
 * @access  Private
 */
router.get('/blocked',
  authenticate,
  getBlockedUsers
);

/**
 * @route   GET /api/v1/friends/search
 * @desc    Search users for friends
 * @access  Private
 */
router.get('/search',
  authenticate,
  searchRateLimit,
  validate(userSchemas.searchUsers, 'query'),
  searchUsers
);

/**
 * @route   GET /api/v1/friends/:userId/mutual
 * @desc    Get mutual friends
 * @access  Private
 */
router.get('/:userId/mutual',
  authenticate,
  getMutualFriends
);

/**
 * @route   DELETE /api/v1/friends/:friendId
 * @desc    Remove friend
 * @access  Private
 */
router.delete('/:friendId',
  authenticate,
  removeFriend
);

/**
 * @route   POST /api/v1/friends/block
 * @desc    Block user
 * @access  Private
 */
router.post('/block',
  authenticate,
  validate(friendSchemas.blockUser),
  blockUser
);

/**
 * @route   POST /api/v1/friends/unblock
 * @desc    Unblock user
 * @access  Private
 */
router.post('/unblock',
  authenticate,
  validate(friendSchemas.unblockUser),
  unblockUser
);

/**
 * @route   PUT /api/v1/friends/:friendId/close-friend
 * @desc    Toggle close friend status
 * @access  Private
 */
router.put('/:friendId/close-friend',
  authenticate,
  toggleCloseFriend
);

module.exports = router;