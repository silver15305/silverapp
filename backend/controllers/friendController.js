/**
 * Friend Controller
 * Handles friend requests, friendships, blocking, and social connections
 */

const { asyncHandler } = require('../utils/asyncHandler');
const { AppError, ValidationError, NotFoundError, AuthorizationError, ConflictError } = require('../errors/AppError');
const { removeSensitiveFields } = require('../utils/helpers');
const { logger } = require('../config/logger');
const Friend = require('../models/Friend');
const User = require('../models/User');
const Notification = require('../models/Notification');

/**
 * Send friend request
 * @route POST /api/v1/friends/request
 */
const sendFriendRequest = asyncHandler(async (req, res, next) => {
  const { friend_id } = req.body;
  const userId = req.user.id;

  // Check if trying to add self
  if (userId === friend_id) {
    return next(new ValidationError('You cannot send a friend request to yourself'));
  }

  // Check if friend exists
  const friend = await User.findByPk(friend_id);
  if (!friend) {
    return next(new NotFoundError('User not found'));
  }

  // Check if friend is active
  if (!friend.is_active) {
    return next(new ValidationError('User account is not active'));
  }

  try {
    // Send friend request
    const friendship = await Friend.sendRequest(userId, friend_id);

    // Create notification for the friend
    await Notification.createFriendRequestNotification(friend_id, userId);

    logger.info(`Friend request sent from ${userId} to ${friend_id}`, { friendshipId: friendship.id });

    res.status(201).json({
      status: 'success',
      message: 'Friend request sent successfully',
      data: {
        friendship
      }
    });
  } catch (error) {
    if (error.message.includes('already')) {
      return next(new ConflictError(error.message));
    }
    throw error;
  }
});

/**
 * Respond to friend request (accept/decline/block)
 * @route PUT /api/v1/friends/request/:friendId
 */
const respondToFriendRequest = asyncHandler(async (req, res, next) => {
  const { friendId } = req.params;
  const { action } = req.body; // accept, decline, block
  const userId = req.user.id;

  // Find the friendship
  const friendship = await Friend.findExistingFriendship(userId, friendId);

  if (!friendship) {
    return next(new NotFoundError('Friend request not found'));
  }

  // Check if request is pending and user is the recipient
  if (friendship.status !== 'pending') {
    return next(new ValidationError('Friend request is not pending'));
  }

  if (friendship.requested_by === userId) {
    return next(new ValidationError('You cannot respond to your own friend request'));
  }

  let message = '';
  
  switch (action) {
    case 'accept':
      await friendship.accept();
      message = 'Friend request accepted';
      
      // Create notification for the requester
      await Notification.createNotification({
        userId: friendship.requested_by,
        fromUserId: userId,
        type: 'friend_accept',
        title: 'Friend Request Accepted',
        message: 'accepted your friend request',
        actionUrl: `/profile/${userId}`,
        priority: 'normal',
        category: 'social'
      });
      break;
      
    case 'decline':
      await friendship.decline();
      message = 'Friend request declined';
      break;
      
    case 'block':
      await friendship.block(userId);
      message = 'User blocked';
      break;
      
    default:
      return next(new ValidationError('Invalid action. Use accept, decline, or block'));
  }

  logger.info(`Friend request ${action}ed by ${userId}`, { 
    friendshipId: friendship.id, 
    requestedBy: friendship.requested_by 
  });

  res.status(200).json({
    status: 'success',
    message,
    data: {
      friendship
    }
  });
});

/**
 * Get friends list
 * @route GET /api/v1/friends
 */
const getFriends = asyncHandler(async (req, res, next) => {
  const { userId, page = 1, limit = 50 } = req.query;
  const requesterId = req.user.id;
  const targetUserId = userId || requesterId;
  const offset = (page - 1) * limit;

  // Check if requesting another user's friends
  if (targetUserId !== requesterId) {
    const targetUser = await User.findByPk(targetUserId);
    if (!targetUser) {
      return next(new NotFoundError('User not found'));
    }
    
    // Check if target user's profile is private
    if (targetUser.is_private) {
      const areFriends = await Friend.areFriends(requesterId, targetUserId);
      if (!areFriends) {
        return next(new AuthorizationError('This user\'s friends list is private'));
      }
    }
  }

  const friends = await Friend.getUserFriends(targetUserId, parseInt(limit), offset);

  // Format friends data
  const formattedFriends = friends.map(friendship => {
    const friend = friendship.user_id === targetUserId ? friendship.friend : friendship.user;
    return {
      ...removeSensitiveFields(friend.toJSON()),
      friendship_date: friendship.accepted_at,
      is_close_friend: friendship.is_close_friend
    };
  });

  res.status(200).json({
    status: 'success',
    data: {
      friends: formattedFriends,
      pagination: {
        currentPage: parseInt(page),
        totalItems: formattedFriends.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: formattedFriends.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get friend requests
 * @route GET /api/v1/friends/requests
 */
const getFriendRequests = asyncHandler(async (req, res, next) => {
  const { type = 'received', page = 1, limit = 20 } = req.query;
  const userId = req.user.id;

  let requests;
  
  if (type === 'received') {
    requests = await Friend.getPendingRequests(userId);
  } else if (type === 'sent') {
    requests = await Friend.getSentRequests(userId);
  } else {
    return next(new ValidationError('Invalid type. Use received or sent'));
  }

  // Format requests data
  const formattedRequests = requests.map(friendship => {
    const otherUser = friendship.requested_by === userId ? 
      (friendship.user_id === userId ? friendship.friend : friendship.user) :
      friendship.user || friendship.friend;
      
    return {
      friendship_id: friendship.id,
      user: removeSensitiveFields(otherUser.toJSON()),
      requested_at: friendship.requested_at,
      requested_by: friendship.requested_by
    };
  });

  res.status(200).json({
    status: 'success',
    data: {
      requests: formattedRequests,
      type,
      pagination: {
        currentPage: parseInt(page),
        totalItems: formattedRequests.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: formattedRequests.length === parseInt(limit)
      }
    }
  });
});

/**
 * Remove friend
 * @route DELETE /api/v1/friends/:friendId
 */
const removeFriend = asyncHandler(async (req, res, next) => {
  const { friendId } = req.params;
  const userId = req.user.id;

  // Find the friendship
  const friendship = await Friend.findExistingFriendship(userId, friendId);

  if (!friendship) {
    return next(new NotFoundError('Friendship not found'));
  }

  // Check if they are actually friends
  if (friendship.status !== 'accepted') {
    return next(new ValidationError('You are not friends with this user'));
  }

  // Remove friendship (soft delete)
  await friendship.destroy();

  logger.info(`Friendship removed between ${userId} and ${friendId}`, { friendshipId: friendship.id });

  res.status(200).json({
    status: 'success',
    message: 'Friend removed successfully'
  });
});

/**
 * Block user
 * @route POST /api/v1/friends/block
 */
const blockUser = asyncHandler(async (req, res, next) => {
  const { user_id } = req.body;
  const userId = req.user.id;

  // Check if trying to block self
  if (userId === user_id) {
    return next(new ValidationError('You cannot block yourself'));
  }

  // Check if user exists
  const userToBlock = await User.findByPk(user_id);
  if (!userToBlock) {
    return next(new NotFoundError('User not found'));
  }

  // Find existing friendship or create new one
  let friendship = await Friend.findExistingFriendship(userId, user_id);

  if (friendship) {
    // Block existing relationship
    await friendship.block(userId);
  } else {
    // Create new blocked relationship
    friendship = await Friend.create({
      user_id: userId < user_id ? userId : user_id,
      friend_id: userId < user_id ? user_id : userId,
      status: 'blocked',
      requested_by: userId,
      blocked_by: userId,
      blocked_at: new Date()
    });
  }

  logger.info(`User ${user_id} blocked by ${userId}`, { friendshipId: friendship.id });

  res.status(200).json({
    status: 'success',
    message: 'User blocked successfully'
  });
});

/**
 * Unblock user
 * @route POST /api/v1/friends/unblock
 */
const unblockUser = asyncHandler(async (req, res, next) => {
  const { user_id } = req.body;
  const userId = req.user.id;

  // Find the friendship
  const friendship = await Friend.findExistingFriendship(userId, user_id);

  if (!friendship) {
    return next(new NotFoundError('No relationship found with this user'));
  }

  // Check if user is blocked and current user blocked them
  if (friendship.status !== 'blocked' || friendship.blocked_by !== userId) {
    return next(new ValidationError('User is not blocked by you'));
  }

  // Unblock user
  await friendship.unblock();

  logger.info(`User ${user_id} unblocked by ${userId}`, { friendshipId: friendship.id });

  res.status(200).json({
    status: 'success',
    message: 'User unblocked successfully'
  });
});

/**
 * Get blocked users
 * @route GET /api/v1/friends/blocked
 */
const getBlockedUsers = asyncHandler(async (req, res, next) => {
  const { page = 1, limit = 20 } = req.query;
  const userId = req.user.id;

  const blockedRelationships = await Friend.scope(['blocked', 'withUsers']).findAll({
    where: {
      blocked_by: userId
    },
    order: [['blocked_at', 'DESC']],
    limit: parseInt(limit),
    offset: (page - 1) * limit
  });

  // Format blocked users data
  const blockedUsers = blockedRelationships.map(friendship => {
    const blockedUser = friendship.user_id === userId ? friendship.friend : friendship.user;
    return {
      ...removeSensitiveFields(blockedUser.toJSON()),
      blocked_at: friendship.blocked_at
    };
  });

  res.status(200).json({
    status: 'success',
    data: {
      blockedUsers,
      pagination: {
        currentPage: parseInt(page),
        totalItems: blockedUsers.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: blockedUsers.length === parseInt(limit)
      }
    }
  });
});

/**
 * Toggle close friend status
 * @route PUT /api/v1/friends/:friendId/close-friend
 */
const toggleCloseFriend = asyncHandler(async (req, res, next) => {
  const { friendId } = req.params;
  const userId = req.user.id;

  // Find the friendship
  const friendship = await Friend.findExistingFriendship(userId, friendId);

  if (!friendship) {
    return next(new NotFoundError('Friendship not found'));
  }

  // Check if they are actually friends
  if (friendship.status !== 'accepted') {
    return next(new ValidationError('You are not friends with this user'));
  }

  // Toggle close friend status
  await friendship.toggleCloseFriend();

  logger.info(`Close friend status toggled for ${friendId} by ${userId}`, { 
    friendshipId: friendship.id,
    isCloseFriend: friendship.is_close_friend
  });

  res.status(200).json({
    status: 'success',
    message: `${friendship.is_close_friend ? 'Added to' : 'Removed from'} close friends`,
    data: {
      is_close_friend: friendship.is_close_friend
    }
  });
});

/**
 * Get mutual friends
 * @route GET /api/v1/friends/:userId/mutual
 */
const getMutualFriends = asyncHandler(async (req, res, next) => {
  const { userId: targetUserId } = req.params;
  const { page = 1, limit = 20 } = req.query;
  const requesterId = req.user.id;

  // Check if target user exists
  const targetUser = await User.findByPk(targetUserId);
  if (!targetUser) {
    return next(new NotFoundError('User not found'));
  }

  // Get mutual friends
  const mutualFriendIds = await Friend.getMutualFriends(requesterId, targetUserId);

  // Fetch mutual friends details
  const mutualFriends = await User.findAll({
    where: {
      id: mutualFriendIds.slice((page - 1) * limit, page * limit)
    },
    attributes: ['id', 'username', 'first_name', 'last_name', 'profile_picture', 'is_verified']
  });

  res.status(200).json({
    status: 'success',
    data: {
      mutualFriends,
      totalMutual: mutualFriendIds.length,
      pagination: {
        currentPage: parseInt(page),
        totalItems: mutualFriendIds.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: mutualFriendIds.length > page * limit
      }
    }
  });
});

/**
 * Get friend suggestions
 * @route GET /api/v1/friends/suggestions
 */
const getFriendSuggestions = asyncHandler(async (req, res, next) => {
  const { limit = 10 } = req.query;
  const userId = req.user.id;

  const suggestions = await Friend.getFriendSuggestions(userId, parseInt(limit));

  res.status(200).json({
    status: 'success',
    data: {
      suggestions
    }
  });
});

/**
 * Search users for friends
 * @route GET /api/v1/friends/search
 */
const searchUsers = asyncHandler(async (req, res, next) => {
  const { query, page = 1, limit = 20 } = req.query;
  const userId = req.user.id;

  if (!query || query.trim().length === 0) {
    return next(new ValidationError('Search query is required'));
  }

  const users = await User.searchUsers(query.trim(), parseInt(limit));

  // Filter out current user and add friendship status
  const filteredUsers = [];
  for (const user of users) {
    if (user.id === userId) continue;

    const friendship = await Friend.findExistingFriendship(userId, user.id);
    const userWithStatus = {
      ...removeSensitiveFields(user.toJSON()),
      friendship_status: friendship ? friendship.status : 'none',
      is_friend: friendship ? friendship.status === 'accepted' : false
    };

    filteredUsers.push(userWithStatus);
  }

  res.status(200).json({
    status: 'success',
    data: {
      users: filteredUsers,
      query: query.trim(),
      pagination: {
        currentPage: parseInt(page),
        totalItems: filteredUsers.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: filteredUsers.length === parseInt(limit)
      }
    }
  });
});

module.exports = {
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
};