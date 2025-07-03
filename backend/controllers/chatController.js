/**
 * Chat Controller
 * Handles messaging, conversations, and real-time chat functionality
 */

const { asyncHandler } = require('../utils/asyncHandler');
const { AppError, ValidationError, NotFoundError, AuthorizationError } = require('../errors/AppError');
const { removeSensitiveFields } = require('../utils/helpers');
const { logger } = require('../config/logger');
const Message = require('../models/Message');
const User = require('../models/User');
const Friend = require('../models/Friend');
const socketService = require('../services/socket');

/**
 * Send message
 * @route POST /api/v1/chat/messages
 */
const sendMessage = asyncHandler(async (req, res, next) => {
  const {
    receiver_id,
    content,
    message_type,
    media_url,
    reply_to_id,
    location_data,
    contact_data
  } = req.body;
  
  const senderId = req.user.id;

  // Check if receiver exists
  const receiver = await User.findByPk(receiver_id);
  if (!receiver) {
    return next(new NotFoundError('Receiver not found'));
  }

  // Check if users are friends or if receiver allows messages from non-friends
  const areFriends = await Friend.areFriends(senderId, receiver_id);
  if (!areFriends && receiver.is_private) {
    return next(new AuthorizationError('You can only message friends'));
  }

  // Check if sender is blocked
  const isBlocked = await Friend.isBlocked(senderId, receiver_id);
  if (isBlocked) {
    return next(new AuthorizationError('Cannot send message to this user'));
  }

  // Generate conversation ID
  const conversationId = Message.generateConversationId(senderId, receiver_id);

  // Create message
  const message = await Message.create({
    sender_id: senderId,
    receiver_id,
    conversation_id: conversationId,
    content,
    message_type: message_type || 'text',
    media_url,
    reply_to_id,
    location_data,
    contact_data
  });

  // Fetch message with sender details
  const createdMessage = await Message.scope(['withSender', 'withReceiver']).findByPk(message.id);

  // Send real-time message via Socket.IO
  await socketService.sendMessageToConversation(conversationId, createdMessage, senderId);

  // Mark message as delivered if receiver is online
  if (socketService.isUserOnline(receiver_id)) {
    await message.markAsDelivered();
  }

  logger.info(`Message sent from ${senderId} to ${receiver_id}`, { messageId: message.id });

  res.status(201).json({
    status: 'success',
    message: 'Message sent successfully',
    data: {
      message: createdMessage
    }
  });
});

/**
 * Get conversations list
 * @route GET /api/v1/chat/conversations
 */
const getConversations = asyncHandler(async (req, res, next) => {
  const { page = 1, limit = 20 } = req.query;
  const userId = req.user.id;

  const conversations = await Message.getUserConversations(userId, parseInt(limit));

  res.status(200).json({
    status: 'success',
    data: {
      conversations,
      pagination: {
        currentPage: parseInt(page),
        totalItems: conversations.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: conversations.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get conversation messages
 * @route GET /api/v1/chat/conversations/:conversationId/messages
 */
const getConversationMessages = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;
  const { page = 1, limit = 50 } = req.query;
  const userId = req.user.id;
  const offset = (page - 1) * limit;

  // Verify user is part of this conversation
  const [user1Id, user2Id] = conversationId.split('_');
  if (userId !== user1Id && userId !== user2Id) {
    return next(new AuthorizationError('Access denied to this conversation'));
  }

  const messages = await Message.getConversationMessages(
    conversationId, 
    userId, 
    parseInt(limit), 
    offset
  );

  // Mark messages as read
  await Message.markConversationAsRead(conversationId, userId);

  res.status(200).json({
    status: 'success',
    data: {
      messages: messages.reverse(), // Reverse to show oldest first
      conversationId,
      pagination: {
        currentPage: parseInt(page),
        totalItems: messages.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: messages.length === parseInt(limit)
      }
    }
  });
});

/**
 * Mark message as read
 * @route PUT /api/v1/chat/messages/:messageId/read
 */
const markMessageAsRead = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;
  const userId = req.user.id;

  const message = await Message.findByPk(messageId);

  if (!message) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is the receiver
  if (message.receiver_id !== userId) {
    return next(new AuthorizationError('You can only mark messages sent to you as read'));
  }

  await message.markAsRead();

  // Send read receipt via Socket.IO
  await socketService.sendMessageToConversation(
    message.conversation_id,
    {
      type: 'read_receipt',
      messageId: message.id,
      readBy: userId,
      readAt: message.read_at
    },
    userId
  );

  logger.info(`Message marked as read by user ${userId}`, { messageId });

  res.status(200).json({
    status: 'success',
    message: 'Message marked as read'
  });
});

/**
 * Delete message
 * @route DELETE /api/v1/chat/messages/:messageId
 */
const deleteMessage = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;
  const userId = req.user.id;

  const message = await Message.findByPk(messageId);

  if (!message) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is sender or receiver
  if (message.sender_id !== userId && message.receiver_id !== userId) {
    return next(new AuthorizationError('You can only delete your own messages'));
  }

  await message.deleteForUser(userId);

  logger.info(`Message deleted by user ${userId}`, { messageId });

  res.status(200).json({
    status: 'success',
    message: 'Message deleted successfully'
  });
});

/**
 * Search messages
 * @route GET /api/v1/chat/search
 */
const searchMessages = asyncHandler(async (req, res, next) => {
  const { query, page = 1, limit = 20 } = req.query;
  const userId = req.user.id;

  if (!query || query.trim().length === 0) {
    return next(new ValidationError('Search query is required'));
  }

  const messages = await Message.searchMessages(userId, query.trim(), parseInt(limit));

  res.status(200).json({
    status: 'success',
    data: {
      messages,
      query: query.trim(),
      pagination: {
        currentPage: parseInt(page),
        totalItems: messages.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: messages.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get unread messages count
 * @route GET /api/v1/chat/unread-count
 */
const getUnreadCount = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;

  const unreadCount = await Message.getUnreadCount(userId);

  res.status(200).json({
    status: 'success',
    data: {
      unreadCount
    }
  });
});

/**
 * Add reaction to message
 * @route POST /api/v1/chat/messages/:messageId/reactions
 */
const addReaction = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;
  const { emoji } = req.body;
  const userId = req.user.id;

  if (!emoji) {
    return next(new ValidationError('Emoji is required'));
  }

  const message = await Message.findByPk(messageId);

  if (!message) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is part of this conversation
  if (message.sender_id !== userId && message.receiver_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  await message.addReaction(userId, emoji);

  // Send reaction update via Socket.IO
  await socketService.sendMessageToConversation(
    message.conversation_id,
    {
      type: 'reaction_added',
      messageId: message.id,
      emoji,
      userId,
      reactions: message.reactions
    }
  );

  logger.info(`Reaction added to message by user ${userId}`, { messageId, emoji });

  res.status(200).json({
    status: 'success',
    message: 'Reaction added successfully',
    data: {
      reactions: message.reactions
    }
  });
});

/**
 * Remove reaction from message
 * @route DELETE /api/v1/chat/messages/:messageId/reactions/:emoji
 */
const removeReaction = asyncHandler(async (req, res, next) => {
  const { messageId, emoji } = req.params;
  const userId = req.user.id;

  const message = await Message.findByPk(messageId);

  if (!message) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is part of this conversation
  if (message.sender_id !== userId && message.receiver_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  await message.removeReaction(userId, emoji);

  // Send reaction update via Socket.IO
  await socketService.sendMessageToConversation(
    message.conversation_id,
    {
      type: 'reaction_removed',
      messageId: message.id,
      emoji,
      userId,
      reactions: message.reactions
    }
  );

  logger.info(`Reaction removed from message by user ${userId}`, { messageId, emoji });

  res.status(200).json({
    status: 'success',
    message: 'Reaction removed successfully',
    data: {
      reactions: message.reactions
    }
  });
});

/**
 * Forward message
 * @route POST /api/v1/chat/messages/:messageId/forward
 */
const forwardMessage = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;
  const { receiver_ids } = req.body;
  const userId = req.user.id;

  if (!receiver_ids || !Array.isArray(receiver_ids) || receiver_ids.length === 0) {
    return next(new ValidationError('Receiver IDs are required'));
  }

  const originalMessage = await Message.findByPk(messageId);

  if (!originalMessage) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is part of the original conversation
  if (originalMessage.sender_id !== userId && originalMessage.receiver_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  const forwardedMessages = [];

  // Forward to each receiver
  for (const receiverId of receiver_ids) {
    // Check if receiver exists
    const receiver = await User.findByPk(receiverId);
    if (!receiver) {
      continue; // Skip invalid receivers
    }

    // Check if users are friends or if receiver allows messages from non-friends
    const areFriends = await Friend.areFriends(userId, receiverId);
    if (!areFriends && receiver.is_private) {
      continue; // Skip if not friends and receiver is private
    }

    // Generate conversation ID
    const conversationId = Message.generateConversationId(userId, receiverId);

    // Create forwarded message
    const forwardedMessage = await Message.create({
      sender_id: userId,
      receiver_id: receiverId,
      conversation_id: conversationId,
      content: originalMessage.content,
      message_type: originalMessage.message_type,
      media_url: originalMessage.media_url,
      is_forwarded: true,
      forwarded_from: originalMessage.id
    });

    forwardedMessages.push(forwardedMessage);

    // Send real-time message via Socket.IO
    await socketService.sendMessageToConversation(conversationId, forwardedMessage, userId);
  }

  logger.info(`Message forwarded by user ${userId}`, { 
    originalMessageId: messageId, 
    forwardedCount: forwardedMessages.length 
  });

  res.status(200).json({
    status: 'success',
    message: `Message forwarded to ${forwardedMessages.length} recipients`,
    data: {
      forwardedCount: forwardedMessages.length
    }
  });
});

/**
 * Get message delivery status
 * @route GET /api/v1/chat/messages/:messageId/status
 */
const getMessageStatus = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;
  const userId = req.user.id;

  const message = await Message.findByPk(messageId);

  if (!message) {
    return next(new NotFoundError('Message not found'));
  }

  // Check if user is the sender
  if (message.sender_id !== userId) {
    return next(new AuthorizationError('You can only check status of messages you sent'));
  }

  res.status(200).json({
    status: 'success',
    data: {
      messageId: message.id,
      is_delivered: message.is_delivered,
      delivered_at: message.delivered_at,
      is_read: message.is_read,
      read_at: message.read_at
    }
  });
});

module.exports = {
  sendMessage,
  getConversations,
  getConversationMessages,
  markMessageAsRead,
  deleteMessage,
  searchMessages,
  getUnreadCount,
  addReaction,
  removeReaction,
  forwardMessage,
  getMessageStatus
};