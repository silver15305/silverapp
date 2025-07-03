/**
 * Chat Routes
 * Defines all chat and messaging API endpoints
 */

const express = require('express');
const {
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
} = require('../controllers/chatController');

const { authenticate } = require('../middleware/auth');
const { validate, messageSchemas } = require('../middleware/validator');
const { messageRateLimit, searchRateLimit } = require('../middleware/rateLimiting');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');

const router = express.Router();

/**
 * @route   POST /api/v1/chat/messages
 * @desc    Send message
 * @access  Private
 */
router.post('/messages',
  authenticate,
  messageRateLimit,
  loggingSQLInjectionFilter,
  validate(messageSchemas.sendMessage),
  sendMessage
);

/**
 * @route   GET /api/v1/chat/conversations
 * @desc    Get conversations list
 * @access  Private
 */
router.get('/conversations',
  authenticate,
  validate(messageSchemas.getConversations, 'query'),
  getConversations
);

/**
 * @route   GET /api/v1/chat/conversations/:conversationId/messages
 * @desc    Get conversation messages
 * @access  Private
 */
router.get('/conversations/:conversationId/messages',
  authenticate,
  validate(messageSchemas.getConversation, 'query'),
  getConversationMessages
);

/**
 * @route   GET /api/v1/chat/search
 * @desc    Search messages
 * @access  Private
 */
router.get('/search',
  authenticate,
  searchRateLimit,
  validate(messageSchemas.searchMessages, 'query'),
  searchMessages
);

/**
 * @route   GET /api/v1/chat/unread-count
 * @desc    Get unread messages count
 * @access  Private
 */
router.get('/unread-count',
  authenticate,
  getUnreadCount
);

/**
 * @route   PUT /api/v1/chat/messages/:messageId/read
 * @desc    Mark message as read
 * @access  Private
 */
router.put('/messages/:messageId/read',
  authenticate,
  markMessageAsRead
);

/**
 * @route   DELETE /api/v1/chat/messages/:messageId
 * @desc    Delete message
 * @access  Private
 */
router.delete('/messages/:messageId',
  authenticate,
  deleteMessage
);

/**
 * @route   POST /api/v1/chat/messages/:messageId/reactions
 * @desc    Add reaction to message
 * @access  Private
 */
router.post('/messages/:messageId/reactions',
  authenticate,
  addReaction
);

/**
 * @route   DELETE /api/v1/chat/messages/:messageId/reactions/:emoji
 * @desc    Remove reaction from message
 * @access  Private
 */
router.delete('/messages/:messageId/reactions/:emoji',
  authenticate,
  removeReaction
);

/**
 * @route   POST /api/v1/chat/messages/:messageId/forward
 * @desc    Forward message
 * @access  Private
 */
router.post('/messages/:messageId/forward',
  authenticate,
  messageRateLimit,
  forwardMessage
);

/**
 * @route   GET /api/v1/chat/messages/:messageId/status
 * @desc    Get message delivery status
 * @access  Private
 */
router.get('/messages/:messageId/status',
  authenticate,
  getMessageStatus
);

module.exports = router;