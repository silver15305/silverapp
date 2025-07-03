/**
 * Socket.IO Service
 * Handles real-time communication for chat, notifications, and live updates
 */

const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { logger } = require('../config/logger');
const redisService = require('./redis');
const { TokenManager } = require('../utils/security');

/**
 * Socket Service Class
 */
class SocketService {
  constructor() {
    this.io = null;
    this.connectedUsers = new Map(); // userId -> Set of socketIds
    this.socketUsers = new Map(); // socketId -> userId
    this.rooms = new Map(); // roomId -> Set of socketIds
  }

  /**
   * Initialize Socket.IO server
   * @param {Object} server - HTTP server instance
   */
  initialize(server) {
    this.io = new Server(server, {
      cors: {
        origin: process.env.NODE_ENV === 'production' 
          ? ['https://silverapp.com'] // Replace with your domain
          : ['http://localhost:3000', 'http://localhost:8080'],
        methods: ['GET', 'POST'],
        credentials: true
      },
      transports: ['websocket', 'polling'],
      pingTimeout: 60000,
      pingInterval: 25000
    });

    this.setupMiddleware();
    this.setupEventHandlers();
    
    logger.info('Socket.IO service initialized');
  }

  /**
   * Setup authentication middleware
   */
  setupMiddleware() {
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
          return next(new Error('Authentication token required'));
        }

        const decoded = TokenManager.verifyAccessToken(token);
        socket.userId = decoded.userId;
        socket.user = decoded;
        
        logger.debug(`Socket authenticated for user: ${socket.userId}`);
        next();
      } catch (error) {
        logger.error('Socket authentication failed:', error);
        next(new Error('Authentication failed'));
      }
    });
  }

  /**
   * Setup event handlers
   */
  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      this.handleConnection(socket);
      
      // Chat events
      socket.on('join_conversation', (data) => this.handleJoinConversation(socket, data));
      socket.on('leave_conversation', (data) => this.handleLeaveConversation(socket, data));
      socket.on('send_message', (data) => this.handleSendMessage(socket, data));
      socket.on('message_read', (data) => this.handleMessageRead(socket, data));
      socket.on('typing_start', (data) => this.handleTypingStart(socket, data));
      socket.on('typing_stop', (data) => this.handleTypingStop(socket, data));
      
      // Notification events
      socket.on('mark_notification_read', (data) => this.handleMarkNotificationRead(socket, data));
      
      // Presence events
      socket.on('update_status', (data) => this.handleUpdateStatus(socket, data));
      
      // General events
      socket.on('disconnect', () => this.handleDisconnection(socket));
      socket.on('error', (error) => this.handleError(socket, error));
    });
  }

  /**
   * Handle new socket connection
   * @param {Object} socket - Socket instance
   */
  async handleConnection(socket) {
    try {
      const userId = socket.userId;
      
      // Add user to connected users map
      if (!this.connectedUsers.has(userId)) {
        this.connectedUsers.set(userId, new Set());
      }
      this.connectedUsers.get(userId).add(socket.id);
      this.socketUsers.set(socket.id, userId);
      
      // Join user to their personal room
      socket.join(`user:${userId}`);
      
      // Update user online status
      await this.updateUserOnlineStatus(userId, true);
      
      // Notify friends about online status
      await this.notifyFriendsStatusChange(userId, 'online');
      
      logger.info(`User ${userId} connected with socket ${socket.id}`);
      
      // Send pending notifications
      await this.sendPendingNotifications(socket, userId);
      
    } catch (error) {
      logger.error('Error handling socket connection:', error);
    }
  }

  /**
   * Handle socket disconnection
   * @param {Object} socket - Socket instance
   */
  async handleDisconnection(socket) {
    try {
      const userId = socket.userId;
      
      if (userId) {
        // Remove socket from user's connections
        if (this.connectedUsers.has(userId)) {
          this.connectedUsers.get(userId).delete(socket.id);
          
          // If no more connections for this user, mark as offline
          if (this.connectedUsers.get(userId).size === 0) {
            this.connectedUsers.delete(userId);
            await this.updateUserOnlineStatus(userId, false);
            await this.notifyFriendsStatusChange(userId, 'offline');
          }
        }
        
        this.socketUsers.delete(socket.id);
        
        logger.info(`User ${userId} disconnected socket ${socket.id}`);
      }
    } catch (error) {
      logger.error('Error handling socket disconnection:', error);
    }
  }

  /**
   * Handle joining a conversation
   * @param {Object} socket - Socket instance
   * @param {Object} data - Conversation data
   */
  handleJoinConversation(socket, data) {
    try {
      const { conversationId } = data;
      const roomId = `conversation:${conversationId}`;
      
      socket.join(roomId);
      
      // Add to rooms map
      if (!this.rooms.has(roomId)) {
        this.rooms.set(roomId, new Set());
      }
      this.rooms.get(roomId).add(socket.id);
      
      logger.debug(`User ${socket.userId} joined conversation ${conversationId}`);
      
      // Notify other participants
      socket.to(roomId).emit('user_joined_conversation', {
        userId: socket.userId,
        conversationId
      });
      
    } catch (error) {
      logger.error('Error joining conversation:', error);
      socket.emit('error', { message: 'Failed to join conversation' });
    }
  }

  /**
   * Handle leaving a conversation
   * @param {Object} socket - Socket instance
   * @param {Object} data - Conversation data
   */
  handleLeaveConversation(socket, data) {
    try {
      const { conversationId } = data;
      const roomId = `conversation:${conversationId}`;
      
      socket.leave(roomId);
      
      // Remove from rooms map
      if (this.rooms.has(roomId)) {
        this.rooms.get(roomId).delete(socket.id);
        if (this.rooms.get(roomId).size === 0) {
          this.rooms.delete(roomId);
        }
      }
      
      logger.debug(`User ${socket.userId} left conversation ${conversationId}`);
      
      // Notify other participants
      socket.to(roomId).emit('user_left_conversation', {
        userId: socket.userId,
        conversationId
      });
      
    } catch (error) {
      logger.error('Error leaving conversation:', error);
    }
  }

  /**
   * Handle sending a message
   * @param {Object} socket - Socket instance
   * @param {Object} data - Message data
   */
  async handleSendMessage(socket, data) {
    try {
      const { conversationId, message } = data;
      const roomId = `conversation:${conversationId}`;
      
      // Broadcast message to conversation participants
      socket.to(roomId).emit('new_message', {
        ...message,
        senderId: socket.userId,
        timestamp: new Date().toISOString()
      });
      
      // Store message delivery status
      await this.storeMessageDeliveryStatus(message.id, conversationId);
      
      logger.debug(`Message sent in conversation ${conversationId} by user ${socket.userId}`);
      
    } catch (error) {
      logger.error('Error sending message:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  }

  /**
   * Handle message read receipt
   * @param {Object} socket - Socket instance
   * @param {Object} data - Read receipt data
   */
  handleMessageRead(socket, data) {
    try {
      const { conversationId, messageId } = data;
      const roomId = `conversation:${conversationId}`;
      
      // Notify sender about read receipt
      socket.to(roomId).emit('message_read', {
        messageId,
        readBy: socket.userId,
        readAt: new Date().toISOString()
      });
      
      logger.debug(`Message ${messageId} read by user ${socket.userId}`);
      
    } catch (error) {
      logger.error('Error handling message read:', error);
    }
  }

  /**
   * Handle typing start
   * @param {Object} socket - Socket instance
   * @param {Object} data - Typing data
   */
  handleTypingStart(socket, data) {
    try {
      const { conversationId } = data;
      const roomId = `conversation:${conversationId}`;
      
      socket.to(roomId).emit('user_typing', {
        userId: socket.userId,
        conversationId,
        isTyping: true
      });
      
    } catch (error) {
      logger.error('Error handling typing start:', error);
    }
  }

  /**
   * Handle typing stop
   * @param {Object} socket - Socket instance
   * @param {Object} data - Typing data
   */
  handleTypingStop(socket, data) {
    try {
      const { conversationId } = data;
      const roomId = `conversation:${conversationId}`;
      
      socket.to(roomId).emit('user_typing', {
        userId: socket.userId,
        conversationId,
        isTyping: false
      });
      
    } catch (error) {
      logger.error('Error handling typing stop:', error);
    }
  }

  /**
   * Handle marking notification as read
   * @param {Object} socket - Socket instance
   * @param {Object} data - Notification data
   */
  handleMarkNotificationRead(socket, data) {
    try {
      const { notificationId } = data;
      
      // Emit confirmation back to user
      socket.emit('notification_read_confirmed', {
        notificationId,
        readAt: new Date().toISOString()
      });
      
      logger.debug(`Notification ${notificationId} marked as read by user ${socket.userId}`);
      
    } catch (error) {
      logger.error('Error marking notification as read:', error);
    }
  }

  /**
   * Handle status update
   * @param {Object} socket - Socket instance
   * @param {Object} data - Status data
   */
  async handleUpdateStatus(socket, data) {
    try {
      const { status } = data; // online, away, busy, offline
      
      await this.updateUserOnlineStatus(socket.userId, status !== 'offline', status);
      await this.notifyFriendsStatusChange(socket.userId, status);
      
      logger.debug(`User ${socket.userId} status updated to ${status}`);
      
    } catch (error) {
      logger.error('Error updating user status:', error);
    }
  }

  /**
   * Handle socket errors
   * @param {Object} socket - Socket instance
   * @param {Error} error - Error object
   */
  handleError(socket, error) {
    logger.error(`Socket error for user ${socket.userId}:`, error);
  }

  /**
   * Send notification to user
   * @param {string} userId - User ID
   * @param {Object} notification - Notification data
   */
  async sendNotificationToUser(userId, notification) {
    try {
      const userRoom = `user:${userId}`;
      this.io.to(userRoom).emit('new_notification', notification);
      
      logger.debug(`Notification sent to user ${userId}`);
    } catch (error) {
      logger.error('Error sending notification:', error);
    }
  }

  /**
   * Send message to conversation
   * @param {string} conversationId - Conversation ID
   * @param {Object} message - Message data
   * @param {string} excludeUserId - User ID to exclude from broadcast
   */
  async sendMessageToConversation(conversationId, message, excludeUserId = null) {
    try {
      const roomId = `conversation:${conversationId}`;
      
      if (excludeUserId) {
        // Get all sockets in the room except the excluded user
        const room = this.io.sockets.adapter.rooms.get(roomId);
        if (room) {
          room.forEach(socketId => {
            const socket = this.io.sockets.sockets.get(socketId);
            if (socket && socket.userId !== excludeUserId) {
              socket.emit('new_message', message);
            }
          });
        }
      } else {
        this.io.to(roomId).emit('new_message', message);
      }
      
      logger.debug(`Message sent to conversation ${conversationId}`);
    } catch (error) {
      logger.error('Error sending message to conversation:', error);
    }
  }

  /**
   * Check if user is online
   * @param {string} userId - User ID
   * @returns {boolean} Online status
   */
  isUserOnline(userId) {
    return this.connectedUsers.has(userId) && this.connectedUsers.get(userId).size > 0;
  }

  /**
   * Get online users count
   * @returns {number} Number of online users
   */
  getOnlineUsersCount() {
    return this.connectedUsers.size;
  }

  /**
   * Update user online status in Redis
   * @param {string} userId - User ID
   * @param {boolean} isOnline - Online status
   * @param {string} status - Detailed status
   */
  async updateUserOnlineStatus(userId, isOnline, status = 'online') {
    try {
      if (!redisService.isReady()) return;

      const key = `user_status:${userId}`;
      const statusData = {
        isOnline,
        status,
        lastSeen: new Date().toISOString()
      };

      if (isOnline) {
        await redisService.set(key, statusData, 3600); // 1 hour TTL
      } else {
        await redisService.set(key, statusData, 86400); // 24 hours TTL for offline status
      }
    } catch (error) {
      logger.error('Error updating user online status:', error);
    }
  }

  /**
   * Notify friends about status change
   * @param {string} userId - User ID
   * @param {string} status - New status
   */
  async notifyFriendsStatusChange(userId, status) {
    try {
      // This would typically fetch user's friends from database
      // and notify them about the status change
      // For now, we'll emit to a general friends room
      
      this.io.emit('friend_status_change', {
        userId,
        status,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error notifying friends about status change:', error);
    }
  }

  /**
   * Send pending notifications to user
   * @param {Object} socket - Socket instance
   * @param {string} userId - User ID
   */
  async sendPendingNotifications(socket, userId) {
    try {
      if (!redisService.isReady()) return;

      const key = `pending_notifications:${userId}`;
      const notifications = await redisService.lrange(key, 0, -1, true);
      
      if (notifications && notifications.length > 0) {
        notifications.forEach(notification => {
          socket.emit('new_notification', notification);
        });
        
        // Clear pending notifications
        await redisService.del(key);
        
        logger.debug(`Sent ${notifications.length} pending notifications to user ${userId}`);
      }
    } catch (error) {
      logger.error('Error sending pending notifications:', error);
    }
  }

  /**
   * Store message delivery status
   * @param {string} messageId - Message ID
   * @param {string} conversationId - Conversation ID
   */
  async storeMessageDeliveryStatus(messageId, conversationId) {
    try {
      if (!redisService.isReady()) return;

      const key = `message_delivery:${messageId}`;
      const deliveryData = {
        messageId,
        conversationId,
        deliveredAt: new Date().toISOString()
      };

      await redisService.set(key, deliveryData, 86400); // 24 hours TTL
    } catch (error) {
      logger.error('Error storing message delivery status:', error);
    }
  }

  /**
   * Broadcast to all connected users
   * @param {string} event - Event name
   * @param {Object} data - Event data
   */
  broadcast(event, data) {
    this.io.emit(event, data);
  }

  /**
   * Get socket service statistics
   * @returns {Object} Service statistics
   */
  getStats() {
    return {
      connectedUsers: this.connectedUsers.size,
      totalSockets: this.socketUsers.size,
      activeRooms: this.rooms.size,
      uptime: process.uptime()
    };
  }
}

// Create singleton instance
const socketService = new SocketService();

module.exports = socketService;