/**
 * Notification Controller
 * Handles user notifications, push notifications, and notification preferences
 * Updated to integrate with China-compatible push services
 */

const { asyncHandler } = require('../utils/asyncHandler');
const { AppError, ValidationError, NotFoundError, AuthorizationError } = require('../errors/AppError');
const { logger } = require('../config/logger');
const Notification = require('../models/Notification');
const socketService = require('../services/socket');
const pushService = require('../services/push');

/**
 * Get user notifications
 * @route GET /api/v1/notifications
 */
const getNotifications = asyncHandler(async (req, res, next) => {
  const { category, page = 1, limit = 20 } = req.query;
  const userId = req.user.id;
  const offset = (page - 1) * limit;

  const notifications = await Notification.getUserNotifications(
    userId, 
    parseInt(limit), 
    offset, 
    category
  );

  // Mark notifications as seen
  await Notification.markAllAsSeen(userId);

  res.status(200).json({
    status: 'success',
    data: {
      notifications,
      pagination: {
        currentPage: parseInt(page),
        totalItems: notifications.length,
        itemsPerPage: parseInt(limit),
        hasNextPage: notifications.length === parseInt(limit)
      }
    }
  });
});

/**
 * Get notification counts
 * @route GET /api/v1/notifications/counts
 */
const getNotificationCounts = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;

  const [
    totalUnread,
    totalUnseen,
    socialUnread,
    systemUnread,
    promotionalUnread,
    securityUnread
  ] = await Promise.all([
    Notification.getUnreadCount(userId),
    Notification.getUnseenCount(userId),
    Notification.getUnreadCount(userId, 'social'),
    Notification.getUnreadCount(userId, 'system'),
    Notification.getUnreadCount(userId, 'promotional'),
    Notification.getUnreadCount(userId, 'security')
  ]);

  res.status(200).json({
    status: 'success',
    data: {
      total: {
        unread: totalUnread,
        unseen: totalUnseen
      },
      categories: {
        social: socialUnread,
        system: systemUnread,
        promotional: promotionalUnread,
        security: securityUnread
      }
    }
  });
});

/**
 * Mark notification as read
 * @route PUT /api/v1/notifications/:notificationId/read
 */
const markAsRead = asyncHandler(async (req, res, next) => {
  const { notificationId } = req.params;
  const userId = req.user.id;

  const notification = await Notification.findByPk(notificationId);

  if (!notification) {
    return next(new NotFoundError('Notification not found'));
  }

  // Check if notification belongs to user
  if (notification.user_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  await notification.markAsRead();

  logger.info(`Notification marked as read by user ${userId}`, { notificationId });

  res.status(200).json({
    status: 'success',
    message: 'Notification marked as read',
    data: {
      notification
    }
  });
});

/**
 * Mark all notifications as read
 * @route PUT /api/v1/notifications/read-all
 */
const markAllAsRead = asyncHandler(async (req, res, next) => {
  const { category } = req.body;
  const userId = req.user.id;

  await Notification.markAllAsRead(userId, category);

  logger.info(`All notifications marked as read by user ${userId}`, { category });

  res.status(200).json({
    status: 'success',
    message: category ? 
      `All ${category} notifications marked as read` : 
      'All notifications marked as read'
  });
});

/**
 * Delete notification
 * @route DELETE /api/v1/notifications/:notificationId
 */
const deleteNotification = asyncHandler(async (req, res, next) => {
  const { notificationId } = req.params;
  const userId = req.user.id;

  const notification = await Notification.findByPk(notificationId);

  if (!notification) {
    return next(new NotFoundError('Notification not found'));
  }

  // Check if notification belongs to user
  if (notification.user_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  await notification.softDelete();

  logger.info(`Notification deleted by user ${userId}`, { notificationId });

  res.status(200).json({
    status: 'success',
    message: 'Notification deleted successfully'
  });
});

/**
 * Delete all notifications
 * @route DELETE /api/v1/notifications/all
 */
const deleteAllNotifications = asyncHandler(async (req, res, next) => {
  const { category } = req.body;
  const userId = req.user.id;

  const whereClause = {
    user_id: userId,
    is_deleted: false
  };

  if (category) {
    whereClause.category = category;
  }

  await Notification.update(
    { 
      is_deleted: true, 
      deleted_at: new Date() 
    },
    { where: whereClause }
  );

  logger.info(`All notifications deleted by user ${userId}`, { category });

  res.status(200).json({
    status: 'success',
    message: category ? 
      `All ${category} notifications deleted` : 
      'All notifications deleted'
  });
});

/**
 * Get notification settings
 * @route GET /api/v1/notifications/settings
 */
const getNotificationSettings = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;

  // In a real app, this would come from a user_notification_settings table
  // For now, we'll return default settings
  const settings = {
    push_notifications: true,
    email_notifications: false,
    sms_notifications: false,
    categories: {
      social: {
        push: true,
        email: false,
        sms: false
      },
      system: {
        push: true,
        email: true,
        sms: false
      },
      promotional: {
        push: false,
        email: false,
        sms: false
      },
      security: {
        push: true,
        email: true,
        sms: true
      }
    },
    quiet_hours: {
      enabled: false,
      start_time: '22:00',
      end_time: '08:00'
    }
  };

  res.status(200).json({
    status: 'success',
    data: {
      settings
    }
  });
});

/**
 * Update notification settings
 * @route PUT /api/v1/notifications/settings
 */
const updateNotificationSettings = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;
  const settings = req.body;

  // In a real app, this would update the user_notification_settings table
  // For now, we'll just log the update
  logger.info(`Notification settings updated by user ${userId}`, { settings });

  res.status(200).json({
    status: 'success',
    message: 'Notification settings updated successfully',
    data: {
      settings
    }
  });
});

/**
 * Send test notification
 * @route POST /api/v1/notifications/test
 */
const sendTestNotification = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;

  // Create test notification
  const notification = await Notification.createNotification({
    userId,
    fromUserId: null,
    type: 'system',
    title: 'Test Notification',
    message: 'This is a test notification to verify your notification settings.',
    priority: 'normal',
    category: 'system'
  });

  // Send real-time notification via Socket.IO
  await socketService.sendNotificationToUser(userId, notification);

  // Send push notification via China-compatible push services
  if (pushService.isAvailable()) {
    try {
      const pushResult = await pushService.sendNotificationToUser(userId, {
        title: notification.title,
        body: notification.message,
        data: {
          notificationId: notification.id,
          type: notification.type,
          category: notification.category
        }
      });

      if (pushResult.success) {
        await notification.markPushSent();
        logger.info(`Push notification sent successfully for test notification`, {
          userId,
          notificationId: notification.id,
          pushResults: pushResult.summary
        });
      } else {
        logger.warn(`Push notification failed for test notification`, {
          userId,
          notificationId: notification.id,
          error: pushResult.error
        });
      }
    } catch (error) {
      logger.error('Push notification error for test notification:', error);
    }
  }

  logger.info(`Test notification sent to user ${userId}`, { notificationId: notification.id });

  res.status(200).json({
    status: 'success',
    message: 'Test notification sent successfully',
    data: {
      notification,
      pushSent: pushService.isAvailable()
    }
  });
});

/**
 * Get notification statistics
 * @route GET /api/v1/notifications/stats
 */
const getNotificationStats = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;

  const stats = await Notification.getUserStats(userId);

  res.status(200).json({
    status: 'success',
    data: {
      stats
    }
  });
});

/**
 * Mark notification as clicked
 * @route PUT /api/v1/notifications/:notificationId/clicked
 */
const markAsClicked = asyncHandler(async (req, res, next) => {
  const { notificationId } = req.params;
  const userId = req.user.id;

  const notification = await Notification.findByPk(notificationId);

  if (!notification) {
    return next(new NotFoundError('Notification not found'));
  }

  // Check if notification belongs to user
  if (notification.user_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  await notification.markAsClicked();

  logger.info(`Notification clicked by user ${userId}`, { notificationId });

  res.status(200).json({
    status: 'success',
    message: 'Notification marked as clicked',
    data: {
      notification,
      action_url: notification.action_url
    }
  });
});

/**
 * Get notification by ID
 * @route GET /api/v1/notifications/:notificationId
 */
const getNotification = asyncHandler(async (req, res, next) => {
  const { notificationId } = req.params;
  const userId = req.user.id;

  const notification = await Notification.scope('withFromUser').findByPk(notificationId);

  if (!notification) {
    return next(new NotFoundError('Notification not found'));
  }

  // Check if notification belongs to user
  if (notification.user_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  // Mark as seen if not already
  if (!notification.is_seen) {
    await notification.markAsSeen();
  }

  res.status(200).json({
    status: 'success',
    data: {
      notification
    }
  });
});

/**
 * Snooze notification
 * @route PUT /api/v1/notifications/:notificationId/snooze
 */
const snoozeNotification = asyncHandler(async (req, res, next) => {
  const { notificationId } = req.params;
  const { snooze_until } = req.body;
  const userId = req.user.id;

  const notification = await Notification.findByPk(notificationId);

  if (!notification) {
    return next(new NotFoundError('Notification not found'));
  }

  // Check if notification belongs to user
  if (notification.user_id !== userId) {
    return next(new AuthorizationError('Access denied'));
  }

  // Update notification to be hidden until snooze_until time
  await notification.update({
    expires_at: new Date(snooze_until)
  });

  logger.info(`Notification snoozed by user ${userId}`, { 
    notificationId, 
    snoozeUntil: snooze_until 
  });

  res.status(200).json({
    status: 'success',
    message: 'Notification snoozed successfully',
    data: {
      notification,
      snooze_until
    }
  });
});

module.exports = {
  getNotifications,
  getNotificationCounts,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  deleteAllNotifications,
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification,
  getNotificationStats,
  markAsClicked,
  getNotification,
  snoozeNotification
};