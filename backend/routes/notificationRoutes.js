/**
 * Notification Routes
 * Defines all notification-related API endpoints
 */

const express = require('express');
const {
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
} = require('../controllers/notificationController');

const { authenticate } = require('../middleware/auth');
const { validate, notificationSchemas } = require('../middleware/validator');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');

const router = express.Router();

/**
 * @route   GET /api/v1/notifications
 * @desc    Get user notifications
 * @access  Private
 */
router.get('/',
  authenticate,
  validate(notificationSchemas.getNotifications, 'query'),
  getNotifications
);

/**
 * @route   GET /api/v1/notifications/counts
 * @desc    Get notification counts
 * @access  Private
 */
router.get('/counts',
  authenticate,
  getNotificationCounts
);

/**
 * @route   GET /api/v1/notifications/settings
 * @desc    Get notification settings
 * @access  Private
 */
router.get('/settings',
  authenticate,
  getNotificationSettings
);

/**
 * @route   GET /api/v1/notifications/stats
 * @desc    Get notification statistics
 * @access  Private
 */
router.get('/stats',
  authenticate,
  getNotificationStats
);

/**
 * @route   GET /api/v1/notifications/:notificationId
 * @desc    Get notification by ID
 * @access  Private
 */
router.get('/:notificationId',
  authenticate,
  getNotification
);

/**
 * @route   PUT /api/v1/notifications/settings
 * @desc    Update notification settings
 * @access  Private
 */
router.put('/settings',
  authenticate,
  loggingSQLInjectionFilter,
  updateNotificationSettings
);

/**
 * @route   PUT /api/v1/notifications/:notificationId/read
 * @desc    Mark notification as read
 * @access  Private
 */
router.put('/:notificationId/read',
  authenticate,
  markAsRead
);

/**
 * @route   PUT /api/v1/notifications/read-all
 * @desc    Mark all notifications as read
 * @access  Private
 */
router.put('/read-all',
  authenticate,
  validate(notificationSchemas.markAllAsRead),
  markAllAsRead
);

/**
 * @route   PUT /api/v1/notifications/:notificationId/clicked
 * @desc    Mark notification as clicked
 * @access  Private
 */
router.put('/:notificationId/clicked',
  authenticate,
  markAsClicked
);

/**
 * @route   PUT /api/v1/notifications/:notificationId/snooze
 * @desc    Snooze notification
 * @access  Private
 */
router.put('/:notificationId/snooze',
  authenticate,
  snoozeNotification
);

/**
 * @route   DELETE /api/v1/notifications/:notificationId
 * @desc    Delete notification
 * @access  Private
 */
router.delete('/:notificationId',
  authenticate,
  deleteNotification
);

/**
 * @route   DELETE /api/v1/notifications/all
 * @desc    Delete all notifications
 * @access  Private
 */
router.delete('/all',
  authenticate,
  deleteAllNotifications
);

/**
 * @route   POST /api/v1/notifications/test
 * @desc    Send test notification
 * @access  Private
 */
router.post('/test',
  authenticate,
  sendTestNotification
);

module.exports = router;