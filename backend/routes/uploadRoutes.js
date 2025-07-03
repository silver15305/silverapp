/**
 * Upload Routes
 * Defines file upload API endpoints using China-compatible cloud storage
 */

const express = require('express');
const multer = require('multer');
const { authenticate } = require('../middleware/auth');
const { uploadRateLimit } = require('../middleware/rateLimiting');
const { loggingSQLInjectionFilter } = require('../middleware/sqlInjectionFilter');
const { customValidations } = require('../middleware/validator');
const storageService = require('../services/storage');
const { logger } = require('../config/logger');
const { AppError } = require('../errors/AppError');

const router = express.Router();

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 5 // Maximum 5 files
  },
  fileFilter: (req, file, cb) => {
    // Allow images, videos, and documents
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'video/mp4',
      'video/avi',
      'video/mov',
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'), false);
    }
  }
});

/**
 * @route   POST /api/v1/upload/avatar
 * @desc    Upload user avatar
 * @access  Private
 */
router.post('/avatar',
  authenticate,
  uploadRateLimit,
  upload.single('avatar'),
  customValidations.validateFileUpload(['image/jpeg', 'image/png', 'image/gif', 'image/webp'], 5 * 1024 * 1024),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return next(new AppError('No file uploaded', 400));
      }

      const result = await storageService.uploadFile(
        req.file.buffer,
        req.file.originalname,
        req.user.id,
        'avatar',
        req.file.mimetype
      );

      if (!result.success) {
        return next(new AppError('File upload failed: ' + result.error, 500));
      }

      // Update user's profile picture in database
      await req.user.update({
        profile_picture: result.url
      });

      logger.info('Avatar uploaded successfully:', {
        userId: req.user.id,
        fileKey: result.key,
        provider: result.provider
      });

      res.status(200).json({
        status: 'success',
        message: 'Avatar uploaded successfully',
        data: {
          url: result.url,
          key: result.key,
          provider: result.provider
        }
      });

    } catch (error) {
      logger.error('Avatar upload failed:', error);
      next(new AppError('Avatar upload failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/upload/cover
 * @desc    Upload user cover picture
 * @access  Private
 */
router.post('/cover',
  authenticate,
  uploadRateLimit,
  upload.single('cover'),
  customValidations.validateFileUpload(['image/jpeg', 'image/png', 'image/gif', 'image/webp'], 10 * 1024 * 1024),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return next(new AppError('No file uploaded', 400));
      }

      const result = await storageService.uploadFile(
        req.file.buffer,
        req.file.originalname,
        req.user.id,
        'cover',
        req.file.mimetype
      );

      if (!result.success) {
        return next(new AppError('File upload failed: ' + result.error, 500));
      }

      // Update user's cover picture in database
      await req.user.update({
        cover_picture: result.url
      });

      logger.info('Cover picture uploaded successfully:', {
        userId: req.user.id,
        fileKey: result.key,
        provider: result.provider
      });

      res.status(200).json({
        status: 'success',
        message: 'Cover picture uploaded successfully',
        data: {
          url: result.url,
          key: result.key,
          provider: result.provider
        }
      });

    } catch (error) {
      logger.error('Cover picture upload failed:', error);
      next(new AppError('Cover picture upload failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/upload/post-media
 * @desc    Upload media for posts
 * @access  Private
 */
router.post('/post-media',
  authenticate,
  uploadRateLimit,
  upload.array('media', 5),
  async (req, res, next) => {
    try {
      if (!req.files || req.files.length === 0) {
        return next(new AppError('No files uploaded', 400));
      }

      const uploadPromises = req.files.map(file => 
        storageService.uploadFile(
          file.buffer,
          file.originalname,
          req.user.id,
          'post',
          file.mimetype
        )
      );

      const results = await Promise.all(uploadPromises);
      const successfulUploads = results.filter(result => result.success);
      const failedUploads = results.filter(result => !result.success);

      if (successfulUploads.length === 0) {
        return next(new AppError('All file uploads failed', 500));
      }

      logger.info('Post media uploaded:', {
        userId: req.user.id,
        successful: successfulUploads.length,
        failed: failedUploads.length
      });

      res.status(200).json({
        status: 'success',
        message: `${successfulUploads.length} files uploaded successfully`,
        data: {
          uploads: successfulUploads.map(result => ({
            url: result.url,
            key: result.key,
            provider: result.provider
          })),
          failed: failedUploads.length
        }
      });

    } catch (error) {
      logger.error('Post media upload failed:', error);
      next(new AppError('Media upload failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/upload/message-media
 * @desc    Upload media for messages
 * @access  Private
 */
router.post('/message-media',
  authenticate,
  uploadRateLimit,
  upload.single('media'),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return next(new AppError('No file uploaded', 400));
      }

      const result = await storageService.uploadFile(
        req.file.buffer,
        req.file.originalname,
        req.user.id,
        'message',
        req.file.mimetype
      );

      if (!result.success) {
        return next(new AppError('File upload failed: ' + result.error, 500));
      }

      logger.info('Message media uploaded successfully:', {
        userId: req.user.id,
        fileKey: result.key,
        provider: result.provider
      });

      res.status(200).json({
        status: 'success',
        message: 'Media uploaded successfully',
        data: {
          url: result.url,
          key: result.key,
          provider: result.provider,
          size: result.size,
          type: req.file.mimetype
        }
      });

    } catch (error) {
      logger.error('Message media upload failed:', error);
      next(new AppError('Media upload failed', 500));
    }
  }
);

/**
 * @route   POST /api/v1/upload/presigned-url
 * @desc    Generate presigned URL for direct upload
 * @access  Private
 */
router.post('/presigned-url',
  authenticate,
  loggingSQLInjectionFilter,
  async (req, res, next) => {
    try {
      const { fileName, fileType, uploadType = 'general' } = req.body;

      if (!fileName || !fileType) {
        return next(new AppError('File name and type are required', 400));
      }

      const key = storageService.generateFileKey(fileName, req.user.id, uploadType);
      const result = await storageService.generatePresignedUrl(key, 3600); // 1 hour

      if (!result.success) {
        return next(new AppError('Failed to generate presigned URL: ' + result.error, 500));
      }

      logger.info('Presigned URL generated:', {
        userId: req.user.id,
        fileKey: result.key,
        provider: result.provider
      });

      res.status(200).json({
        status: 'success',
        message: 'Presigned URL generated successfully',
        data: {
          uploadUrl: result.url,
          key: result.key,
          provider: result.provider,
          expires: result.expires
        }
      });

    } catch (error) {
      logger.error('Presigned URL generation failed:', error);
      next(new AppError('Presigned URL generation failed', 500));
    }
  }
);

/**
 * @route   DELETE /api/v1/upload/:key
 * @desc    Delete uploaded file
 * @access  Private
 */
router.delete('/:key',
  authenticate,
  async (req, res, next) => {
    try {
      const { key } = req.params;
      const { provider } = req.query;

      // Verify that the file belongs to the user (extract user ID from key)
      if (!key.includes(req.user.id)) {
        return next(new AppError('Access denied', 403));
      }

      const result = await storageService.deleteFile(key, provider);

      if (!result.success) {
        return next(new AppError('File deletion failed: ' + result.error, 500));
      }

      logger.info('File deleted successfully:', {
        userId: req.user.id,
        fileKey: key,
        provider: result.provider
      });

      res.status(200).json({
        status: 'success',
        message: 'File deleted successfully'
      });

    } catch (error) {
      logger.error('File deletion failed:', error);
      next(new AppError('File deletion failed', 500));
    }
  }
);

/**
 * @route   GET /api/v1/upload/info/:key
 * @desc    Get file information
 * @access  Private
 */
router.get('/info/:key',
  authenticate,
  async (req, res, next) => {
    try {
      const { key } = req.params;
      const { provider } = req.query;

      // Verify that the file belongs to the user (extract user ID from key)
      if (!key.includes(req.user.id)) {
        return next(new AppError('Access denied', 403));
      }

      const result = await storageService.getFileInfo(key, provider);

      if (!result.success) {
        return next(new AppError('Failed to get file info: ' + result.error, 500));
      }

      res.status(200).json({
        status: 'success',
        data: {
          key: result.key,
          size: result.size,
          contentType: result.contentType,
          lastModified: result.lastModified,
          provider: result.provider
        }
      });

    } catch (error) {
      logger.error('Get file info failed:', error);
      next(new AppError('Failed to get file info', 500));
    }
  }
);

module.exports = router;