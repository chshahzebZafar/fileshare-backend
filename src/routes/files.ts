import express from 'express';
import fs from 'fs';
import { query, validationResult } from 'express-validator';
import File from '../models/File';
import Folder from '../models/Folder';
import { authenticate } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';
import S3Service from '../utils/s3';

const router = express.Router();

const validateFileQuery = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('sortBy')
    .optional()
    .isIn(['name', 'size', 'createdAt', 'updatedAt'])
    .withMessage('Invalid sort field'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc')
];

// @route   GET /api/files
// @desc    Get user's files with pagination and filtering
// @access  Private
router.get('/', authenticate, validateFileQuery, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const {
    page = 1,
    limit = 20,
    sortBy = 'createdAt',
    sortOrder = 'desc',
    folder,
    type,
    tags,
    search
  } = req.query;

  const skip = (parseInt(page as string) - 1) * parseInt(limit as string);
  const sort: Record<string, 1 | -1> = { [sortBy as string]: sortOrder === 'desc' ? -1 : 1 };

  // Build query
  const query: Record<string, unknown> = { owner: req.user!._id };

  if (folder) {
    query.folder = folder;
  }

  if (type) {
    if (type === 'image') query.mimeType = { $regex: /^image\// };
    else if (type === 'video') query.mimeType = { $regex: /^video\// };
    else if (type === 'audio') query.mimeType = { $regex: /^audio\// };
    else if (type === 'document') {
      query.mimeType = {
        $in: [
          'application/pdf',
          'application/msword',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'application/vnd.ms-excel',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'application/vnd.ms-powerpoint',
          'application/vnd.openxmlformats-officedocument.presentationml.presentation',
          'text/plain',
          'text/html',
          'text/css',
          'text/javascript',
          'application/json',
          'application/xml'
        ]
      };
    }
  }

  if (tags) {
    const tagArray = Array.isArray(tags) ? tags : [tags];
    query.tags = { $in: tagArray };
  }

  if (search) {
    const searchString = Array.isArray(search) ? search[0] : search;
    query.$or = [
      { name: { $regex: searchString, $options: 'i' } },
      { originalName: { $regex: searchString, $options: 'i' } },
      { tags: { $in: [new RegExp(searchString, 'i')] } }
    ];
  }

  // Execute query
  const [files, total] = await Promise.all([
    File.find(query)
      .populate('folder', 'name path')
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit as string)),
    File.countDocuments(query)
  ]);

  const totalPages = Math.ceil(total / parseInt(limit as string));

  res.json({
    success: true,
    message: 'Files retrieved successfully',
    data: { files },
    pagination: {
      page: parseInt(page as string),
      limit: parseInt(limit as string),
      total,
      totalPages
    }
  });
}));

// @route   GET /api/files/:fileId
// @desc    Get a specific file
// @access  Private
router.get('/:fileId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;

  const file = await File.findOne({ _id: fileId, owner: req.user!._id })
    .populate('folder', 'name path');

  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  res.json({
    success: true,
    message: 'File retrieved successfully',
    data: { file }
  });
}));

// @route   PUT /api/files/:fileId
// @desc    Update file metadata
// @access  Private
router.put('/:fileId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;
  const { name, tags, folder, permissions } = req.body;

  const file = await File.findOne({ _id: fileId, owner: req.user!._id });
  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  // Update fields
  if (name !== undefined) file.name = name;
  if (tags !== undefined) file.tags = tags;
  if (folder !== undefined) file.folder = folder;
  if (permissions !== undefined) {
    if (permissions.public !== undefined) file.permissions.public = permissions.public;
    if (permissions.password !== undefined) file.permissions.password = permissions.password;
    if (permissions.expiresAt !== undefined) file.permissions.expiresAt = permissions.expiresAt;
    if (permissions.maxDownloads !== undefined) file.permissions.maxDownloads = permissions.maxDownloads;
  }

  await file.save();
  await file.populate('folder', 'name path');

  res.json({
    success: true,
    message: 'File updated successfully',
    data: { file }
  });
}));

// @route   DELETE /api/files/:fileId
// @desc    Delete a file
// @access  Private
router.delete('/:fileId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;

  const file = await File.findOne({ _id: fileId, owner: req.user!._id });
  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  // Delete file from S3
  try {
    await S3Service.deleteFile(file.s3Key);
  } catch (error) {
    console.error('Failed to delete file from S3:', error);
    // Continue with database deletion even if S3 deletion fails
  }

  // Delete from database
  await file.deleteOne();

  res.json({
    success: true,
    message: 'File deleted successfully'
  });
}));

// @route   POST /api/files/bulk-delete
// @desc    Delete multiple files
// @access  Private
router.post('/bulk-delete', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileIds } = req.body;

  if (!Array.isArray(fileIds) || fileIds.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'File IDs array is required'
    });
  }

  const files = await File.find({ _id: { $in: fileIds }, owner: req.user!._id });
  
  if (files.length === 0) {
    return res.status(404).json({
      success: false,
      message: 'No files found'
    });
  }

  const deletedFiles = [];
  const errors = [];

  for (const file of files) {
    try {
      // Delete file from S3
      try {
        await S3Service.deleteFile(file.s3Key);
      } catch (s3Error) {
        console.error('Failed to delete file from S3:', s3Error);
        // Continue with database deletion even if S3 deletion fails
      }
      
      await file.deleteOne();
      deletedFiles.push(file._id);
    } catch (error) {
      errors.push({
        fileId: file._id,
        error: error instanceof Error ? error.message : 'Delete failed'
      });
    }
  }

  res.json({
    success: true,
    message: `Deleted ${deletedFiles.length} files successfully`,
    data: {
      deletedFiles,
      errors: errors.length > 0 ? errors : undefined
    }
  });
}));

// @route   POST /api/files/move
// @desc    Move files to a different folder
// @access  Private
router.post('/move', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileIds, folderId } = req.body;

  if (!Array.isArray(fileIds) || fileIds.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'File IDs array is required'
    });
  }

  // Validate folder if provided
  if (folderId) {
    const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id });
    if (!folder) {
      return res.status(404).json({
        success: false,
        message: 'Folder not found'
      });
    }
  }

  const result = await File.updateMany(
    { _id: { $in: fileIds }, owner: req.user!._id },
    { folder: folderId || null }
  );

  res.json({
    success: true,
    message: `Moved ${result.modifiedCount} files successfully`,
    data: { modifiedCount: result.modifiedCount }
  });
}));

// @route   GET /api/files/stats
// @desc    Get file statistics
// @access  Private
router.get('/stats/overview', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const stats = await File.aggregate([
    { $match: { owner: req.user!._id } },
    {
      $group: {
        _id: null,
        totalFiles: { $sum: 1 },
        totalSize: { $sum: '$size' },
        avgFileSize: { $avg: '$size' }
      }
    }
  ]);

  const typeStats = await File.aggregate([
    { $match: { owner: req.user!._id } },
    {
      $group: {
        _id: {
          $cond: {
            if: { $regexMatch: { input: '$mimeType', regex: /^image\// } },
            then: 'images',
            else: {
              $cond: {
                if: { $regexMatch: { input: '$mimeType', regex: /^video\// } },
                then: 'videos',
                else: {
                  $cond: {
                    if: { $regexMatch: { input: '$mimeType', regex: /^audio\// } },
                    then: 'audio',
                    else: 'documents'
                  }
                }
              }
            }
          }
        },
        count: { $sum: 1 },
        size: { $sum: '$size' }
      }
    }
  ]);

  const recentFiles = await File.find({ owner: req.user!._id })
    .sort({ createdAt: -1 })
    .limit(5)
    .select('name originalName size createdAt');

  res.json({
    success: true,
    data: {
      overview: stats[0] || { totalFiles: 0, totalSize: 0, avgFileSize: 0 },
      byType: typeStats,
      recentFiles
    }
  });
}));

export default router; 