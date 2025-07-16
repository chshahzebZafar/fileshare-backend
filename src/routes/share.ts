import express from 'express';
import { body, validationResult } from 'express-validator';
import Share from '../models/Share';
import File from '../models/File';
import Folder from '../models/Folder';
import { Collection } from '../models/File';
import { authenticate } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';

const router = express.Router();

// Validation middleware
const validateShare = [
  body('type')
    .isIn(['file', 'folder', 'collection'])
    .withMessage('Type must be file, folder, or collection'),
  body('resourceId')
    .isMongoId()
    .withMessage('Invalid resource ID'),
  body('access.type')
    .isIn(['public', 'password', 'email'])
    .withMessage('Access type must be public, password, or email'),
  body('access.password')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Password cannot be empty'),
  body('access.emails')
    .optional()
    .isArray()
    .withMessage('Emails must be an array'),
  body('access.expiresAt')
    .optional()
    .isISO8601()
    .withMessage('Invalid expiration date'),
  body('access.maxDownloads')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Max downloads must be a positive integer'),
  body('settings.allowDownload')
    .optional()
    .isBoolean()
    .withMessage('Allow download must be a boolean'),
  body('settings.allowPreview')
    .optional()
    .isBoolean()
    .withMessage('Allow preview must be a boolean'),
  body('settings.allowComments')
    .optional()
    .isBoolean()
    .withMessage('Allow comments must be a boolean')
];

// @route   POST /api/share
// @desc    Create a new share
// @access  Private
router.post('/', authenticate, validateShare, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { type, resourceId, access, settings } = req.body;

  // Verify resource exists and user owns it
  let resource;
  if (type === 'file') {
    resource = await File.findOne({ _id: resourceId, owner: req.user!._id });
  } else if (type === 'folder') {
    resource = await Folder.findOne({ _id: resourceId, owner: req.user!._id });
  } else if (type === 'collection') {
    resource = await Collection.findOne({ _id: resourceId, owner: req.user!._id });
  }

  if (!resource) {
    return res.status(404).json({
      success: false,
      message: 'Resource not found'
    });
  }

  // Create share
  const share = new Share({
    type,
    resource: resourceId,
    resourceModel: type === 'file' ? 'File' : type === 'folder' ? 'Folder' : 'Collection',
    owner: req.user!._id,
    access: {
      type: access.type,
      password: access.password,
      emails: access.emails,
      expiresAt: access.expiresAt ? new Date(access.expiresAt) : undefined,
      maxDownloads: access.maxDownloads,
      downloadCount: 0
    },
    settings: {
      allowDownload: settings?.allowDownload ?? true,
      allowPreview: settings?.allowPreview ?? true,
      allowComments: settings?.allowComments ?? false
    }
  });

  await share.save();
  await share.populate('resource');
  await share.populate('owner', 'username email');

  res.status(201).json({
    success: true,
    message: 'Share created successfully',
    data: { share }
  });
}));

// @route   GET /api/share
// @desc    Get user's shares
// @access  Private
router.get('/', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { type, active } = req.query;

  const query: Record<string, unknown> = { owner: req.user!._id };

  if (type) {
    query.type = type;
  }

  if (active === 'true') {
    query['access.expiresAt'] = { $gt: new Date() };
  } else if (active === 'false') {
    query['access.expiresAt'] = { $lte: new Date() };
  }

  const shares = await Share.find(query)
    .populate('resource', 'name originalName mimeType size')
    .sort({ createdAt: -1 });

  res.json({
    success: true,
    message: 'Shares retrieved successfully',
    data: { shares }
  });
}));

// @route   GET /api/share/:shareId
// @desc    Get a specific share
// @access  Private
router.get('/:shareId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { shareId } = req.params;

  const share = await Share.findOne({ _id: shareId, owner: req.user!._id })
    .populate('resource')
    .populate('owner', 'username email');

  if (!share) {
    return res.status(404).json({
      success: false,
      message: 'Share not found'
    });
  }

  res.json({
    success: true,
    message: 'Share retrieved successfully',
    data: { share }
  });
}));

// @route   PUT /api/share/:shareId
// @desc    Update a share
// @access  Private
router.put('/:shareId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { shareId } = req.params;
  const { access, settings } = req.body;

  const share = await Share.findOne({ _id: shareId, owner: req.user!._id });
  if (!share) {
    return res.status(404).json({
      success: false,
      message: 'Share not found'
    });
  }

  // Update access settings
  if (access) {
    if (access.type !== undefined) share.access.type = access.type;
    if (access.password !== undefined) share.access.password = access.password;
    if (access.emails !== undefined) share.access.emails = access.emails;
    if (access.expiresAt !== undefined) {
      share.access.expiresAt = access.expiresAt ? new Date(access.expiresAt) : undefined;
    }
    if (access.maxDownloads !== undefined) share.access.maxDownloads = access.maxDownloads;
  }

  // Update share settings
  if (settings) {
    if (settings.allowDownload !== undefined) share.settings.allowDownload = settings.allowDownload;
    if (settings.allowPreview !== undefined) share.settings.allowPreview = settings.allowPreview;
    if (settings.allowComments !== undefined) share.settings.allowComments = settings.allowComments;
  }

  await share.save();
  await share.populate('resource');
  await share.populate('owner', 'username email');

  res.json({
    success: true,
    message: 'Share updated successfully',
    data: { share }
  });
}));

// @route   DELETE /api/share/:shareId
// @desc    Delete a share
// @access  Private
router.delete('/:shareId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { shareId } = req.params;

  const share = await Share.findOne({ _id: shareId, owner: req.user!._id });
  if (!share) {
    return res.status(404).json({
      success: false,
      message: 'Share not found'
    });
  }

  await share.deleteOne();

  res.json({
    success: true,
    message: 'Share deleted successfully'
  });
}));

// @route   GET /api/share/public/:shareId
// @desc    Get public share info (for accessing shared content)
// @access  Public
router.get('/public/:shareId', asyncHandler(async (req, res) => {
  const { shareId } = req.params;

  const share = await Share.findById(shareId)
    .populate('resource')
    .populate('owner', 'username');

  if (!share) {
    return res.status(404).json({
      success: false,
      message: 'Share not found'
    });
  }

  // Check if share is expired
  if (share.access.expiresAt && new Date() > share.access.expiresAt) {
    return res.status(410).json({
      success: false,
      message: 'Share has expired'
    });
  }

  // Return basic info without sensitive data
  res.json({
    success: true,
    data: {
      share: {
        _id: share._id,
        type: share.type,
        resource: {
          _id: share.resource._id,
          name: share.resource.name,
          originalName: share.resource.originalName,
          mimeType: share.resource.mimeType,
          size: share.resource.size
        },
        owner: {
          username: share.owner.username
        },
        access: {
          type: share.access.type,
          expiresAt: share.access.expiresAt,
          maxDownloads: share.access.maxDownloads,
          downloadCount: share.access.downloadCount
        },
        settings: share.settings,
        createdAt: share.createdAt
      }
    }
  });
}));

// @route   POST /api/share/:shareId/access
// @desc    Validate access to a share
// @access  Public
router.post('/:shareId/access', asyncHandler(async (req, res) => {
  const { shareId } = req.params;
  const { password, email } = req.body;

  const share = await Share.findById(shareId);
  if (!share) {
    return res.status(404).json({
      success: false,
      message: 'Share not found'
    });
  }

  // Check if share is expired
  if (share.access.expiresAt && new Date() > share.access.expiresAt) {
    return res.status(410).json({
      success: false,
      message: 'Share has expired'
    });
  }

  // Check access type
  if (share.access.type === 'password') {
    if (!password || password !== share.access.password) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password'
      });
    }
  } else if (share.access.type === 'email') {
    if (!email || !share.access.emails?.includes(email)) {
      return res.status(401).json({
        success: false,
        message: 'Email not authorized'
      });
    }
  }

  res.json({
    success: true,
    message: 'Access granted'
  });
}));

// @route   GET /api/share/stats
// @desc    Get sharing statistics
// @access  Private
router.get('/stats/overview', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const stats = await Share.aggregate([
    { $match: { owner: req.user!._id } },
    {
      $group: {
        _id: null,
        totalShares: { $sum: 1 },
        activeShares: {
          $sum: {
            $cond: [
              { $or: [
                { $eq: ['$access.expiresAt', null] },
                { $gt: ['$access.expiresAt', new Date()] }
              ]},
              1,
              0
            ]
          }
        },
        totalDownloads: { $sum: '$access.downloadCount' }
      }
    }
  ]);

  const typeStats = await Share.aggregate([
    { $match: { owner: req.user!._id } },
    {
      $group: {
        _id: '$type',
        count: { $sum: 1 },
        downloads: { $sum: '$access.downloadCount' }
      }
    }
  ]);

  const recentShares = await Share.find({ owner: req.user!._id })
    .populate('resource', 'name originalName')
    .sort({ createdAt: -1 })
    .limit(5);

  res.json({
    success: true,
    data: {
      overview: stats[0] || { totalShares: 0, activeShares: 0, totalDownloads: 0 },
      byType: typeStats,
      recentShares
    }
  });
}));

export default router; 