import express from 'express';
import { body, validationResult } from 'express-validator';
import User from '../models/User';
import File from '../models/File';
import Folder from '../models/Folder';
import { authenticate } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';

const router = express.Router();

// Validation middleware
const validateProfileUpdate = [
  body('firstName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters'),
  body('lastName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters'),
  body('avatar')
    .optional()
    .isURL()
    .withMessage('Avatar must be a valid URL')
];

const validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one lowercase letter, one uppercase letter, and one number')
];

// @route   GET /api/user/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const user = await User.findById(req.user!._id).select('-password');
  
  res.json({
    success: true,
    data: { user }
  });
}));

// @route   PUT /api/user/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', authenticate, validateProfileUpdate, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { firstName, lastName, avatar } = req.body;

  const user = await User.findById(req.user!._id);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  if (firstName !== undefined) user.firstName = firstName;
  if (lastName !== undefined) user.lastName = lastName;
  if (avatar !== undefined) user.avatar = avatar;

  await user.save();

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: { user }
  });
}));

// @route   PUT /api/user/password
// @desc    Change password
// @access  Private
router.put('/password', authenticate, validatePasswordChange, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user!._id).select('+password');
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Verify current password
  const isCurrentPasswordValid = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordValid) {
    return res.status(400).json({
      success: false,
      message: 'Current password is incorrect'
    });
  }

  // Update password
  user.password = newPassword;
  await user.save();

  res.json({
    success: true,
    message: 'Password changed successfully'
  });
}));

// @route   GET /api/user/settings
// @desc    Get user settings
// @access  Private
router.get('/settings', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const user = await User.findById(req.user!._id).select('settings');
  
  res.json({
    success: true,
    data: { settings: user!.settings }
  });
}));

// @route   PUT /api/user/settings
// @desc    Update user settings
// @access  Private
router.put('/settings', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { theme, language, notifications } = req.body;

  const user = await User.findById(req.user!._id);
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  if (theme !== undefined) user.settings.theme = theme;
  if (language !== undefined) user.settings.language = language;
  if (notifications !== undefined) {
    if (notifications.email !== undefined) user.settings.notifications.email = notifications.email;
    if (notifications.push !== undefined) user.settings.notifications.push = notifications.push;
  }

  await user.save();

  res.json({
    success: true,
    message: 'Settings updated successfully',
    data: { settings: user.settings }
  });
}));

// @route   GET /api/user/storage
// @desc    Get user storage information
// @access  Private
router.get('/storage', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const user = await User.findById(req.user!._id).select('storage subscription');
  
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Calculate storage usage by type
  const storageByType = await File.aggregate([
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
        size: { $sum: '$size' }
      }
    }
  ]);

  // Get largest files
  const largestFiles = await File.find({ owner: req.user!._id })
    .sort({ size: -1 })
    .limit(5)
    .select('name originalName size mimeType createdAt');

  res.json({
    success: true,
    data: {
      storage: user.storage,
      subscription: user.subscription,
      byType: storageByType,
      largestFiles
    }
  });
}));

// @route   GET /api/user/activity
// @desc    Get user activity
// @access  Private
router.get('/activity', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { limit = 20 } = req.query;

  // Get recent files
  const recentFiles = await File.find({ owner: req.user!._id })
    .sort({ createdAt: -1 })
    .limit(parseInt(limit as string))
    .select('name originalName size mimeType createdAt');

  // Get recent folders
  const recentFolders = await Folder.find({ owner: req.user!._id })
    .sort({ createdAt: -1 })
    .limit(parseInt(limit as string))
    .select('name description createdAt');

  // Get storage usage over time (last 30 days)
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const storageHistory = await File.aggregate([
    {
      $match: {
        owner: req.user!._id,
        createdAt: { $gte: thirtyDaysAgo }
      }
    },
    {
      $group: {
        _id: {
          $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
        },
        size: { $sum: '$size' }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  res.json({
    success: true,
    data: {
      recentFiles,
      recentFolders,
      storageHistory
    }
  });
}));

// @route   DELETE /api/user/account
// @desc    Delete user account
// @access  Private
router.delete('/account', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      success: false,
      message: 'Password is required to delete account'
    });
  }

  const user = await User.findById(req.user!._id).select('+password');
  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(400).json({
      success: false,
      message: 'Password is incorrect'
    });
  }

  // Delete all user's files from disk
  const files = await File.find({ owner: req.user!._id });
  const fs = require('fs');
  
  for (const file of files) {
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }
  }

  // Delete all user's data from database
  await Promise.all([
    File.deleteMany({ owner: req.user!._id }),
    Folder.deleteMany({ owner: req.user!._id }),
    // Add other collections as needed
    User.findByIdAndDelete(req.user!._id)
  ]);

  res.json({
    success: true,
    message: 'Account deleted successfully'
  });
}));

// @route   POST /api/user/export-data
// @desc    Export user data
// @access  Private
router.post('/export-data', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  // Get all user data
  const [user, files, folders] = await Promise.all([
    User.findById(req.user!._id).select('-password'),
    File.find({ owner: req.user!._id }),
    Folder.find({ owner: req.user!._id })
  ]);

  const exportData = {
    user: {
      profile: {
        email: user!.email,
        username: user!.username,
        firstName: user!.firstName,
        lastName: user!.lastName,
        createdAt: user!.createdAt
      },
      subscription: user!.subscription,
      settings: user!.settings
    },
    files: files.map(file => ({
      name: file.name,
      originalName: file.originalName,
      mimeType: file.mimeType,
      size: file.size,
      tags: file.tags,
      createdAt: file.createdAt
    })),
    folders: folders.map(folder => ({
      name: folder.name,
      description: folder.description,
      path: folder.path,
      tags: folder.tags,
      createdAt: folder.createdAt
    }))
  };

  res.json({
    success: true,
    data: exportData
  });
}));

export default router; 