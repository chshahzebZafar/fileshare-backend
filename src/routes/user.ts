import express from 'express';
import fs from 'fs';
import { body, validationResult } from 'express-validator';
import User from '../models/User';
import File from '../models/File';
import Folder from '../models/Folder';
import { authenticate, asyncHandler } from '../middleware/auth';
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
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
    return;
  }

  const { firstName, lastName, avatar } = req.body;

  const user = await User.findById(req.user!._id);
  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
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
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
    return;
  }

  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user!._id).select('+password');
  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
  }

  // Verify current password
  const isCurrentPasswordValid = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordValid) {
    res.status(400).json({
      success: false,
      message: 'Current password is incorrect'
    });
    return;
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
  
  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
  }
  
  res.json({
    success: true,
    data: { settings: user.settings }
  });
}));

// @route   PUT /api/user/settings
// @desc    Update user settings
// @access  Private
router.put('/settings', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { theme, language, notifications } = req.body;

  const user = await User.findById(req.user!._id);
  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
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
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
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

// @route   GET /api/user/global-activity
// @desc    Get global user activity for world map
// @access  Public
router.get('/global-activity', asyncHandler(async (req, res) => {
  try {
    // Get users who were active in the last 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const userActivity = await User.aggregate([
      {
        $match: {
          lastActive: { $gte: twentyFourHoursAgo }
        }
      },
      {
        $group: {
          _id: '$country',
          userCount: { $sum: 1 },
          lastActive: { $max: '$lastActive' }
        }
      },
      {
        $project: {
          country: '$_id',
          userCount: 1,
          lastActive: 1,
          _id: 0
        }
      },
      {
        $sort: { userCount: -1 }
      }
    ]);

    // Add country coordinates and codes
    const countryData = {
      'United States': { code: 'US', lat: 39.8283, lng: -98.5795 },
      'United Kingdom': { code: 'GB', lat: 55.3781, lng: -3.4360 },
      'Germany': { code: 'DE', lat: 51.1657, lng: 10.4515 },
      'France': { code: 'FR', lat: 46.2276, lng: 2.2137 },
      'Canada': { code: 'CA', lat: 56.1304, lng: -106.3468 },
      'Australia': { code: 'AU', lat: -25.2744, lng: 133.7751 },
      'Japan': { code: 'JP', lat: 36.2048, lng: 138.2529 },
      'Brazil': { code: 'BR', lat: -14.2350, lng: -51.9253 },
      'India': { code: 'IN', lat: 20.5937, lng: 78.9629 },
      'Spain': { code: 'ES', lat: 40.4637, lng: -3.7492 },
      'Netherlands': { code: 'NL', lat: 52.1326, lng: 5.2913 },
      'Italy': { code: 'IT', lat: 41.8719, lng: 12.5674 },
      'Sweden': { code: 'SE', lat: 60.1282, lng: 18.6435 },
      'Norway': { code: 'NO', lat: 60.4720, lng: 8.4689 },
      'Denmark': { code: 'DK', lat: 56.2639, lng: 9.5018 },
      'Finland': { code: 'FI', lat: 61.9241, lng: 25.7482 },
      'Switzerland': { code: 'CH', lat: 46.8182, lng: 8.2275 },
      'Belgium': { code: 'BE', lat: 50.8503, lng: 4.3517 },
      'Austria': { code: 'AT', lat: 47.5162, lng: 14.5501 },
      'Poland': { code: 'PL', lat: 51.9194, lng: 19.1451 },
      'Czech Republic': { code: 'CZ', lat: 49.8175, lng: 15.4730 },
      'Hungary': { code: 'HU', lat: 47.1625, lng: 19.5033 },
      'Slovakia': { code: 'SK', lat: 48.6690, lng: 19.6990 },
      'Slovenia': { code: 'SI', lat: 46.0569, lng: 14.5058 },
      'Croatia': { code: 'HR', lat: 45.1000, lng: 15.2000 },
      'Serbia': { code: 'RS', lat: 44.0165, lng: 21.0059 },
      'Bulgaria': { code: 'BG', lat: 42.7339, lng: 25.4858 },
      'Romania': { code: 'RO', lat: 45.9432, lng: 24.9668 },
      'Greece': { code: 'GR', lat: 39.0742, lng: 21.8243 },
      'Portugal': { code: 'PT', lat: 39.3999, lng: -8.2245 },
      'Ireland': { code: 'IE', lat: 53.1424, lng: -7.6921 },
      'Iceland': { code: 'IS', lat: 64.9631, lng: -19.0208 },
      'Luxembourg': { code: 'LU', lat: 49.8153, lng: 6.1296 },
      'Malta': { code: 'MT', lat: 35.9375, lng: 14.3754 }
    };

    const enrichedActivity = userActivity
      .filter(activity => countryData[activity.country])
      .map(activity => ({
        ...activity,
        countryCode: countryData[activity.country].code,
        latitude: countryData[activity.country].lat,
        longitude: countryData[activity.country].lng
      }));

    res.json({
      success: true,
      data: {
        userActivity: enrichedActivity,
        totalUsers: enrichedActivity.reduce((sum, activity) => sum + activity.userCount, 0),
        totalCountries: enrichedActivity.length,
        lastUpdated: new Date()
      }
    });
  } catch (error) {
    console.error('Error fetching global activity:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch global activity data'
    });
  }
}));

// @route   DELETE /api/user/account
// @desc    Delete user account
// @access  Private
router.delete('/account', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { password } = req.body;

  if (!password) {
    res.status(400).json({
      success: false,
      message: 'Password is required to delete account'
    });
    return;
  }

  const user = await User.findById(req.user!._id).select('+password');
  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    res.status(400).json({
      success: false,
      message: 'Password is incorrect'
    });
    return;
  }

  // Delete all user's files from disk
  const files = await File.find({ owner: req.user!._id });
  
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

  if (!user) {
    res.status(404).json({
      success: false,
      message: 'User not found'
    });
    return;
  }

  const exportData = {
    user: {
      profile: {
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        createdAt: user.createdAt
      },
      subscription: user.subscription,
      settings: user.settings
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