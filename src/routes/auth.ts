import express from 'express';
import { body, validationResult } from 'express-validator';
import User from '../models/User';
import { authenticate, asyncHandler } from '../middleware/auth';
import { errorHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';

const router = express.Router();

// Validation middleware
const validateRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('username')
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('firstName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters'),
  body('lastName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters')
];

const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const validatePasswordReset = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email')
];

const validatePasswordUpdate = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
];

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', validateRegistration, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email, username, password, firstName, lastName } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: existingUser.email === email 
        ? 'Email already registered' 
        : 'Username already taken'
    });
  }

  // Create new user
  const user = new User({
    email,
    username,
    password,
    firstName,
    lastName
  });

  await user.save();

  // Generate email verification token
  const verificationToken = user.generateEmailVerificationToken();
  await user.save();

  // TODO: Send verification email
  console.log('Verification token:', verificationToken);

  // Generate auth token
  const token = user.generateAuthToken();

  res.status(201).json({
    success: true,
    message: 'User registered successfully. Please check your email to verify your account.',
    data: {
      user: {
        _id: user._id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: user.isEmailVerified,
        subscription: user.subscription,
        storage: user.storage
      },
      token
    }
  });
}));

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', validateLogin, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email, password } = req.body;

  // Find user by email
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Check password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Generate auth token
  const token = user.generateAuthToken();

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: {
        _id: user._id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: user.isEmailVerified,
        subscription: user.subscription,
        storage: user.storage,
        settings: user.settings
      },
      token
    }
  });
}));

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  res.json({
    success: true,
    message: 'User retrieved successfully',
    data: {
      user: {
        _id: req.user!._id,
        email: req.user!.email,
        username: req.user!.username,
        firstName: req.user!.firstName,
        lastName: req.user!.lastName,
        avatar: req.user!.avatar,
        isEmailVerified: req.user!.isEmailVerified,
        subscription: req.user!.subscription,
        storage: req.user!.storage,
        settings: req.user!.settings,
        createdAt: req.user!.createdAt
      }
    }
  });
}));

// @route   POST /api/auth/forgot-password
// @desc    Send password reset email
// @access  Public
router.post('/forgot-password', validatePasswordReset, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal if email exists or not
    return res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    });
  }

  // Generate reset token
  const resetToken = user.generatePasswordResetToken();
  await user.save();

  // TODO: Send reset email
  console.log('Reset token:', resetToken);

  res.json({
    success: true,
    message: 'If an account with that email exists, a password reset link has been sent.'
  });
}));

// @route   POST /api/auth/reset-password
// @desc    Reset password with token
// @access  Public
router.post('/reset-password', validatePasswordUpdate, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { token, password } = req.body;

  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() }
  }).select('+resetPasswordToken +resetPasswordExpires');

  if (!user) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired reset token'
    });
  }

  // Update password
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.json({
    success: true,
    message: 'Password reset successful'
  });
}));

// @route   POST /api/auth/verify-email
// @desc    Verify email with token
// @access  Public
router.post('/verify-email', asyncHandler(async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'Verification token is required'
    });
  }

  const user = await User.findOne({ emailVerificationToken: token });
  if (!user) {
    return res.status(400).json({
      success: false,
      message: 'Invalid verification token'
    });
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  await user.save();

  res.json({
    success: true,
    message: 'Email verified successfully'
  });
}));

// @route   POST /api/auth/resend-verification
// @desc    Resend email verification
// @access  Private
router.post('/resend-verification', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  if (req.user!.isEmailVerified) {
    return res.status(400).json({
      success: false,
      message: 'Email is already verified'
    });
  }

  const verificationToken = req.user!.generateEmailVerificationToken();
  await req.user!.save();

  // TODO: Send verification email
  console.log('New verification token:', verificationToken);

  res.json({
    success: true,
    message: 'Verification email sent'
  });
}));

// @route   PUT /api/auth/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', authenticate, asyncHandler(async (req: AuthRequest, res) => {
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
    data: {
      user: {
        _id: user._id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar,
        isEmailVerified: user.isEmailVerified,
        subscription: user.subscription,
        storage: user.storage,
        settings: user.settings
      }
    }
  });
}));

// @route   PUT /api/auth/settings
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
    data: {
      settings: user.settings
    }
  });
}));

// @route   POST /api/auth/logout
// @desc    Logout user (client-side token removal)
// @access  Private
router.post('/logout', authenticate, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

export default router; 