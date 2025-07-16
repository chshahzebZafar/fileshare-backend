import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import User from '../models/User';
import { AuthRequest } from '../types';

interface JwtPayload {
  userId: string;
  email: string;
  iat: number;
  exp: number;
}

type AsyncFunction = (req: Request, res: Response, next: NextFunction) => Promise<void>;

export const asyncHandler = (fn: AsyncFunction) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      res.status(401).json({
        success: false,
        message: 'Invalid token. User not found.'
      });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        success: false,
        message: 'Invalid token.'
      });
      return;
    }
    
    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({
        success: false,
        message: 'Token expired.'
      });
      return;
    }

    res.status(500).json({
      success: false,
      message: 'Server error during authentication.'
    });
    return;
  }
};

export const optionalAuth = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
      const user = await User.findById(decoded.userId).select('-password');
      if (user) {
        req.user = user;
      }
    }

    next();
  } catch (error) {
    // Continue without authentication for optional routes
    next();
  }
};

export const requireEmailVerification = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      message: 'Authentication required.'
    });
    return;
  }

  if (!req.user.isEmailVerified) {
    res.status(403).json({
      success: false,
      message: 'Email verification required. Please check your email and verify your account.'
    });
    return;
  }

  next();
};

export const checkSubscription = (requiredPlan: 'free' | 'pro' | 'enterprise' = 'free') => {
  return async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
      return;
    }

    const planHierarchy = {
      free: 0,
      pro: 1,
      enterprise: 2
    };

    const userPlanLevel = planHierarchy[req.user.subscription.plan];
    const requiredPlanLevel = planHierarchy[requiredPlan];

    if (userPlanLevel < requiredPlanLevel) {
      res.status(403).json({
        success: false,
        message: `${requiredPlan} plan required for this feature.`
      });
      return;
    }

    if (req.user.subscription.status !== 'active') {
      res.status(403).json({
        success: false,
        message: 'Active subscription required for this feature.'
      });
      return;
    }

    next();
  };
};

export const checkStorageLimit = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      message: 'Authentication required.'
    });
    return;
  }

  // Simple storage check - just pass through for now
  next();
};

export const checkStorageLimitAfterUpload = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      message: 'Authentication required.'
    });
    return;
  }

  // Calculate total size of uploaded files
  let totalFileSize = 0;
  
  if (req.file) {
    totalFileSize = req.file.size;
  } else if (req.files && Array.isArray(req.files)) {
    totalFileSize = (req.files as Express.Multer.File[]).reduce((sum, file) => sum + file.size, 0);
  }

  const currentUsage = req.user.storage.used;
  const limit = req.user.storage.limit;

  if (currentUsage + totalFileSize > limit) {
    // Clean up uploaded files
    if (req.file) {
      fs.unlinkSync(req.file.path);
    } else if (req.files && Array.isArray(req.files)) {
      (req.files as Express.Multer.File[]).forEach(file => {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      });
    }

    res.status(413).json({
      success: false,
      message: 'Storage limit exceeded. Please upgrade your plan or delete some files.'
    });
    return;
  }

  next();
}; 