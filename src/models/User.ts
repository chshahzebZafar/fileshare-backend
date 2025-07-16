import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { IUser } from '../types';

export interface IUserDocument extends IUser, Document {
  comparePassword(candidatePassword: string): Promise<boolean>;
  generateAuthToken(): string;
  generateEmailVerificationToken(): string;
  generatePasswordResetToken(): string;
  updateStorageUsed(bytes: number): Promise<void>;
  hasFeature(feature: string): boolean;
}

export interface IUserModel extends mongoose.Model<IUserDocument> {
  getStorageLimit(plan: string): number;
}

const userSchema = new Schema<IUserDocument>({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  firstName: {
    type: String,
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  avatar: {
    type: String,
    default: null
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    select: false
  },
  resetPasswordToken: {
    type: String,
    select: false
  },
  resetPasswordExpires: {
    type: Date,
    select: false
  },
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'pro', 'enterprise'],
      default: 'free'
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'cancelled'],
      default: 'active'
    },
    startDate: {
      type: Date,
      default: Date.now
    },
    endDate: {
      type: Date
    },
    features: [{
      type: String,
      default: ['basic_upload', 'basic_download']
    }]
  },
  storage: {
    used: {
      type: Number,
      default: 0
    },
    limit: {
      type: Number,
      default: 1024 * 1024 * 1024 // 1GB for free plan
    }
  },
  settings: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    },
    language: {
      type: String,
      default: 'en'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      }
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ 'subscription.status': 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.username;
});

// Virtual for storage usage percentage
userSchema.virtual('storageUsagePercentage').get(function() {
  return Math.round((this.storage.used / this.storage.limit) * 100);
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error as Error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to generate JWT token
userSchema.methods.generateAuthToken = function(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not configured');
  }
  
  const payload = { userId: this._id, email: this.email };
  const options = { expiresIn: process.env.JWT_EXPIRES_IN || '7d' };
  
  return jwt.sign(payload, secret, options);
};

// Method to generate email verification token
userSchema.methods.generateEmailVerificationToken = function(): string {
  const token = crypto.randomBytes(32).toString('hex');
  this.emailVerificationToken = token;
  return token;
};

// Method to generate password reset token
userSchema.methods.generatePasswordResetToken = function(): string {
  const token = crypto.randomBytes(32).toString('hex');
  this.resetPasswordToken = token;
  this.resetPasswordExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  return token;
};

// Method to update storage used
userSchema.methods.updateStorageUsed = async function(bytes: number): Promise<void> {
  this.storage.used += bytes;
  await this.save();
};

// Method to check if user has a specific feature
userSchema.methods.hasFeature = function(feature: string): boolean {
  return this.subscription.features.includes(feature);
};

// Static method to get storage limits by plan
userSchema.statics.getStorageLimit = function(plan: string): number {
  const limits = {
    free: 1024 * 1024 * 1024, // 1GB
    pro: 10 * 1024 * 1024 * 1024, // 10GB
    enterprise: 100 * 1024 * 1024 * 1024 // 100GB
  };
  return limits[plan as keyof typeof limits] || limits.free;
};

export default mongoose.model<IUserDocument, IUserModel>('User', userSchema); 