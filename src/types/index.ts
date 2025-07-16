import { Request } from 'express';

// User related types
export interface IUser {
  _id: string;
  email: string;
  username: string;
  password: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  isEmailVerified: boolean;
  emailVerificationToken?: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  subscription: {
    plan: 'free' | 'pro' | 'enterprise';
    status: 'active' | 'inactive' | 'cancelled';
    startDate: Date;
    endDate?: Date;
    features: string[];
  };
  storage: {
    used: number;
    limit: number;
  };
  settings: {
    theme: 'light' | 'dark' | 'auto';
    language: string;
    notifications: {
      email: boolean;
      push: boolean;
    };
  };
  createdAt: Date;
  updatedAt: Date;
}

// File related types
export interface IFile {
  _id: string;
  name: string;
  originalName: string;
  mimeType: string;
  size: number;
  path: string;
  hash: string;
  owner: string | IUser;
  folder?: string | IFolder;
  tags: string[];
  metadata: {
    width?: number;
    height?: number;
    duration?: number;
    bitrate?: number;
    codec?: string;
  };
  permissions: {
    public: boolean;
    password?: string;
    expiresAt?: Date;
    maxDownloads?: number;
    downloadCount: number;
  };
  aiAnalysis?: {
    category: string;
    tags: string[];
    description?: string;
    confidence: number;
  };
  createdAt: Date;
  updatedAt: Date;
}

// Folder related types
export interface IFolder {
  _id: string;
  name: string;
  description?: string;
  owner: string | IUser;
  parent?: string | IFolder;
  path: string;
  tags: string[];
  permissions: {
    public: boolean;
    password?: string;
    expiresAt?: Date;
  };
  createdAt: Date;
  updatedAt: Date;
}

// Share related types
export interface IShare {
  _id: string;
  type: 'file' | 'folder';
  resource: string | IFile | IFolder;
  owner: string | IUser;
  access: {
    type: 'public' | 'password' | 'email';
    password?: string;
    emails?: string[];
    expiresAt?: Date;
    maxDownloads?: number;
    downloadCount: number;
  };
  settings: {
    allowDownload: boolean;
    allowPreview: boolean;
    allowComments: boolean;
  };
  createdAt: Date;
  updatedAt: Date;
}

// Comment related types
export interface IComment {
  _id: string;
  content: string;
  author: string | IUser;
  file?: string | IFile;
  folder?: string | IFolder;
  parent?: string | IComment;
  replies: string[] | IComment[];
  createdAt: Date;
  updatedAt: Date;
}

// Analytics related types
export interface IAnalytics {
  _id: string;
  user: string | IUser;
  type: 'file_upload' | 'file_download' | 'file_share' | 'folder_create' | 'login';
  data: Record<string, any>;
  timestamp: Date;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Request with user
export interface AuthRequest extends Request {
  user?: IUser;
}

// Upload related types
export interface UploadProgress {
  fileId: string;
  fileName: string;
  progress: number;
  status: 'uploading' | 'processing' | 'completed' | 'error';
  error?: string;
}

// Search and filter types
export interface SearchFilters {
  query?: string;
  type?: 'file' | 'folder';
  mimeType?: string;
  tags?: string[];
  dateFrom?: Date;
  dateTo?: Date;
  sizeMin?: number;
  sizeMax?: number;
  sortBy?: 'name' | 'size' | 'createdAt' | 'updatedAt';
  sortOrder?: 'asc' | 'desc';
}

// Pagination types
export interface PaginationOptions {
  page: number;
  limit: number;
  skip: number;
}

// File upload options
export interface UploadOptions {
  folder?: string;
  tags?: string[];
  public?: boolean;
  password?: string;
  expiresAt?: Date;
  maxDownloads?: number;
}

// Environment variables interface
export interface EnvironmentVariables {
  NODE_ENV: string;
  PORT: number;
  MONGODB_URI: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
  FRONTEND_URL: string;
  UPLOAD_PATH: string;
  MAX_FILE_SIZE: number;
  ALLOWED_FILE_TYPES: string[];
  EMAIL_SERVICE: string;
  EMAIL_USER: string;
  EMAIL_PASS: string;
  REDIS_URL?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_REGION?: string;
  AWS_S3_BUCKET?: string;
} 