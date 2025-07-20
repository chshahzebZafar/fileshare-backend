import mongoose, { Schema, Document } from 'mongoose';
import User from './User';
import { IFile } from '../types';

export interface IFileDocument extends Omit<IFile, '_id'>, Document {
  updateDownloadCount(): Promise<void>;
  isExpired(): boolean;
  canDownload(): boolean;
  getPublicUrl(): string;
}

const fileSchema = new Schema<IFileDocument>({
  title: {
    type: String,
    trim: true,
    default: ''
  },
  message: {
    type: String,
    trim: true,
    default: ''
  },
  recipients: [
    {
      email: { type: String, trim: true, required: true },
      type: { type: String, enum: ['to', 'cc'], default: 'to' }
    }
  ],
  name: {
    type: String,
    required: [true, 'File name is required'],
    trim: true
  },
  originalName: {
    type: String,
    required: [true, 'Original file name is required'],
    trim: true
  },
  mimeType: {
    type: String,
    required: [true, 'MIME type is required']
  },
  size: {
    type: Number,
    required: [true, 'File size is required'],
    min: [0, 'File size cannot be negative']
  },
  s3Key: {
    type: String,
    required: [true, 'S3 key is required']
  },
  hash: {
    type: String,
    required: [true, 'File hash is required']
  },
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'File owner is required']
  },
  folder: {
    type: Schema.Types.ObjectId,
    ref: 'Folder'
  },
  tags: [{
    type: String,
    trim: true
  }],
  metadata: {
    width: Number,
    height: Number,
    duration: Number,
    bitrate: Number,
    codec: String,
    iv: String
  },
  permissions: {
    public: {
      type: Boolean,
      default: false
    },
    password: {
      type: String,
      select: false
    },
    expiresAt: {
      type: Date
    },
    maxDownloads: {
      type: Number,
      min: [0, 'Max downloads cannot be negative']
    },
    downloadCount: {
      type: Number,
      default: 0,
      min: [0, 'Download count cannot be negative']
    }
  },
  aiAnalysis: {
    category: {
      type: String,
      enum: ['image', 'video', 'audio', 'document', 'archive', 'other']
    },
    tags: [String],
    description: String,
    confidence: {
      type: Number,
      min: [0, 'Confidence cannot be negative'],
      max: [1, 'Confidence cannot exceed 1']
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
fileSchema.index({ owner: 1 });
fileSchema.index({ folder: 1 });
fileSchema.index({ tags: 1 });
fileSchema.index({ 'permissions.public': 1 });
fileSchema.index({ createdAt: -1 });
fileSchema.index({ name: 'text', originalName: 'text' });
fileSchema.index({ hash: 1, owner: 1 }, { unique: true }); // Added compound unique index

// Virtual for file extension
fileSchema.virtual('extension').get(function(this: IFileDocument) {
  return this.originalName.split('.').pop()?.toLowerCase();
});

// Virtual for formatted size
fileSchema.virtual('formattedSize').get(function(this: IFileDocument) {
  const bytes = this.size;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
});

// Virtual for is image
fileSchema.virtual('isImage').get(function(this: IFileDocument) {
  return this.mimeType.startsWith('image/');
});

// Virtual for is video
fileSchema.virtual('isVideo').get(function(this: IFileDocument) {
  return this.mimeType.startsWith('video/');
});

// Virtual for is audio
fileSchema.virtual('isAudio').get(function(this: IFileDocument) {
  return this.mimeType.startsWith('audio/');
});

// Virtual for is document
fileSchema.virtual('isDocument').get(function(this: IFileDocument) {
  const documentTypes = [
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
  ];
  return documentTypes.includes(this.mimeType);
});

// Method to update download count
fileSchema.methods.updateDownloadCount = async function(): Promise<void> {
  this.permissions.downloadCount += 1;
  await this.save();
};

// Method to check if file is expired
fileSchema.methods.isExpired = function(): boolean {
  if (!this.permissions.expiresAt) return false;
  return new Date() > this.permissions.expiresAt;
};

// Method to check if file can be downloaded
fileSchema.methods.canDownload = function(): boolean {
  if (this.isExpired()) return false;
  if (this.permissions.maxDownloads && this.permissions.downloadCount >= this.permissions.maxDownloads) {
    return false;
  }
  return true;
};

// Method to get public URL
fileSchema.methods.getPublicUrl = function(): string {
  return `${process.env.BACKEND_URL}/api/download/${this._id}`;
};

// Pre-save middleware to update user storage
fileSchema.pre('save', async function(this: IFileDocument, next) {
  if (this.isNew) {
    try {
      await User.findByIdAndUpdate(
        this.owner,
        { $inc: { 'storage.used': this.size } }
      );
    } catch (error) {
      next(error as Error);
    }
  }
  next();
});

// Pre-deleteOne middleware to update user storage
fileSchema.pre('deleteOne', { document: true, query: false }, async function(this: IFileDocument, next) {
  try {
    await User.findByIdAndUpdate(
      this.owner,
      { $inc: { 'storage.used': -this.size } }
    );
  } catch (error) {
    next(error as Error);
  }
  next();
});

// Collection (Bundle) model for grouping files
export interface ICollectionDocument extends Document {
  name: string;
  owner: mongoose.Types.ObjectId;
  files: mongoose.Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
  title: string;
  message: string;
  recipients: { email: string, type: 'to' | 'cc' }[];
}

const collectionSchema = new Schema<ICollectionDocument>({
  name: { type: String, required: true, trim: true },
  owner: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  files: [{ type: Schema.Types.ObjectId, ref: 'File', required: true }],
  title: { type: String, trim: true, default: '' },
  message: { type: String, trim: true, default: '' },
  recipients: [
    {
      email: { type: String, trim: true, required: true },
      type: { type: String, enum: ['to', 'cc'], default: 'to' }
    }
  ],
}, {
  timestamps: true
});

export const Collection = mongoose.model<ICollectionDocument>('Collection', collectionSchema);

export default mongoose.model<IFileDocument>('File', fileSchema); 