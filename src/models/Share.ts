import mongoose, { Schema, Document } from 'mongoose';
import { IShare } from '../types';

export interface IShareDocument extends IShare, Document {
  isExpired(): boolean;
  canDownload(): boolean;
  updateDownloadCount(): Promise<void>;
}

const shareSchema = new Schema<IShareDocument>({
  type: {
    type: String,
    enum: ['file', 'folder', 'collection'],
    required: [true, 'Share type is required']
  },
  resource: {
    type: Schema.Types.ObjectId,
    refPath: 'resourceModel',
    required: [true, 'Resource is required']
  },
  resourceModel: {
    type: String,
    enum: ['File', 'Folder', 'Collection'],
    required: [true, 'Resource model is required']
  },
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Share owner is required']
  },
  access: {
    type: {
      type: String,
      enum: ['public', 'password', 'email'],
      default: 'public'
    },
    password: {
      type: String,
      select: false
    },
    emails: [{
      type: String,
      trim: true,
      lowercase: true
    }],
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
  settings: {
    allowDownload: {
      type: Boolean,
      default: true
    },
    allowPreview: {
      type: Boolean,
      default: true
    },
    allowComments: {
      type: Boolean,
      default: false
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
shareSchema.index({ owner: 1 });
shareSchema.index({ resource: 1 });
shareSchema.index({ 'access.type': 1 });
shareSchema.index({ createdAt: -1 });

// Virtual for share URL
shareSchema.virtual('shareUrl').get(function() {
  return `${process.env.FRONTEND_URL}/share/${this._id}`;
});

// Method to check if share is expired
shareSchema.methods.isExpired = function(): boolean {
  if (!this.access.expiresAt) return false;
  return new Date() > this.access.expiresAt;
};

// Method to check if share can be downloaded
shareSchema.methods.canDownload = function(): boolean {
  if (this.isExpired()) return false;
  if (this.access.maxDownloads && this.access.downloadCount >= this.access.maxDownloads) {
    return false;
  }
  return this.settings.allowDownload;
};

// Method to update download count
shareSchema.methods.updateDownloadCount = async function(): Promise<void> {
  this.access.downloadCount += 1;
  await this.save();
};

// Pre-save middleware to set resource model
shareSchema.pre('save', function(next) {
  if (this.type === 'file') {
    this.resourceModel = 'File';
  } else if (this.type === 'folder') {
    this.resourceModel = 'Folder';
  } else if (this.type === 'collection') {
    this.resourceModel = 'Collection';
  }
  next();
});

export default mongoose.model<IShareDocument>('Share', shareSchema); 