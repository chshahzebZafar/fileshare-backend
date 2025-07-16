import mongoose, { Schema, Document } from 'mongoose';
import { IFolder } from '../types';

export interface IFolderDocument extends IFolder, Document {
  getFullPath(): string;
  getChildren(): Promise<IFolderDocument[]>;
  getFiles(): Promise<any[]>;
  getTotalSize(): Promise<number>;
  isExpired(): boolean;
}

const folderSchema = new Schema<IFolderDocument>({
  name: {
    type: String,
    required: [true, 'Folder name is required'],
    trim: true,
    maxlength: [255, 'Folder name cannot exceed 255 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Folder owner is required']
  },
  parent: {
    type: Schema.Types.ObjectId,
    ref: 'Folder'
  },
  path: {
    type: String,
    unique: true
  },
  tags: [{
    type: String,
    trim: true
  }],
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
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
folderSchema.index({ owner: 1 });
folderSchema.index({ parent: 1 });
folderSchema.index({ tags: 1 });
folderSchema.index({ 'permissions.public': 1 });
folderSchema.index({ createdAt: -1 });
folderSchema.index({ name: 'text', description: 'text' });

// Virtual for folder depth
folderSchema.virtual('depth').get(function() {
  return this.path.split('/').length - 1;
});

// Virtual for is root folder
folderSchema.virtual('isRoot').get(function() {
  return !this.parent;
});

// Method to get full path
folderSchema.methods.getFullPath = function(): string {
  return this.path;
};

// Method to get children folders
folderSchema.methods.getChildren = async function(): Promise<IFolderDocument[]> {
  return this.model('Folder').find({ parent: this._id }).sort({ name: 1 });
};

// Method to get files in folder
folderSchema.methods.getFiles = async function(): Promise<any[]> {
  return this.model('File').find({ folder: this._id }).sort({ name: 1 });
};

// Method to get total size of folder
folderSchema.methods.getTotalSize = async function(): Promise<number> {
  const File = this.model('File');
  const result = await File.aggregate([
    { $match: { folder: this._id } },
    { $group: { _id: null, totalSize: { $sum: '$size' } } }
  ]);
  return result[0]?.totalSize || 0;
};

// Method to check if folder is expired
folderSchema.methods.isExpired = function(): boolean {
  if (!this.permissions.expiresAt) return false;
  return new Date() > this.permissions.expiresAt;
};

// Pre-save middleware to generate path
folderSchema.pre('save', async function(next) {
  // Always generate path for new documents or when name/parent changes
  if (this.isNew || this.isModified('name') || this.isModified('parent')) {
    try {
      if (this.parent) {
        const parentFolder = await this.model('Folder').findById(this.parent);
        if (!parentFolder) {
          throw new Error('Parent folder not found');
        }
        this.path = `${parentFolder.path}/${this.name}`;
      } else {
        // For root folders, create a simple path with user ID and folder name
        this.path = `/${this.owner.toString()}/${this.name}`;
      }
      
      // Ensure path is set
      if (!this.path) {
        throw new Error('Failed to generate folder path');
      }
    } catch (error) {
      next(error as Error);
    }
  }
  next();
});

// Pre-remove middleware to handle children
folderSchema.pre('remove', async function(next) {
  try {
    // Move all files to parent folder or root
    const File = this.model('File');
    await File.updateMany(
      { folder: this._id },
      { folder: this.parent || null }
    );

    // Move all subfolders to parent folder or root
    await this.model('Folder').updateMany(
      { parent: this._id },
      { parent: this.parent || null }
    );
  } catch (error) {
    next(error as Error);
  }
  next();
});

export default mongoose.model<IFolderDocument>('Folder', folderSchema); 