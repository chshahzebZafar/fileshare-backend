import express from 'express';
import fs from 'fs';
import path from 'path';
import File from '../models/File';
import Share from '../models/Share';
import { authenticate, optionalAuth } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';

const router = express.Router();

// @route   GET /api/download/:fileId
// @desc    Download a file
// @access  Private/Public (depending on file permissions)
router.get('/:fileId', optionalAuth, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;
  const { password } = req.query;

  // Find file
  const file = await File.findById(fileId)
    .populate('owner', 'username email')
    .populate('folder', 'name path');

  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  // Check if file is expired
  if (file.isExpired()) {
    return res.status(410).json({
      success: false,
      message: 'File has expired'
    });
  }

  // Check download limits
  if (!file.canDownload()) {
    return res.status(429).json({
      success: false,
      message: 'Download limit exceeded'
    });
  }

  // Check access permissions
  const isOwner = req.user && req.user._id.toString() === file.owner._id.toString();
  const isPublic = file.permissions.public;

  if (!isOwner && !isPublic) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Check password if required
  if (file.permissions.password && !isOwner) {
    if (!password || password !== file.permissions.password) {
      return res.status(401).json({
        success: false,
        message: 'Password required'
      });
    }
  }

  // Check if file exists on disk
  if (!fs.existsSync(file.path)) {
    return res.status(404).json({
      success: false,
      message: 'File not found on server'
    });
  }

  // Get file stats
  const stats = fs.statSync(file.path);

  // Set headers
  res.setHeader('Content-Type', file.mimeType);
  res.setHeader('Content-Length', stats.size);
  res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
  res.setHeader('Cache-Control', 'no-cache');

  // Update download count
  await file.updateDownloadCount();

  // Stream file
  const fileStream = fs.createReadStream(file.path);
  fileStream.pipe(res);

  // Handle errors
  fileStream.on('error', (error) => {
    console.error('File stream error:', error);
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: 'Error streaming file'
      });
    }
  });
}));

// @route   GET /api/download/share/:shareId
// @desc    Download a shared file
// @access  Public
router.get('/share/:shareId', asyncHandler(async (req, res) => {
  const { shareId } = req.params;
  const { password } = req.query;

  // Find share
  const share = await Share.findById(shareId)
    .populate({
      path: 'resource',
      populate: {
        path: 'owner',
        select: 'username email'
      }
    })
    .populate('owner', 'username email');

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

  // Check download limits
  if (share.access.maxDownloads && share.access.downloadCount >= share.access.maxDownloads) {
    return res.status(429).json({
      success: false,
      message: 'Download limit exceeded'
    });
  }

  // Check access type
  if (share.access.type === 'password') {
    if (!password || password !== share.access.password) {
      return res.status(401).json({
        success: false,
        message: 'Password required'
      });
    }
  } else if (share.access.type === 'email') {
    // TODO: Implement email-based access control
    return res.status(403).json({
      success: false,
      message: 'Email-based access not implemented yet'
    });
  }

  // Get the actual file/folder
  const resource = share.resource;
  if (!resource) {
    return res.status(404).json({
      success: false,
      message: 'Resource not found'
    });
  }

  // Handle file download
  if (share.type === 'file') {
    const file = resource as any;
    
    if (!fs.existsSync(file.path)) {
      return res.status(404).json({
        success: false,
        message: 'File not found on server'
      });
    }

    // Check if download is allowed
    if (!share.settings.allowDownload) {
      return res.status(403).json({
        success: false,
        message: 'Download not allowed for this share'
      });
    }

    // Get file stats
    const stats = fs.statSync(file.path);

    // Set headers
    res.setHeader('Content-Type', file.mimeType);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Cache-Control', 'no-cache');

    // Update download count
    share.access.downloadCount += 1;
    await share.save();

    // Stream file
    const fileStream = fs.createReadStream(file.path);
    fileStream.pipe(res);

    // Handle errors
    fileStream.on('error', (error) => {
      console.error('File stream error:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: 'Error streaming file'
        });
      }
    });

  } else {
    // Handle folder download (zip)
    return res.status(501).json({
      success: false,
      message: 'Folder download not implemented yet'
    });
  }
}));

// @route   GET /api/download/preview/:fileId
// @desc    Preview a file (for images, videos, etc.)
// @access  Private/Public (depending on file permissions)
router.get('/preview/:fileId', optionalAuth, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;

  // Find file
  const file = await File.findById(fileId)
    .populate('owner', 'username email');

  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  // Check if file is expired
  if (file.isExpired()) {
    return res.status(410).json({
      success: false,
      message: 'File has expired'
    });
  }

  // Check access permissions
  const isOwner = req.user && req.user._id.toString() === file.owner._id.toString();
  const isPublic = file.permissions.public;

  if (!isOwner && !isPublic) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Check if file exists on disk
  if (!fs.existsSync(file.path)) {
    return res.status(404).json({
      success: false,
      message: 'File not found on server'
    });
  }

  // Get file stats
  const stats = fs.statSync(file.path);

  // Set headers for preview
  res.setHeader('Content-Type', file.mimeType);
  res.setHeader('Content-Length', stats.size);
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Cache-Control', 'public, max-age=3600');

  // Stream file
  const fileStream = fs.createReadStream(file.path);
  fileStream.pipe(res);

  // Handle errors
  fileStream.on('error', (error) => {
    console.error('File stream error:', error);
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: 'Error streaming file'
      });
    }
  });
}));

// @route   GET /api/download/info/:fileId
// @desc    Get file information without downloading
// @access  Private/Public (depending on file permissions)
router.get('/info/:fileId', optionalAuth, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;

  // Find file
  const file = await File.findById(fileId)
    .populate('owner', 'username email')
    .populate('folder', 'name path');

  if (!file) {
    return res.status(404).json({
      success: false,
      message: 'File not found'
    });
  }

  // Check if file is expired
  if (file.isExpired()) {
    return res.status(410).json({
      success: false,
      message: 'File has expired'
    });
  }

  // Check access permissions
  const isOwner = req.user && req.user._id.toString() === file.owner._id.toString();
  const isPublic = file.permissions.public;

  if (!isOwner && !isPublic) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Check if file exists on disk
  const exists = fs.existsSync(file.path);

  res.json({
    success: true,
    data: {
      file: {
        _id: file._id,
        name: file.name,
        originalName: file.originalName,
        mimeType: file.mimeType,
        size: file.size,
        formattedSize: file.formattedSize,
        extension: file.extension,
        isImage: file.isImage,
        isVideo: file.isVideo,
        isAudio: file.isAudio,
        isDocument: file.isDocument,
        tags: file.tags,
        metadata: file.metadata,
        aiAnalysis: file.aiAnalysis,
        permissions: {
          public: file.permissions.public,
          expiresAt: file.permissions.expiresAt,
          maxDownloads: file.permissions.maxDownloads,
          downloadCount: file.permissions.downloadCount
        },
        owner: file.owner,
        folder: file.folder,
        createdAt: file.createdAt,
        updatedAt: file.updatedAt,
        exists
      }
    }
  });
}));

export default router; 