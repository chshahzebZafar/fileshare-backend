import express from 'express';
import fs from 'fs';
import path from 'path';
import File from '../models/File';
import Share from '../models/Share';
import { authenticate, optionalAuth } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';
import jwt from 'jsonwebtoken';
import { Collection } from '../models/File';
import archiver from 'archiver';

const router = express.Router();

// Helper: Generate a short-lived download token
function generateDownloadToken(shareId: string) {
  const secret = process.env.JWT_SECRET || 'download_secret';
  return jwt.sign({ shareId }, secret, { expiresIn: '10m' });
}

function verifyDownloadToken(token: string) {
  const secret = process.env.JWT_SECRET || 'download_secret';
  try {
    return jwt.verify(token, secret) as { shareId: string };
  } catch {
    return null;
  }
}

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

// POST /api/download/share/:shareId/access
// Validate password or email and issue a short-lived download token
router.post('/share/:shareId/access', asyncHandler(async (req, res) => {
  const { shareId } = req.params;
  const { password, email } = req.body;

  const share = await Share.findById(shareId);
  if (!share) {
    return res.status(404).json({ success: false, message: 'Share not found' });
  }
  if (share.access.expiresAt && new Date() > share.access.expiresAt) {
    return res.status(410).json({ success: false, message: 'Share has expired' });
  }
  if (share.access.type === 'password') {
    if (!password || password !== share.access.password) {
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }
  } else if (share.access.type === 'email') {
    if (Array.isArray(share.access.emails) && share.access.emails.length > 0) {
      if (!email || !share.access.emails.includes(email)) {
        return res.status(401).json({ success: false, message: 'Email not authorized' });
      }
    }
    // If emails list is empty or not set, allow access without email validation
  }
  // Issue a short-lived download token
  const token = generateDownloadToken(shareId);
  res.json({ success: true, message: 'Access granted', token });
}));

// Update GET /api/download/share/:shareId to use token for email-based shares
router.get('/share/:shareId', asyncHandler(async (req, res) => {
  const { shareId } = req.params;
  const token = req.query.token as string || req.headers['x-download-token'] as string;

  // Find share
  const share = await Share.findById(shareId)
    .populate({
      path: 'resource',
      populate: { path: 'owner', select: 'username email' }
    })
    .populate('owner', 'username email');

  if (!share) {
    return res.status(404).json({ success: false, message: 'Share not found' });
  }
  if (share.access.expiresAt && new Date() > share.access.expiresAt) {
    return res.status(410).json({ success: false, message: 'Share has expired' });
  }
  if (share.access.maxDownloads && share.access.downloadCount >= share.access.maxDownloads) {
    return res.status(429).json({ success: false, message: 'Download limit exceeded' });
  }
  // Secure access check
  if (share.access.type === 'password' || share.access.type === 'email') {
    if (!token) {
      return res.status(401).json({ success: false, message: 'Download token required' });
    }
    const payload = verifyDownloadToken(token);
    if (!payload || payload.shareId !== shareId) {
      return res.status(401).json({ success: false, message: 'Invalid or expired download token' });
    }
  }

  // Get the actual file/folder/collection
  const resource = share.resource;
  if (!resource) {
    return res.status(404).json({ success: false, message: 'Resource not found' });
  }
  if (share.type === 'file') {
    const file = resource as any;
    if (!fs.existsSync(file.path)) {
      return res.status(404).json({ success: false, message: 'File not found on server' });
    }
    if (!share.settings.allowDownload) {
      return res.status(403).json({ success: false, message: 'Download not allowed for this share' });
    }
    const stats = fs.statSync(file.path);
    res.setHeader('Content-Type', file.mimeType);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Cache-Control', 'no-cache');
    share.access.downloadCount += 1;
    await share.save();
    const fileStream = fs.createReadStream(file.path);
    fileStream.pipe(res);
    fileStream.on('error', (error) => {
      console.error('File stream error:', error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Error streaming file' });
      }
    });
  } else if (share.type === 'collection') {
    // Download all files in the collection as a ZIP
    const collection = resource as any;
    if (!Array.isArray(collection.files) || collection.files.length === 0) {
      return res.status(404).json({ success: false, message: 'No files in collection' });
    }
    // Populate files
    await collection.populate('files');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${collection.name}.zip"`);
    res.setHeader('Cache-Control', 'no-cache');
    share.access.downloadCount += 1;
    await share.save();
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', (err) => {
      res.status(500).json({ success: false, message: 'Error creating ZIP', error: err.message });
    });
    archive.pipe(res);
    for (const file of collection.files) {
      if (file && file.path && file.originalName && fs.existsSync(file.path)) {
        archive.file(file.path, { name: file.originalName });
      }
    }
    archive.finalize();
    return;
  } else {
    return res.status(501).json({ success: false, message: 'Folder download not implemented yet' });
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
        formattedSize: (file as any).formattedSize,
        extension: (file as any).extension,
        isImage: (file as any).isImage,
        isVideo: (file as any).isVideo,
        isAudio: (file as any).isAudio,
        isDocument: (file as any).isDocument,
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