import express from 'express';
import { body, validationResult } from 'express-validator';
import path from 'path';
import fs from 'fs';
import File from '../models/File';
import Folder from '../models/Folder';
import { authenticate, checkStorageLimit } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { uploadSingle, uploadMultiple, generateFileHash, cleanupUploadedFiles } from '../middleware/upload';
import { AuthRequest } from '../types';

const router = express.Router();

// Validation middleware
const validateUploadOptions = [
  body('folder')
    .optional()
    .isMongoId()
    .withMessage('Invalid folder ID'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('public')
    .optional()
    .isBoolean()
    .withMessage('Public must be a boolean'),
  body('password')
    .optional()
    .isLength({ min: 1 })
    .withMessage('Password cannot be empty'),
  body('expiresAt')
    .optional()
    .isISO8601()
    .withMessage('Invalid expiration date'),
  body('maxDownloads')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Max downloads must be a positive integer')
];

// @route   POST /api/upload/single
// @desc    Upload a single file
// @access  Private
router.post('/single', 
  authenticate, 
  checkStorageLimit,
  validateUploadOptions,
  asyncHandler(async (req: AuthRequest, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    uploadSingle(req, res, async (err: any) => {
      if (err) {
        return res.status(400).json({
          success: false,
          message: err.message
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded'
        });
      }

      try {
        const { folder, tags, public: isPublic, password, expiresAt, maxDownloads } = req.body;

        // Validate folder if provided
        if (folder) {
          const folderDoc = await Folder.findOne({ _id: folder, owner: req.user!._id });
          if (!folderDoc) {
            cleanupUploadedFiles(req.file);
            return res.status(404).json({
              success: false,
              message: 'Folder not found'
            });
          }
        }

        // Generate file hash
        const hash = await generateFileHash(req.file.path);

        // Check for duplicate file
        const existingFile = await File.findOne({ hash, owner: req.user!._id });
        if (existingFile) {
          cleanupUploadedFiles(req.file);
          return res.status(409).json({
            success: false,
            message: 'File already exists',
            data: { existingFile }
          });
        }

        // Create file document
        const file = new File({
          name: req.file.filename,
          originalName: req.file.originalname,
          mimeType: req.file.mimetype,
          size: req.file.size,
          path: req.file.path,
          hash,
          owner: req.user!._id,
          folder: folder || null,
          tags: tags ? JSON.parse(tags) : [],
          permissions: {
            public: isPublic === 'true' || isPublic === true,
            password: password || undefined,
            expiresAt: expiresAt ? new Date(expiresAt) : undefined,
            maxDownloads: maxDownloads ? parseInt(maxDownloads) : undefined,
            downloadCount: 0
          }
        });

        await file.save();

        // Populate owner and folder
        await file.populate('owner', 'username email');
        if (file.folder) {
          await file.populate('folder', 'name path');
        }

        res.status(201).json({
          success: true,
          message: 'File uploaded successfully',
          data: { file }
        });

      } catch (error) {
        cleanupUploadedFiles(req.file);
        throw error;
      }
    });
  })
);

// @route   POST /api/upload/multiple
// @desc    Upload multiple files
// @access  Private
router.post('/multiple',
  authenticate,
  checkStorageLimit,
  validateUploadOptions,
  asyncHandler(async (req: AuthRequest, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    uploadMultiple(req, res, async (err: any) => {
      if (err) {
        return res.status(400).json({
          success: false,
          message: err.message
        });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No files uploaded'
        });
      }

      try {
        const { folder, tags, public: isPublic, password, expiresAt, maxDownloads } = req.body;
        const files = req.files as Express.Multer.File[];

        // Validate folder if provided
        if (folder) {
          const folderDoc = await Folder.findOne({ _id: folder, owner: req.user!._id });
          if (!folderDoc) {
            cleanupUploadedFiles(files);
            return res.status(404).json({
              success: false,
              message: 'Folder not found'
            });
          }
        }

        const uploadedFiles = [];
        const errors = [];

        for (const file of files) {
          try {
            // Generate file hash
            const hash = await generateFileHash(file.path);

            // Check for duplicate file
            const existingFile = await File.findOne({ hash, owner: req.user!._id });
            if (existingFile) {
              cleanupUploadedFiles([file]);
              errors.push({
                filename: file.originalname,
                error: 'File already exists'
              });
              continue;
            }

            // Create file document
            const fileDoc = new File({
              name: file.filename,
              originalName: file.originalname,
              mimeType: file.mimetype,
              size: file.size,
              path: file.path,
              hash,
              owner: req.user!._id,
              folder: folder || null,
              tags: tags ? JSON.parse(tags) : [],
              permissions: {
                public: isPublic === 'true' || isPublic === true,
                password: password || undefined,
                expiresAt: expiresAt ? new Date(expiresAt) : undefined,
                maxDownloads: maxDownloads ? parseInt(maxDownloads) : undefined,
                downloadCount: 0
              }
            });

            await fileDoc.save();
            await fileDoc.populate('owner', 'username email');
            if (fileDoc.folder) {
              await fileDoc.populate('folder', 'name path');
            }

            uploadedFiles.push(fileDoc);

          } catch (error) {
            cleanupUploadedFiles([file]);
            errors.push({
              filename: file.originalname,
              error: error instanceof Error ? error.message : 'Upload failed'
            });
          }
        }

        res.status(201).json({
          success: true,
          message: `Uploaded ${uploadedFiles.length} files successfully`,
          data: {
            files: uploadedFiles,
            errors: errors.length > 0 ? errors : undefined
          }
        });

      } catch (error) {
        cleanupUploadedFiles(files);
        throw error;
      }
    });
  })
);

// @route   POST /api/upload/chunk
// @desc    Upload file in chunks (for large files)
// @access  Private
router.post('/chunk',
  authenticate,
  asyncHandler(async (req: AuthRequest, res) => {
    const { chunkIndex, totalChunks, fileId, fileName, fileSize, mimeType } = req.body;

    if (!chunkIndex || !totalChunks || !fileId || !fileName) {
      return res.status(400).json({
        success: false,
        message: 'Missing required chunk information'
      });
    }

    // Create temporary directory for chunks
    const tempDir = path.join(process.env.UPLOAD_PATH || './uploads', 'temp', fileId);
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    // Save chunk
    const chunkPath = path.join(tempDir, `chunk_${chunkIndex}`);
    const chunkData = req.body.chunk;
    
    if (!chunkData) {
      return res.status(400).json({
        success: false,
        message: 'No chunk data provided'
      });
    }

    // Convert base64 to buffer and save
    const buffer = Buffer.from(chunkData, 'base64');
    fs.writeFileSync(chunkPath, buffer);

    // Check if all chunks are uploaded
    const uploadedChunks = fs.readdirSync(tempDir).filter(file => file.startsWith('chunk_'));
    
    if (uploadedChunks.length === parseInt(totalChunks)) {
      // Combine chunks
      const finalPath = path.join(process.env.UPLOAD_PATH || './uploads', req.user!._id.toString(), fileName);
      const finalDir = path.dirname(finalPath);
      
      if (!fs.existsSync(finalDir)) {
        fs.mkdirSync(finalDir, { recursive: true });
      }

      const writeStream = fs.createWriteStream(finalPath);
      
      for (let i = 0; i < parseInt(totalChunks); i++) {
        const chunkPath = path.join(tempDir, `chunk_${i}`);
        const chunkBuffer = fs.readFileSync(chunkPath);
        writeStream.write(chunkBuffer);
      }
      
      writeStream.end();

      // Clean up temp directory
      fs.rmSync(tempDir, { recursive: true, force: true });

      // Create file document
      const hash = await generateFileHash(finalPath);
      
      const file = new File({
        name: fileName,
        originalName: fileName,
        mimeType,
        size: parseInt(fileSize),
        path: finalPath,
        hash,
        owner: req.user!._id
      });

      await file.save();

      res.json({
        success: true,
        message: 'File uploaded successfully',
        data: { file }
      });

    } else {
      res.json({
        success: true,
        message: `Chunk ${chunkIndex} uploaded successfully`,
        data: { 
          uploadedChunks: uploadedChunks.length,
          totalChunks: parseInt(totalChunks)
        }
      });
    }
  })
);

// @route   GET /api/upload/progress/:fileId
// @desc    Get upload progress for a file
// @access  Private
router.get('/progress/:fileId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;
  
  // This would typically be stored in Redis or memory for real-time progress
  // For now, we'll return a mock response
  res.json({
    success: true,
    data: {
      fileId,
      progress: 0,
      status: 'pending'
    }
  });
}));

// @route   DELETE /api/upload/cancel/:fileId
// @desc    Cancel file upload
// @access  Private
router.delete('/cancel/:fileId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { fileId } = req.params;
  
  // Clean up any temporary files
  const tempDir = path.join(process.env.UPLOAD_PATH || './uploads', 'temp', fileId);
  if (fs.existsSync(tempDir)) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  res.json({
    success: true,
    message: 'Upload cancelled successfully'
  });
}));

export default router; 