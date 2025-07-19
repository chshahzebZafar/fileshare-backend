import express from 'express';
import { body, validationResult } from 'express-validator';
import path from 'path';
import fs from 'fs';
import File from '../models/File';
import Folder from '../models/Folder';
import { authenticate, checkStorageLimit } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { uploadSingle, uploadMultiple, generateFileHash, cleanupUploadedFiles, encryptFileOnDisk } from '../middleware/upload';
import { AuthRequest } from '../types';
import { Collection } from '../models/File';

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

    uploadSingle(req, res, async (err: Error | null) => {
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
       // Check for duplicate file
const existingFile = await File.findOne({ hash, owner: req.user!._id });
if (existingFile) {
  cleanupUploadedFiles(req.file);

  // Optionally update metadata (like folder, tags) if user provides them again
  if (folder) existingFile.folder = folder;
  if (tags) existingFile.tags = JSON.parse(tags);
  if (typeof isPublic !== 'undefined') existingFile.permissions.public = isPublic === 'true' || isPublic === true;
  if (password) existingFile.permissions.password = password;
  if (expiresAt) existingFile.permissions.expiresAt = new Date(expiresAt);
  if (maxDownloads) existingFile.permissions.maxDownloads = parseInt(maxDownloads);

  await existingFile.save();

  await existingFile.populate('owner', 'username email');
  if (existingFile.folder) {
    await existingFile.populate('folder', 'name path');
  }

  return res.status(200).json({
    success: true,
    message: 'File already exists, reused previous file',
    data: { file: existingFile }
  });
}


        // Encrypt the file on disk
        const { iv } = await encryptFileOnDisk(req.file.path);
        console.log('Saved file with IV:', iv, 'for file:', req.file.filename);

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
          },
          metadata: {
            ...req.file.metadata,
            iv
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

    uploadMultiple(req, res, async (err: Error | null) => {
      console.log('📤 Backend: Upload request received');
      console.log('📤 Backend: req.files:', req.files ? req.files.length : 'undefined');
      console.log('📤 Backend: req.body:', req.body);
      console.log('📤 Backend: req.headers:', req.headers);
      console.log('📤 Backend: User:', req.user?._id);
      
      if (err) {
        console.log('❌ Backend: Upload error:', err.message);
        return res.status(400).json({
          success: false,
          message: err.message
        });
      }

      if (!req.files || req.files.length === 0) {
        console.log('❌ Backend: No files in request');
        return res.status(400).json({
          success: false,
          message: 'No files uploaded'
        });
      }
      
      console.log('✅ Backend: Files received successfully');

      try {
        const { folder, tags, public: isPublic, password, expiresAt, maxDownloads, bundleName, title, message, recipients } = req.body;
        const files = req.files as Express.Multer.File[];
        let parsedRecipients = [];
        if (recipients) {
          try {
            parsedRecipients = typeof recipients === 'string' ? JSON.parse(recipients) : recipients;
          } catch (e) {
            parsedRecipients = [];
          }
        }

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
        const fileIds = [];
        for (const file of files) {
          try {
            // Generate file hash
            const hash = await generateFileHash(file.path);

            // Check for duplicate file
          // Check for duplicate file
const existingFile = await File.findOne({ hash, owner: req.user!._id });
if (existingFile) {
  cleanupUploadedFiles(req.file);

  // Optionally update metadata (like folder, tags) if user provides them again
  if (folder) existingFile.folder = folder;
  if (tags) existingFile.tags = JSON.parse(tags);
  if (typeof isPublic !== 'undefined') existingFile.permissions.public = isPublic === 'true' || isPublic === true;
  if (password) existingFile.permissions.password = password;
  if (expiresAt) existingFile.permissions.expiresAt = new Date(expiresAt);
  if (maxDownloads) existingFile.permissions.maxDownloads = parseInt(maxDownloads);

  await existingFile.save();

  await existingFile.populate('owner', 'username email');
  if (existingFile.folder) {
    await existingFile.populate('folder', 'name path');
  }

  return res.status(200).json({
    success: true,
    message: 'File already exists, reused previous file',
    data: { file: existingFile }
  });
}


            // Encrypt the file on disk
            const { iv } = await encryptFileOnDisk(file.path);
            console.log('Saved file with IV:', iv, 'for file:', file.filename);

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
              title: title || '',
              message: message || '',
              recipients: parsedRecipients,
              permissions: {
                public: isPublic === 'true' || isPublic === true,
                password: password || undefined,
                expiresAt: expiresAt ? new Date(expiresAt) : undefined,
                maxDownloads: maxDownloads ? parseInt(maxDownloads) : undefined,
                downloadCount: 0
              },
              metadata: {
                ...file.metadata,
                iv
              }
            });

            await fileDoc.save();
            await fileDoc.populate('owner', 'username email');
            if (fileDoc.folder) {
              await fileDoc.populate('folder', 'name path');
            }

            uploadedFiles.push(fileDoc);
            fileIds.push(fileDoc._id);

          } catch (error) {
            cleanupUploadedFiles([file]);
            errors.push({
              filename: file.originalname,
              error: error instanceof Error ? error.message : 'Upload failed'
            });
          }
        }
        // If bundleName is provided, create a Collection
        let collection = null;
        if (bundleName && fileIds.length > 0) {
          collection = new Collection({
            name: bundleName,
            owner: req.user!._id,
            files: fileIds,
            title: title || '',
            message: message || '',
            recipients: parsedRecipients
          });
          await collection.save();
        }
        res.status(201).json({
          success: true,
          message: `Uploaded ${uploadedFiles.length} files successfully`,
          data: {
            files: uploadedFiles,
            errors: errors.length > 0 ? errors : undefined,
            collectionId: collection ? collection._id : undefined
          }
        });

      } catch (error) {
        cleanupUploadedFiles(files);
        throw error;
      }
    });
  })
);

// @route   POST /api/upload/folder
// @desc    Upload a complete folder (multiple files with relative paths)
// @access  Private
router.post('/folder',
  authenticate,
  checkStorageLimit,
  asyncHandler(async (req: AuthRequest, res) => {
    // Use uploadMultiple middleware to handle multiple files
    uploadMultiple(req, res, async (err: Error | null) => {
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
      const files = req.files as Express.Multer.File[];
      const uploadedFiles = [];
      const createdFolders = new Set<string>();
      const folderCache: Record<string, any> = {};
      for (const file of files) {
        // The frontend should send the relative path for each file as part of the form data
        // e.g., req.body['relativePath_0'] = 'myfolder/subfolder/file.txt'
        //       req.body['relativePath_1'] = 'myfolder/file2.txt'
        // The index matches the file order in req.files
        const idx = files.indexOf(file);
        const relativePath = req.body[`relativePath_${idx}`];
        if (!relativePath) {
          cleanupUploadedFiles(file);
          continue;
        }
        // Parse folder structure from relativePath
        const pathParts = relativePath.split('/');
        const fileName = pathParts.pop();
        let parentFolderId = null;
        let currentPath = '';
        for (const part of pathParts) {
          currentPath = currentPath ? `${currentPath}/${part}` : part;
          if (!folderCache[currentPath]) {
            // Check if folder exists for this user and path
            let folderDoc = await Folder.findOne({ name: part, owner: req.user!._id, parent: parentFolderId });
            if (!folderDoc) {
              // Create folder if it doesn't exist
              folderDoc = new Folder({
                name: part,
                owner: req.user!._id,
                parent: parentFolderId
              });
              await folderDoc.save();
              createdFolders.add(currentPath);
            }
            folderCache[currentPath] = folderDoc._id;
          }
          parentFolderId = folderCache[currentPath];
        }
        // Generate file hash
        const hash = await generateFileHash(file.path);
        // Check for duplicate file in this folder for this user
        const existingFile = await File.findOne({ hash, owner: req.user!._id, folder: parentFolderId });
        if (existingFile) {
          cleanupUploadedFiles(file);
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
          folder: parentFolderId
        });
        await fileDoc.save();
        uploadedFiles.push(fileDoc);
      }
      res.status(201).json({
        success: true,
        message: `Uploaded ${uploadedFiles.length} files and created ${createdFolders.size} folders successfully`,
        data: {
          files: uploadedFiles,
          folders: Array.from(createdFolders)
        }
      });
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
    const tempDir = path.join(process.env.UPLOAD_DIR || './uploads', 'temp', fileId);
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
      const finalPath = path.join(process.env.UPLOAD_DIR || './uploads', req.user!._id.toString(), fileName);
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
      fs.rmSync(tempDir, { recursive: true, force: true });

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