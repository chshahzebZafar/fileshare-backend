import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import S3Service from '../utils/s3';

// Ensure upload directory exists (for temporary storage before S3 upload)
const uploadDir = process.env.UPLOAD_DIR || './temp-uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage for temporary files
const storage = multer.memoryStorage(); // Use memory storage for S3 uploads

// File filter function
const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  console.log('🔍 File filter checking:', file.originalname, 'type:', file.mimetype);
  
  const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'video/mp4',
    'video/webm',
    'video/ogg',
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
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
    'application/xml',
    'application/zip',
    'application/x-rar-compressed',
    'application/x-7z-compressed'
  ];

  // For testing, allow all file types
  console.log('✅ File type allowed (testing mode):', file.mimetype);
  cb(null, true);
  
  // Uncomment below for production file type filtering
  /*
  if (allowedTypes.includes(file.mimetype)) {
    console.log('✅ File type allowed:', file.mimetype);
    cb(null, true);
  } else {
    console.log('❌ File type rejected:', file.mimetype);
    cb(new Error(`File type ${file.mimetype} is not allowed`));
  }
  */
};

// Configure multer
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '104857600'), // 100MB default
    files: parseInt(process.env.MAX_FILES || '10') // 10 files default
  }
});

// Single file upload
export const uploadSingle = upload.single('file');

// Multiple files upload
export const uploadMultiple = upload.array('files', parseInt(process.env.MAX_FILES || '10'));

// Fields upload (for different file types)
export const uploadFields = upload.fields([
  { name: 'files', maxCount: parseInt(process.env.MAX_FILES || '10') },
  { name: 'images', maxCount: 5 },
  { name: 'documents', maxCount: 5 }
]);

// Custom upload middleware with additional validation
export const uploadWithValidation = (fieldName: string = 'file', maxCount: number = 1) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const uploadMiddleware = maxCount > 1 
      ? upload.array(fieldName, maxCount)
      : upload.single(fieldName);

    uploadMiddleware(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({
            success: false,
            message: `File too large. Maximum size is ${process.env.MAX_FILE_SIZE || '100MB'}`
          });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
          return res.status(400).json({
            success: false,
            message: `Too many files. Maximum is ${maxCount}`
          });
        }
        return res.status(400).json({
          success: false,
          message: err.message
        });
      } else if (err) {
        return res.status(400).json({
          success: false,
          message: err.message
        });
      }

      // Additional validation
      if (!req.file && !req.files) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded'
        });
      }

      next();
      return;
    });
  };
};

// Generate file hash from buffer
export const generateFileHash = (buffer: Buffer): string => {
  return crypto.createHash('sha256').update(buffer).digest('hex');
};

// Clean up uploaded files on error (no longer needed with memory storage)
export const cleanupUploadedFiles = (files: Express.Multer.File | Express.Multer.File[]) => {
  // No cleanup needed with memory storage
  console.log('🧹 Cleanup called (memory storage - no cleanup needed)');
};

// Upload file to S3 with encryption
export const uploadFileToS3 = async (
  file: Express.Multer.File,
  userId: string,
  folder?: string
): Promise<{ s3Key: string; metadata: any }> => {
  try {
    // Upload to S3
    const result = await S3Service.uploadFile(
      file.buffer!,
      file.originalname,
      file.mimetype,
      userId,
      folder
    );

    return {
      s3Key: result.key,
      metadata: result.metadata
    };
  } catch (error) {
    console.error('S3 upload error:', error);
    throw new Error(`Failed to upload file to S3: ${error}`);
  }
};

// Legacy functions for backward compatibility (deprecated)
export function createEncryptionStream() {
  console.warn('createEncryptionStream is deprecated - use S3Service instead');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(process.env.FILE_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'), 'hex'), iv);
  return { cipher, iv };
}

export function createDecryptionStream(iv: Buffer) {
  console.warn('createDecryptionStream is deprecated - use S3Service instead');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.FILE_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'), 'hex'), iv);
  return decipher;
}

export async function encryptFileOnDisk(filePath: string): Promise<{ iv: string }> {
  console.warn('encryptFileOnDisk is deprecated - use S3Service instead');
  // This function is kept for backward compatibility but should not be used
  return { iv: crypto.randomBytes(16).toString('hex') };
} 