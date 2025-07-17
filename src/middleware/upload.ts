import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from '../types';

// Ensure upload directory exists
const uploadDir = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Create user-specific directory
    const authReq = req as AuthRequest;
    const userId = authReq.user?._id?.toString() || 'anonymous';
    const userDir = path.join(uploadDir, userId);
    
    console.log('📁 Multer destination:', userDir);
    console.log('📁 User ID:', userId);
    
    if (!fs.existsSync(userDir)) {
      console.log('📁 Creating user directory:', userDir);
      fs.mkdirSync(userDir, { recursive: true });
    }
    
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    
    // Sanitize filename
    const sanitizedName = name.replace(/[^a-zA-Z0-9.-]/g, '_');
    const finalFilename = `${sanitizedName}_${uniqueSuffix}${ext}`;
    
    console.log('📁 Original filename:', file.originalname);
    console.log('📁 Generated filename:', finalFilename);
    
    cb(null, finalFilename);
  }
});

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
    });
  };
};

// AES-256 encryption utilities
const ENCRYPTION_KEY = process.env.FILE_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'); // 32 bytes for AES-256
const ALGORITHM = 'aes-256-cbc';

export function createEncryptionStream() {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  return { cipher, iv };
}

export function createDecryptionStream(iv: Buffer) {
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  return decipher;
}

// Exported async function for file encryption
export async function encryptFileOnDisk(filePath: string): Promise<{ iv: string }> {
  const tempPath = filePath + '.enc';
  const { cipher, iv } = createEncryptionStream();
  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath);
    const output = fs.createWriteStream(tempPath);
    input.pipe(cipher).pipe(output);
    output.on('finish', () => {
      fs.unlinkSync(filePath);
      fs.renameSync(tempPath, filePath);
      resolve({ iv: iv.toString('hex') });
    });
    output.on('error', reject);
  });
}

// Generate file hash
export const generateFileHash = (filePath: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', (data) => {
      hash.update(data);
    });
    
    stream.on('end', () => {
      resolve(hash.digest('hex'));
    });
    
    stream.on('error', (error) => {
      reject(error);
    });
  });
};

// Clean up uploaded files on error
export const cleanupUploadedFiles = (files: Express.Multer.File | Express.Multer.File[]) => {
  const fileArray = Array.isArray(files) ? files : [files];
  
  fileArray.forEach(file => {
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }
  });
}; 