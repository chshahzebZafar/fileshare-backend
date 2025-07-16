import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { Request } from 'express';

// Ensure upload directory exists
const uploadDir = process.env.UPLOAD_PATH || './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Create user-specific directory
    const userId = (req as any).user?._id || 'anonymous';
    const userDir = path.join(uploadDir, userId);
    
    if (!fs.existsSync(userDir)) {
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
    cb(null, `${sanitizedName}_${uniqueSuffix}${ext}`);
  }
});

// File filter function
const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
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

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} is not allowed`));
  }
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
  return (req: Request, res: any, next: any) => {
    const uploadMiddleware = maxCount > 1 
      ? upload.array(fieldName, maxCount)
      : upload.single(fieldName);

    uploadMiddleware(req, res, (err: any) => {
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