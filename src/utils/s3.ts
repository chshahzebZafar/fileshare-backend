import dotenv from 'dotenv';
dotenv.config();
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import crypto from 'crypto';
import { Readable } from 'stream';

// S3 Client Configuration
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME!;
const ENCRYPTION_KEY = process.env.FILE_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// Debug logging
console.log('🔍 S3 Configuration:');
console.log('  Bucket:', BUCKET_NAME);
console.log('  Region:', process.env.AWS_REGION);
console.log('  Access Key:', process.env.AWS_ACCESS_KEY_ID ? 'Set' : 'Not Set');
console.log('  Secret Key:', process.env.AWS_SECRET_ACCESS_KEY ? 'Set' : 'Not Set');
const ALGORITHM = 'aes-256-cbc';

export interface S3FileMetadata {
  originalName: string;
  mimeType: string;
  size: number;
  iv: string;
  hash: string;
  encrypted: boolean;
}

export interface UploadResult {
  key: string;
  metadata: S3FileMetadata;
  url?: string;
}

export class S3Service {
  /**
   * Upload file to S3 with encryption
   */
  static async uploadFile(
    fileBuffer: Buffer,
    originalName: string,
    mimeType: string,
    userId: string,
    folder?: string
  ): Promise<UploadResult> {
    try {
      
      // Generate unique file key
      const fileId = crypto.randomBytes(16).toString('hex');
      const extension = originalName.split('.').pop() || '';
      const sanitizedName = originalName.replace(/[^a-zA-Z0-9.-]/g, '_');
      const key = folder 
        ? `users/${userId}/${folder}/${sanitizedName}_${fileId}.${extension}`
        : `users/${userId}/${sanitizedName}_${fileId}.${extension}`;

      // Generate file hash
      const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      // Encrypt file
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
      const encryptedBuffer = Buffer.concat([
        cipher.update(fileBuffer),
        cipher.final()
      ]);

      // Prepare metadata
      const metadata: S3FileMetadata = {
        originalName,
        mimeType,
        size: fileBuffer.length,
        iv: iv.toString('hex'),
        hash,
        encrypted: true
      };

      // Upload to S3
      const uploadCommand = new PutObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
        Body: encryptedBuffer,
        Metadata: {
          originalName: encodeURIComponent(originalName),
          mimeType,
          size: fileBuffer.length.toString(),
          iv: iv.toString('hex'),
          hash,
          encrypted: 'true',
          uploadedAt: new Date().toISOString()
        },
        ContentType: 'application/octet-stream', // Encrypted content
        ServerSideEncryption: 'AES256', // S3 server-side encryption
        SSEKMSKeyId: process.env.AWS_KMS_KEY_ID, // Optional: Use KMS for additional encryption
      });

      await s3Client.send(uploadCommand);

      return {
        key,
        metadata
      };
    } catch (error) {
      console.error('S3 upload error:', error);
      throw new Error(`Failed to upload file to S3: ${error}`);
    }
  }

  /**
   * Download and decrypt file from S3
   */
  static async downloadFile(key: string): Promise<{ buffer: Buffer; metadata: S3FileMetadata }> {
    try {
      
      const getCommand = new GetObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      const response = await s3Client.send(getCommand);
      
      if (!response.Body) {
        throw new Error('No file content received from S3');
      }

      // Get metadata
      const metadata: S3FileMetadata = {
        originalName: decodeURIComponent(response.Metadata?.originalName || ''),
        mimeType: response.Metadata?.mimeType || '',
        size: parseInt(response.Metadata?.size || '0'),
        iv: response.Metadata?.iv || '',
        hash: response.Metadata?.hash || '',
        encrypted: response.Metadata?.encrypted === 'true'
      };

      // Convert stream to buffer
      const chunks: Buffer[] = [];
      const stream = response.Body as Readable;
      
      for await (const chunk of stream) {
        chunks.push(Buffer.from(chunk));
      }
      
      const encryptedBuffer = Buffer.concat(chunks);

      // Decrypt file
      if (metadata.encrypted) {
        const decipher = crypto.createDecipheriv(
          ALGORITHM, 
          Buffer.from(ENCRYPTION_KEY, 'hex'), 
          Buffer.from(metadata.iv, 'hex')
        );
        
        const decryptedBuffer = Buffer.concat([
          decipher.update(encryptedBuffer),
          decipher.final()
        ]);

        return { buffer: decryptedBuffer, metadata };
      }

      return { buffer: encryptedBuffer, metadata };
    } catch (error) {
      console.error('S3 download error:', error);
      throw new Error(`Failed to download file from S3: ${error}`);
    }
  }

  /**
   * Generate presigned URL for direct download
   */
  static async generatePresignedUrl(key: string, expiresIn: number = 3600): Promise<string> {
    try {
      const command = new GetObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      const url = await getSignedUrl(s3Client, command, { expiresIn });
      return url;
    } catch (error) {
      console.error('S3 presigned URL error:', error);
      throw new Error(`Failed to generate presigned URL: ${error}`);
    }
  }

  /**
   * Generate presigned URL for upload (for direct browser uploads)
   */
  static async generatePresignedUploadUrl(
    key: string,
    contentType: string,
    expiresIn: number = 3600
  ): Promise<string> {
    try {
      const command = new PutObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
        ContentType: contentType,
        ServerSideEncryption: 'AES256',
      });

      const url = await getSignedUrl(s3Client, command, { expiresIn });
      return url;
    } catch (error) {
      console.error('S3 presigned upload URL error:', error);
      throw new Error(`Failed to generate presigned upload URL: ${error}`);
    }
  }

  /**
   * Delete file from S3
   */
  static async deleteFile(key: string): Promise<void> {
    try {
      const deleteCommand = new DeleteObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      await s3Client.send(deleteCommand);
    } catch (error) {
      console.error('S3 delete error:', error);
      throw new Error(`Failed to delete file from S3: ${error}`);
    }
  }

  /**
   * Check if file exists in S3
   */
  static async fileExists(key: string): Promise<boolean> {
    try {
      const headCommand = new HeadObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      await s3Client.send(headCommand);
      return true;
    } catch (error: any) {
      if (error.name === 'NotFound') {
        return false;
      }
      throw error;
    }
  }

  /**
   * Get file metadata from S3
   */
  static async getFileMetadata(key: string): Promise<S3FileMetadata | null> {
    try {
      const headCommand = new HeadObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      const response = await s3Client.send(headCommand);
      
      if (!response.Metadata) {
        return null;
      }

      return {
        originalName: decodeURIComponent(response.Metadata.originalName || ''),
        mimeType: response.Metadata.mimeType || '',
        size: parseInt(response.Metadata.size || '0'),
        iv: response.Metadata.iv || '',
        hash: response.Metadata.hash || '',
        encrypted: response.Metadata.encrypted === 'true'
      };
    } catch (error: any) {
      if (error.name === 'NotFound') {
        return null;
      }
      console.error('S3 get metadata error:', error);
      throw new Error(`Failed to get file metadata from S3: ${error}`);
    }
  }

  /**
   * List files for a user
   */
  static async listUserFiles(userId: string, prefix?: string): Promise<string[]> {
    try {
      const { ListObjectsV2Command } = await import('@aws-sdk/client-s3');
      
      const listCommand = new ListObjectsV2Command({
        Bucket: BUCKET_NAME,
        Prefix: prefix || `users/${userId}/`,
        MaxKeys: 1000,
      });

      const response = await s3Client.send(listCommand);
      
      return response.Contents?.map(obj => obj.Key!).filter(Boolean) || [];
    } catch (error) {
      console.error('S3 list files error:', error);
      throw new Error(`Failed to list files from S3: ${error}`);
    }
  }
}

// Utility functions for encryption/decryption
export const encryptBuffer = (buffer: Buffer): { encryptedBuffer: Buffer; iv: string } => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(buffer),
    cipher.final()
  ]);
  return { encryptedBuffer, iv: iv.toString('hex') };
};

export const decryptBuffer = (encryptedBuffer: Buffer, iv: string): Buffer => {
  const decipher = crypto.createDecipheriv(
    ALGORITHM, 
    Buffer.from(ENCRYPTION_KEY, 'hex'), 
    Buffer.from(iv, 'hex')
  );
  return Buffer.concat([
    decipher.update(encryptedBuffer),
    decipher.final()
  ]);
};

export default S3Service; 