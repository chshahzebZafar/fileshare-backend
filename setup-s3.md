# AWS S3 Setup Guide for Ransfer

This guide will help you set up AWS S3 with encryption for your file storage SaaS application.

## Prerequisites

1. AWS Account
2. AWS CLI installed (optional but recommended)
3. Node.js project with the required dependencies

## Step 1: Create S3 Bucket

1. Go to AWS S3 Console
2. Click "Create bucket"
3. Choose a unique bucket name (e.g., `ransfer-files-2024`)
4. Select your preferred region
5. **Important**: Enable encryption settings:
   - Check "Enable server-side encryption"
   - Choose "Amazon S3 managed keys (SSE-S3)" or "AWS KMS managed keys (SSE-KMS)"
6. Block all public access (recommended for security)
7. Create the bucket

## Step 2: Create IAM User

1. Go to AWS IAM Console
2. Create a new user with programmatic access
3. Attach the following policy (or create a custom one):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:GetObjectVersion",
                "s3:PutObjectAcl"
            ],
            "Resource": [
                "arn:aws:s3:::YOUR-BUCKET-NAME",
                "arn:aws:s3:::YOUR-BUCKET-NAME/*"
            ]
        }
    ]
}
```

4. Save the Access Key ID and Secret Access Key

## Step 3: Environment Variables

Add these variables to your `.env` file:

```env
# AWS S3 Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_S3_BUCKET_NAME=your-bucket-name

# Optional: KMS Key for additional encryption
AWS_KMS_KEY_ID=your-kms-key-id

# File Encryption Key (32 bytes = 64 hex characters)
FILE_ENCRYPTION_KEY=your-32-byte-encryption-key-here
```

## Step 4: Generate Encryption Key

Generate a secure 32-byte encryption key:

```bash
# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Or using OpenSSL
openssl rand -hex 32
```

## Step 5: Optional - AWS KMS Setup

For additional security, you can use AWS KMS:

1. Go to AWS KMS Console
2. Create a new symmetric key
3. Add the key ID to your environment variables
4. Update the IAM policy to include KMS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:region:account:key/key-id"
        }
    ]
}
```

## Step 6: Test the Setup

Run your application and test file upload/download:

```bash
npm run dev
```

## Security Features Implemented

### 1. **Client-Side Encryption**
- Files are encrypted with AES-256-CBC before upload
- Each file has a unique IV (Initialization Vector)
- Encryption key is stored securely in environment variables

### 2. **Server-Side Encryption**
- S3 bucket has server-side encryption enabled
- Optional KMS integration for key management
- Files are stored as encrypted blobs

### 3. **Access Control**
- Files are organized by user ID in S3
- IAM policies restrict access to your bucket only
- No public access to files

### 4. **File Integrity**
- SHA-256 hashes prevent duplicate uploads
- File metadata is stored separately
- Download counts and permissions are tracked

## File Structure in S3

```
your-bucket/
├── users/
│   ├── user-id-1/
│   │   ├── file1_abc123.pdf
│   │   ├── file2_def456.jpg
│   │   └── folder1/
│   │       └── file3_ghi789.docx
│   └── user-id-2/
│       └── ...
```

## API Endpoints

The following endpoints now use S3:

- `POST /api/upload/single` - Upload single file to S3
- `POST /api/upload/multiple` - Upload multiple files to S3
- `GET /api/download/:fileId` - Download and decrypt file from S3
- `DELETE /api/files/:fileId` - Delete file from S3

## Monitoring and Logs

Check AWS CloudWatch for:
- S3 access logs
- Error logs
- Performance metrics

## Cost Optimization

1. **Lifecycle Policies**: Set up automatic deletion of old files
2. **Storage Classes**: Use S3-IA for infrequently accessed files
3. **Compression**: Consider compressing files before encryption
4. **CDN**: Use CloudFront for faster downloads

## Troubleshooting

### Common Issues:

1. **Access Denied**: Check IAM permissions
2. **Bucket Not Found**: Verify bucket name and region
3. **Encryption Errors**: Ensure encryption key is 32 bytes
4. **File Not Found**: Check S3 key generation logic

### Debug Commands:

```bash
# Test S3 connection
aws s3 ls s3://your-bucket-name

# Check file in S3
aws s3 ls s3://your-bucket-name/users/user-id/

# Test upload
aws s3 cp test.txt s3://your-bucket-name/test.txt
```

## Migration from Local Storage

If you have existing files in local storage:

1. Create a migration script to upload existing files to S3
2. Update file records in database to use S3 keys
3. Verify all files are accessible
4. Remove local files after verification

## Backup Strategy

1. **Database**: Regular MongoDB backups
2. **S3**: Enable versioning for file recovery
3. **Cross-Region**: Replicate to another region
4. **Encryption Keys**: Store securely (consider AWS Secrets Manager)

## Performance Tips

1. **Presigned URLs**: Use for direct browser uploads
2. **Streaming**: Implement streaming for large files
3. **Caching**: Cache frequently accessed files
4. **Compression**: Compress files before encryption

## Compliance

This setup provides:
- **GDPR**: Data encryption and user control
- **HIPAA**: Encryption at rest and in transit
- **SOC2**: Access controls and audit trails
- **ISO27001**: Information security management 