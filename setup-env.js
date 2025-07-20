const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

console.log('🔧 Setting up environment variables for S3 integration...\n');

// Check if .env file exists
const envPath = path.join(__dirname, '.env');
const envExists = fs.existsSync(envPath);

if (envExists) {
  console.log('📁 .env file already exists');
  const envContent = fs.readFileSync(envPath, 'utf8');
  
  // Check for required S3 variables
  const hasS3Config = envContent.includes('AWS_ACCESS_KEY_ID') && 
                     envContent.includes('AWS_SECRET_ACCESS_KEY') && 
                     envContent.includes('AWS_S3_BUCKET_NAME');
  
  if (hasS3Config) {
    console.log('✅ S3 configuration found in .env file');
  } else {
    console.log('⚠️  S3 configuration missing from .env file');
    console.log('Please add the following variables to your .env file:');
    console.log('');
    console.log('# AWS S3 Configuration');
    console.log('AWS_REGION=us-east-1');
    console.log('AWS_ACCESS_KEY_ID=your-aws-access-key-id');
    console.log('AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key');
    console.log('AWS_S3_BUCKET_NAME=your-s3-bucket-name');
    console.log('');
    console.log('# File Encryption Key (32 bytes = 64 hex characters)');
    console.log('FILE_ENCRYPTION_KEY=' + crypto.randomBytes(32).toString('hex'));
  }
} else {
  console.log('📁 Creating new .env file...');
  
  const envTemplate = `# Server Configuration
PORT=3000
NODE_ENV=development
BACKEND_URL=http://localhost:3000

# Database
MONGODB_URI=mongodb://localhost:27017/ransfer

# JWT
JWT_SECRET=${crypto.randomBytes(32).toString('hex')}
JWT_EXPIRE=7d

# File Upload Configuration
MAX_FILE_SIZE=104857600
MAX_FILES=10
ALLOWED_FILE_TYPES=image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,video/ogg,audio/mpeg,audio/wav,audio/ogg,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,text/plain,text/html,text/css,text/javascript,application/json,application/xml,application/zip,application/x-rar-compressed,application/x-7z-compressed

# File Encryption
FILE_ENCRYPTION_KEY=${crypto.randomBytes(32).toString('hex')}

# AWS S3 Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
AWS_S3_BUCKET_NAME=your-s3-bucket-name
AWS_KMS_KEY_ID=your-kms-key-id-optional

# Email Configuration (Nodemailer)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_FROM=your-email@gmail.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS
CORS_ORIGIN=http://localhost:3000,http://localhost:3001
`;

  fs.writeFileSync(envPath, envTemplate);
  console.log('✅ .env file created successfully!');
  console.log('');
  console.log('📝 Next steps:');
  console.log('1. Edit the .env file and add your AWS credentials');
  console.log('2. Create an S3 bucket in AWS');
  console.log('3. Run: npm run build');
  console.log('4. Run: node test-s3.js');
}

console.log('');
console.log('🔗 AWS S3 Setup Guide:');
console.log('1. Go to AWS Console → S3 → Create bucket');
console.log('2. Go to AWS Console → IAM → Users → Create user');
console.log('3. Attach S3 permissions to the user');
console.log('4. Copy Access Key ID and Secret Access Key to .env file');
console.log('5. Update AWS_S3_BUCKET_NAME with your bucket name');
console.log('');
console.log('📖 For detailed instructions, see: setup-s3.md'); 