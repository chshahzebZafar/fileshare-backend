// Debug S3 connectivity
const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');

const AWS_CONFIG = {
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'AKIA2TCTNYDWLRID2SN4',
    secretAccessKey: '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'
  }
};

const s3Client = new S3Client(AWS_CONFIG);

async function debugS3() {
  console.log('🔍 Debugging S3 connectivity...\n');
  
  try {
    // Test 1: List all buckets (basic connectivity test)
    console.log('📋 Test 1: Listing all buckets...');
    const listCommand = new ListBucketsCommand({});
    const result = await s3Client.send(listCommand);
    
    console.log('✅ Successfully connected to AWS S3!');
    console.log('📁 Available buckets:');
    result.Buckets?.forEach(bucket => {
      console.log(`  - ${bucket.Name} (created: ${bucket.CreationDate})`);
    });
    console.log('');

    // Test 2: Check if our specific bucket exists
    const targetBucket = 'fileshare2025';
    console.log(`🔍 Test 2: Checking if bucket '${targetBucket}' exists...`);
    
    const bucketExists = result.Buckets?.some(bucket => bucket.Name === targetBucket);
    if (bucketExists) {
      console.log(`✅ Bucket '${targetBucket}' found!`);
    } else {
      console.log(`❌ Bucket '${targetBucket}' not found in your account`);
      console.log('');
      console.log('🔧 Possible solutions:');
      console.log('1. Create the bucket in AWS S3 Console');
      console.log('2. Check if the bucket name is correct');
      console.log('3. Verify you have access to the bucket');
    }
    console.log('');

    // Test 3: Check IAM permissions
    console.log('🔐 Test 3: Checking IAM permissions...');
    try {
      const { HeadBucketCommand } = require('@aws-sdk/client-s3');
      const headCommand = new HeadBucketCommand({ Bucket: targetBucket });
      await s3Client.send(headCommand);
      console.log(`✅ You have access to bucket '${targetBucket}'`);
    } catch (error) {
      console.log(`❌ Access denied to bucket '${targetBucket}': ${error.message}`);
      console.log('');
      console.log('🔧 IAM Policy needed:');
      console.log(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::${targetBucket}",
        "arn:aws:s3:::${targetBucket}/*"
      ]
    }
  ]
}`);
    }

  } catch (error) {
    console.error('❌ S3 connection failed:', error.message);
    console.error('');
    console.error('🔧 Common issues:');
    console.error('1. Invalid AWS credentials');
    console.error('2. Network connectivity issues');
    console.error('3. AWS region mismatch');
    console.error('4. IAM user lacks S3 permissions');
  }
}

debugS3(); 