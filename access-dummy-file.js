// Access the uploaded dummy file from S3
const { S3Client, GetObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const crypto = require('crypto');

const AWS_CONFIG = {
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'AKIA2TCTNYDWLRID2SN4',
    secretAccessKey: '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'
  }
};

const BUCKET_NAME = 'fileshare2025';
const ENCRYPTION_KEY = '244ae90a17c3536b28d4a42734cefc673aaa00be68d2b3069a3aff4557e1e3bb';

const s3Client = new S3Client(AWS_CONFIG);

function decryptBuffer(encryptedBuffer, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(iv, 'hex'));
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

async function listFiles() {
  console.log('📋 Listing files in S3 bucket...\n');
  
  try {
    const listCommand = new ListObjectsV2Command({
      Bucket: BUCKET_NAME,
      Prefix: 'test-files/'
    });

    const response = await s3Client.send(listCommand);
    
    if (response.Contents && response.Contents.length > 0) {
      console.log('📁 Found files:');
      response.Contents.forEach((file, index) => {
        console.log(`  ${index + 1}. ${file.Key} (${file.Size} bytes, Last modified: ${file.LastModified})`);
      });
      console.log('');
      return response.Contents;
    } else {
      console.log('❌ No files found in test-files/ directory');
      return [];
    }
  } catch (error) {
    console.error('❌ Error listing files:', error.message);
    return [];
  }
}

async function accessDummyFile(s3Key = 'test-files/dummy-test-file.json') {
  console.log(`🔍 Accessing file: ${s3Key}\n`);
  
  try {
    // Get file metadata first
    console.log('📊 Getting file metadata...');
    const getCommand = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key
    });

    const response = await s3Client.send(getCommand);
    
    console.log('✅ File metadata retrieved:');
    console.log(`  📁 Key: ${s3Key}`);
    console.log(`  📏 Size: ${response.ContentLength} bytes`);
    console.log(`  📅 Last Modified: ${response.LastModified}`);
    console.log(`  🔐 Server-side encryption: ${response.ServerSideEncryption}`);
    console.log('');

    // Get file content
    console.log('📥 Downloading file content...');
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    const encryptedBuffer = Buffer.concat(chunks);

    console.log(`✅ Downloaded ${encryptedBuffer.length} bytes of encrypted data`);
    console.log('');

    // Decrypt the file
    console.log('🔓 Decrypting file...');
    const iv = response.Metadata?.iv;
    if (!iv) {
      throw new Error('No IV found in metadata');
    }
    
    const decryptedBuffer = decryptBuffer(encryptedBuffer, iv);
    const content = decryptedBuffer.toString('utf8');
    const data = JSON.parse(content);

    console.log('✅ File decrypted successfully!');
    console.log('');

    // Display content
    console.log('📄 File content:');
    console.log(JSON.stringify(data, null, 2));
    console.log('');

    // Display metadata
    console.log('📊 File metadata:');
    Object.entries(response.Metadata || {}).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });
    console.log('');

    // Verify file integrity
    console.log('🔍 File integrity check:');
    console.log(`  Original size (from metadata): ${response.Metadata?.size} bytes`);
    console.log(`  Decrypted size: ${decryptedBuffer.length} bytes`);
    console.log(`  Content type: ${response.Metadata?.mimeType}`);
    console.log(`  Encryption status: ${response.Metadata?.encrypted}`);
    console.log('');

    return {
      data,
      metadata: response.Metadata,
      size: decryptedBuffer.length,
      encryptedSize: encryptedBuffer.length
    };
    
  } catch (error) {
    console.error('❌ Error accessing file:', error.message);
    throw error;
  }
}

async function testMultipleFiles() {
  console.log('🚀 Testing access to multiple files...\n');
  
  try {
    // List all files first
    const files = await listFiles();
    
    if (files.length === 0) {
      console.log('❌ No files found to test');
      return;
    }

    // Test access to each file
    for (const file of files) {
      console.log(`\n${'='.repeat(50)}`);
      console.log(`Testing file: ${file.Key}`);
      console.log(`${'='.repeat(50)}`);
      
      try {
        const result = await accessDummyFile(file.Key);
        console.log(`✅ Successfully accessed: ${file.Key}`);
        console.log(`   Size: ${result.size} bytes`);
        console.log(`   Type: ${result.metadata?.mimeType || 'Unknown'}`);
      } catch (error) {
        console.log(`❌ Failed to access: ${file.Key}`);
        console.log(`   Error: ${error.message}`);
      }
    }

  } catch (error) {
    console.error('❌ Error in test:', error.message);
  }
}

// Main execution
async function main() {
  console.log('🎯 S3 File Access Test');
  console.log('=====================\n');

  try {
    // First, list all files
    await listFiles();
    
    // Then access the specific dummy file
    console.log('\n' + '='.repeat(50));
    console.log('ACCESSING SPECIFIC DUMMY FILE');
    console.log('='.repeat(50));
    await accessDummyFile();
    
    // Optionally test multiple files
    console.log('\n' + '='.repeat(50));
    console.log('TESTING ALL FILES');
    console.log('='.repeat(50));
    await testMultipleFiles();
    
    console.log('\n🎉 File access test completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  }
}

// Run the test
main();
