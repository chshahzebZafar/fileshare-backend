// Check and fix environment variables
const fs = require('fs');
const path = require('path');

console.log('🔍 Checking Environment Variables');
console.log('================================\n');

// Required environment variables for S3
const requiredEnvVars = {
  'AWS_REGION': 'us-east-1',
  'AWS_ACCESS_KEY_ID': 'AKIA2TCTNYDWLRID2SN4',
  'AWS_SECRET_ACCESS_KEY': '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',
  'AWS_S3_BUCKET_NAME': 'fileshare2025',
  'FILE_ENCRYPTION_KEY': '244ae90a17c3536b28d4a42734cefc673aaa00be68d2b3069a3aff4557e1e3bb'
};

// Check if .env file exists
const envPath = path.join(__dirname, '.env');
let envContent = '';

if (fs.existsSync(envPath)) {
  envContent = fs.readFileSync(envPath, 'utf8');
  console.log('✅ .env file found');
} else {
  console.log('❌ .env file not found, creating new one');
}

// Check each required variable
console.log('\n📋 Environment Variables Status:');
let needsUpdate = false;

Object.entries(requiredEnvVars).forEach(([key, value]) => {
  const regex = new RegExp(`^${key}=.*`, 'm');
  const match = envContent.match(regex);
  
  if (match) {
    console.log(`  ✅ ${key}: Set`);
  } else {
    console.log(`  ❌ ${key}: Missing`);
    needsUpdate = true;
  }
});

// Update .env file if needed
if (needsUpdate) {
  console.log('\n🔧 Updating .env file...');
  
  // Add missing variables
  Object.entries(requiredEnvVars).forEach(([key, value]) => {
    const regex = new RegExp(`^${key}=.*`, 'm');
    if (!envContent.match(regex)) {
      envContent += `\n${key}=${value}`;
      console.log(`  ➕ Added: ${key}=${value}`);
    }
  });
  
  // Write updated .env file
  fs.writeFileSync(envPath, envContent.trim() + '\n');
  console.log('✅ .env file updated successfully');
} else {
  console.log('\n✅ All environment variables are properly configured');
}

// Test environment variables
console.log('\n🧪 Testing Environment Variables:');
require('dotenv').config();

Object.entries(requiredEnvVars).forEach(([key, expectedValue]) => {
  const actualValue = process.env[key];
  if (actualValue) {
    console.log(`  ✅ ${key}: ${actualValue.substring(0, 20)}${actualValue.length > 20 ? '...' : ''}`);
  } else {
    console.log(`  ❌ ${key}: Not set`);
  }
});

console.log('\n🎉 Environment check complete!');
console.log('📋 Next steps:');
console.log('  1. Restart your server: npm run dev');
console.log('  2. Run the upload test: node test-app-upload-download.js'); 