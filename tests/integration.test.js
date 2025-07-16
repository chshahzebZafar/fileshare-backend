const axios = require('axios');
const mongoose = require('mongoose');

// Configuration
const BASE_URL = 'http://localhost:3001';
const API_BASE = `${BASE_URL}/api`;

// Test data
let testUser = null;
let testToken = null;
let testFolder = null;
let testFile = null;

// Helper functions
const log = (message, data = null) => {
  console.log(`\n${message}`);
  if (data) console.log(JSON.stringify(data, null, 2));
};

const makeRequest = async (method, endpoint, data = null, token = null) => {
  try {
    const config = {
      method,
      url: `${API_BASE}${endpoint}`,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` })
      },
      ...(data && { data })
    };
    
    const response = await axios(config);
    return { success: true, data: response.data, status: response.status };
  } catch (error) {
    let errorMessage = error.message;
    
    if (error.response?.data) {
      if (typeof error.response.data === 'object') {
        errorMessage = JSON.stringify(error.response.data);
      } else {
        errorMessage = error.response.data;
      }
    }
    
    return { 
      success: false, 
      error: errorMessage,
      status: error.response?.status 
    };
  }
};

// Test suite
async function runIntegrationTests() {
  console.log('🚀 Starting Integration Tests...\n');
  
  try {
    // Test 1: Health Check
    log('🏥 Testing Health Check...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    if (healthResponse.status === 200) {
      log('✅ Health Check passed', healthResponse.data);
    } else {
      throw new Error('Health check failed');
    }

    // Test 2: User Registration
    log('👤 Testing User Registration...');
    const registerData = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'Password123'
    };
    
    const registerResult = await makeRequest('POST', '/auth/register', registerData);
    if (registerResult.success) {
      log('✅ User registration successful', registerResult.data);
      testUser = registerResult.data.data.user;
    } else {
      // If user already exists, try login
      log('⚠️ User might already exist, trying login...');
      const loginResult = await makeRequest('POST', '/auth/login', {
        email: registerData.email,
        password: registerData.password
      });
      
      if (loginResult.success) {
        log('✅ User login successful', loginResult.data);
        testUser = loginResult.data.data.user;
        testToken = loginResult.data.data.token;
      } else {
        throw new Error(`Registration/Login failed: ${registerResult.error}`);
      }
    }

    // Test 3: User Login (if not already logged in)
    if (!testToken) {
      log('🔐 Testing User Login...');
      const loginResult = await makeRequest('POST', '/auth/login', {
        email: 'test@example.com',
        password: 'Password123'
      });
      
      if (loginResult.success) {
        log('✅ User login successful', loginResult.data);
        testToken = loginResult.data.data.token;
      } else {
        throw new Error(`Login failed: ${loginResult.error}`);
      }
    }

    // Test 4: Create Root Folder
    log('📁 Testing Root Folder Creation...');
    const folderData = {
      name: 'Test Root Folder',
      description: 'A test root folder for integration testing',
      tags: ['test', 'integration']
    };
    
    const folderResult = await makeRequest('POST', '/folders', folderData, testToken);
    if (folderResult.success) {
      log('✅ Root folder created successfully', folderResult.data);
      testFolder = folderResult.data.data.folder;
    } else {
      throw new Error(`Folder creation failed: ${folderResult.error}`);
    }

    // Test 5: Create Subfolder
    log('📂 Testing Subfolder Creation...');
    const subfolderData = {
      name: 'Test Subfolder',
      description: 'A test subfolder',
      parent: testFolder._id,
      tags: ['test', 'subfolder']
    };
    
    const subfolderResult = await makeRequest('POST', '/folders', subfolderData, testToken);
    if (subfolderResult.success) {
      log('✅ Subfolder created successfully', subfolderResult.data);
    } else {
      throw new Error(`Subfolder creation failed: ${subfolderResult.error}`);
    }

    // Test 6: Get User Folders
    log('📋 Testing Get User Folders...');
    const getFoldersResult = await makeRequest('GET', '/folders', null, testToken);
    if (getFoldersResult.success) {
      log('✅ User folders retrieved successfully', getFoldersResult.data);
    } else {
      throw new Error(`Get folders failed: ${getFoldersResult.error}`);
    }

    // Test 7: Get Specific Folder
    log('📁 Testing Get Specific Folder...');
    const getFolderResult = await makeRequest('GET', `/folders/${testFolder._id}`, null, testToken);
    if (getFolderResult.success) {
      log('✅ Specific folder retrieved successfully', getFolderResult.data);
    } else {
      throw new Error(`Get specific folder failed: ${getFolderResult.error}`);
    }

    // Test 8: Update Folder
    log('✏️ Testing Folder Update...');
    const updateData = {
      name: 'Updated Test Folder',
      description: 'This folder has been updated'
    };
    
    const updateResult = await makeRequest('PUT', `/folders/${testFolder._id}`, updateData, testToken);
    if (updateResult.success) {
      log('✅ Folder updated successfully', updateResult.data);
    } else {
      throw new Error(`Folder update failed: ${updateResult.error}`);
    }

    // Test 9: Get User Profile
    log('👤 Testing Get User Profile...');
    const profileResult = await makeRequest('GET', '/user/profile', null, testToken);
    if (profileResult.success) {
      log('✅ User profile retrieved successfully', profileResult.data);
    } else {
      throw new Error(`Get profile failed: ${profileResult.error}`);
    }

    // Test 10: Update User Profile
    log('✏️ Testing User Profile Update...');
    const profileUpdateData = {
      username: 'updatedtestuser',
      bio: 'This is an updated bio for testing'
    };
    
    const profileUpdateResult = await makeRequest('PUT', '/user/profile', profileUpdateData, testToken);
    if (profileUpdateResult.success) {
      log('✅ User profile updated successfully', profileUpdateResult.data);
    } else {
      throw new Error(`Profile update failed: ${profileUpdateResult.error}`);
    }

    // Test 11: Test Authentication Middleware (Protected Route)
    log('🔒 Testing Protected Route Access...');
    const protectedResult = await makeRequest('GET', '/user/profile');
    if (!protectedResult.success && protectedResult.status === 401) {
      log('✅ Protected route correctly requires authentication');
    } else {
      throw new Error('Protected route should require authentication');
    }

    // Test 12: Test Invalid Token
    log('🚫 Testing Invalid Token...');
    const invalidTokenResult = await makeRequest('GET', '/user/profile', null, 'invalid-token');
    if (!invalidTokenResult.success && invalidTokenResult.status === 401) {
      log('✅ Invalid token correctly rejected');
    } else {
      throw new Error('Invalid token should be rejected');
    }

    console.log('\n🎉 All Integration Tests Passed Successfully!');
    console.log('\n📊 Test Summary:');
    console.log('✅ Health Check');
    console.log('✅ User Registration/Login');
    console.log('✅ Root Folder Creation');
    console.log('✅ Subfolder Creation');
    console.log('✅ Get User Folders');
    console.log('✅ Get Specific Folder');
    console.log('✅ Update Folder');
    console.log('✅ Get User Profile');
    console.log('✅ Update User Profile');
    console.log('✅ Protected Route Authentication');
    console.log('✅ Invalid Token Rejection');

  } catch (error) {
    console.error('\n❌ Test Suite Failed:', error.message);
    console.error('Error details:', error);
    process.exit(1);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runIntegrationTests();
}

module.exports = { runIntegrationTests, makeRequest }; 