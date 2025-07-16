const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const API_BASE = `${BASE_URL}/api`;

async function debugAuth() {
  console.log('🔍 Debugging Authentication Endpoints...\n');
  
  try {
    // Test 1: Check if server is running
    console.log('1. Checking server health...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✅ Server is running:', healthResponse.data);
    
    // Test 2: Try registration
    console.log('\n2. Testing user registration...');
    const registerData = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'Password123'
    };
    
    try {
      const registerResponse = await axios.post(`${API_BASE}/auth/register`, registerData, {
        headers: { 'Content-Type': 'application/json' }
      });
      console.log('✅ Registration successful:', registerResponse.data);
    } catch (registerError) {
      console.log('❌ Registration failed:');
      console.log('Status:', registerError.response?.status);
      console.log('Data:', JSON.stringify(registerError.response?.data, null, 2));
      console.log('Message:', registerError.message);
      
      // Test 3: Try login if registration failed
      console.log('\n3. Testing user login...');
      try {
        const loginResponse = await axios.post(`${API_BASE}/auth/login`, {
          email: 'test@example.com',
          password: 'Password123'
        }, {
          headers: { 'Content-Type': 'application/json' }
        });
        console.log('✅ Login successful:', loginResponse.data);
      } catch (loginError) {
        console.log('❌ Login failed:');
        console.log('Status:', loginError.response?.status);
        console.log('Data:', JSON.stringify(loginError.response?.data, null, 2));
        console.log('Message:', loginError.message);
      }
    }
    
  } catch (error) {
    console.error('❌ Debug failed:', error.message);
    if (error.code === 'ECONNREFUSED') {
      console.log('💡 Make sure the server is running with: npm run dev');
    }
  }
}

debugAuth(); 