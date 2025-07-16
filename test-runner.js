#!/usr/bin/env node

const { runIntegrationTests } = require('./tests/integration.test');

console.log('🧪 Backend Integration Test Runner');
console.log('=====================================\n');

// Check if server is running
const checkServer = async () => {
  try {
    const axios = require('axios');
    await axios.get('http://localhost:3001/health');
    return true;
  } catch (error) {
    return false;
  }
};

const main = async () => {
  console.log('🔍 Checking if server is running...');
  
  const serverRunning = await checkServer();
  if (!serverRunning) {
    console.log('❌ Server is not running on http://localhost:3001');
    console.log('💡 Please start the server first with: npm run dev');
    process.exit(1);
  }
  
  console.log('✅ Server is running, starting tests...\n');
  
  try {
    await runIntegrationTests();
    console.log('\n🎉 All tests completed successfully!');
  } catch (error) {
    console.error('\n❌ Tests failed:', error.message);
    process.exit(1);
  }
};

main(); 