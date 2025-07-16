const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmailService() {
  console.log('🔍 Testing Email Configuration...');
  
  // Check environment variables
  console.log('📧 Email Service:', process.env.EMAIL_SERVICE);
  console.log('👤 Email User:', process.env.EMAIL_USER);
  console.log('🔑 Email Pass:', process.env.EMAIL_PASS ? '***SET***' : 'NOT SET');
  console.log('🌐 Frontend URL:', process.env.FRONTEND_URL);
  
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('❌ Email configuration is missing!');
    return;
  }

  try {
    // Create transporter
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    console.log('✅ Transporter created successfully');

    // Test email
    const testEmail = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER, // Send to yourself for testing
      subject: 'Test Email from Ransfer Backend',
      html: `
        <h2>Test Email</h2>
        <p>This is a test email to verify that the email service is working correctly.</p>
        <p>Time: ${new Date().toISOString()}</p>
      `,
      text: 'This is a test email to verify that the email service is working correctly.'
    };

    console.log('📤 Sending test email...');
    const result = await transporter.sendMail(testEmail);
    
    console.log('✅ Test email sent successfully!');
    console.log('📧 Message ID:', result.messageId);
    console.log('📬 Check your email inbox (and spam folder)');
    
  } catch (error) {
    console.error('❌ Email test failed:', error.message);
    
    if (error.code === 'EAUTH') {
      console.error('🔐 Authentication failed. Check your email and password.');
      console.error('💡 For Gmail, make sure you\'re using an App Password, not your regular password.');
    } else if (error.code === 'ECONNECTION') {
      console.error('🌐 Connection failed. Check your internet connection.');
    }
  }
}

testEmailService(); 