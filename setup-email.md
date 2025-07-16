# Email Setup Guide for Ransfer Backend

This guide will help you configure email functionality for user registration, email verification, and password reset features.

## Prerequisites

- Node.js and npm installed
- A Gmail account (or other email provider)
- Environment variables configured

## Email Configuration

### 1. Gmail Setup (Recommended)

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate an App Password**:
   - Go to Google Account settings
   - Navigate to Security → 2-Step Verification → App passwords
   - Generate a new app password for "Mail"
   - Copy the 16-character password

### 2. Environment Variables

Create a `.env` file in the root directory with the following email configuration:

```env
# Email Configuration
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-16-character-app-password
FRONTEND_URL=http://localhost:3000
```

### 3. Alternative Email Providers

You can use other email providers by changing the `EMAIL_SERVICE`:

#### Outlook/Hotmail
```env
EMAIL_SERVICE=outlook
EMAIL_USER=your-email@outlook.com
EMAIL_PASS=your-password
```

#### Custom SMTP Server
```env
EMAIL_SERVICE=smtp
EMAIL_HOST=smtp.your-provider.com
EMAIL_PORT=587
EMAIL_USER=your-email@your-domain.com
EMAIL_PASS=your-password
```

## Testing Email Functionality

### 1. Build the Project
```bash
npm run build
```

### 2. Test Email Service
```bash
npm run test:email
```

This will test both verification and password reset emails.

### 3. Manual Testing

You can also test the email functionality through the API endpoints:

#### Register a new user
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "TestPass123",
    "firstName": "Test",
    "lastName": "User"
  }'
```

#### Request password reset
```bash
curl -X POST http://localhost:3001/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'
```

## Email Templates

The email service includes three types of emails:

### 1. Email Verification
- **Trigger**: User registration
- **Purpose**: Verify user's email address
- **Template**: Professional welcome email with verification button
- **Expiration**: 24 hours

### 2. Password Reset
- **Trigger**: User requests password reset
- **Purpose**: Allow user to reset their password
- **Template**: Security-focused email with reset button
- **Expiration**: 10 minutes

### 3. File Share Notification
- **Trigger**: User shares a file with someone
- **Purpose**: Notify recipient about shared file
- **Template**: File information with download link

## Troubleshooting

### Common Issues

1. **"Invalid login" error**
   - Make sure you're using an App Password, not your regular Gmail password
   - Verify 2-Factor Authentication is enabled

2. **"Connection timeout" error**
   - Check your internet connection
   - Verify the email service configuration

3. **"Authentication failed" error**
   - Double-check your email and password
   - Ensure the app password is correctly copied

4. **Emails not being sent**
   - Check the console logs for error messages
   - Verify all environment variables are set correctly
   - Test with the email test script

### Debug Mode

To see detailed email logs, you can modify the email service to log more information:

```typescript
// In src/utils/email.ts
console.log('Email configuration:', {
  service: process.env.EMAIL_SERVICE,
  user: process.env.EMAIL_USER,
  frontendUrl: process.env.FRONTEND_URL
});
```

## Security Considerations

1. **Never commit your `.env` file** to version control
2. **Use App Passwords** instead of regular passwords for Gmail
3. **Rotate passwords** regularly
4. **Monitor email sending** for unusual activity
5. **Rate limit** email endpoints to prevent abuse

## Production Deployment

For production deployment:

1. **Use environment-specific email providers** (SendGrid, Mailgun, etc.)
2. **Set up email monitoring** and analytics
3. **Configure proper DNS records** (SPF, DKIM, DMARC)
4. **Implement email queue** for high-volume sending
5. **Set up email templates** with your branding

## API Endpoints

The following endpoints now support email functionality:

- `POST /api/auth/register` - Sends verification email
- `POST /api/auth/forgot-password` - Sends password reset email
- `POST /api/auth/resend-verification` - Resends verification email
- `POST /api/auth/verify-email` - Verifies email with token
- `POST /api/auth/reset-password` - Resets password with token

All email operations are handled gracefully - if email sending fails, the user registration/request will still succeed, but the email won't be sent. 