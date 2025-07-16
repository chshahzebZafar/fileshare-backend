# Authentication Setup Guide

## Prerequisites

1. **MongoDB** - Make sure MongoDB is running locally or you have a MongoDB Atlas connection string
2. **Node.js** - Version 16 or higher
3. **Environment Variables** - Create a `.env` file in the backend directory

## Step 1: Environment Setup

Create a `.env` file in the `backend/` directory with the following content:

```env
# Server Configuration
PORT=3001
NODE_ENV=development

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/ransfer-inspired

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=30d

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Application Configuration
APP_URL=http://localhost:3000
API_URL=http://localhost:3001/api
FRONTEND_URL=http://192.168.8.8:8080
```

## Step 2: Install Dependencies

```bash
cd backend
npm install
```

## Step 3: Start the Backend Server

```bash
npm run dev
```

The server should start on `http://localhost:3001`

## Step 4: Test the Authentication System

Run the test script to verify everything is working:

```bash
node test-registration.js
```

## Step 5: Frontend Configuration

Make sure your frontend is configured to connect to the backend:

1. The API service is already configured to use `http://localhost:3001/api`
2. CORS is configured to allow your frontend origin
3. Password validation now matches backend requirements

## Common Issues and Solutions

### 1. MongoDB Connection Error
- **Error**: "MongoDB connection error"
- **Solution**: 
  - Make sure MongoDB is running locally: `mongod`
  - Or use MongoDB Atlas and update the connection string

### 2. JWT Secret Missing
- **Error**: "JWT_SECRET is not defined"
- **Solution**: Add JWT_SECRET to your .env file

### 3. Password Validation Failed
- **Error**: "Password must contain at least one lowercase letter, one uppercase letter, and one number"
- **Solution**: Use a password that meets all requirements (e.g., "TestPass123")

### 4. CORS Error
- **Error**: "Not allowed by CORS"
- **Solution**: 
  - Check that your frontend URL is in the allowed origins
  - Update the CORS configuration in `backend/src/index.ts`

### 5. Server Not Starting
- **Error**: "Port already in use"
- **Solution**: 
  - Change the PORT in .env file
  - Or kill the process using the port: `lsof -ti:3001 | xargs kill -9`

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user (requires auth)
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/verify-email` - Verify email with token
- `POST /api/auth/resend-verification` - Resend verification email

### Request/Response Format

**Registration Request:**
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "TestPass123",
  "firstName": "Test",
  "lastName": "User"
}
```

**Registration Response:**
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email to verify your account.",
  "data": {
    "user": {
      "_id": "...",
      "email": "test@example.com",
      "username": "testuser",
      "firstName": "Test",
      "lastName": "User",
      "isEmailVerified": false,
      "subscription": {
        "plan": "free",
        "status": "active",
        "features": ["basic_upload", "basic_download"]
      },
      "storage": {
        "used": 0,
        "limit": 1073741824
      }
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

## Security Features

1. **Password Hashing** - Passwords are hashed using bcrypt with 12 rounds
2. **JWT Tokens** - Secure authentication tokens with configurable expiration
3. **Input Validation** - Comprehensive validation using express-validator
4. **Rate Limiting** - API rate limiting to prevent abuse
5. **CORS Protection** - Configured CORS to allow only trusted origins
6. **Helmet Security** - Security headers for protection against common vulnerabilities

## Testing

Use the provided test script to verify the authentication system:

```bash
node test-registration.js
```

This will test:
- Server connectivity
- User registration
- User login
- Duplicate registration prevention
- Error handling 