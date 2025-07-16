# Ransfer Backend API

A comprehensive file sharing and management backend built with Node.js, Express, TypeScript, and MongoDB.

## 🚀 Features

- **Authentication & Authorization**: JWT-based auth with user registration/login
- **File Management**: Upload, download, organize files with folders
- **Folder System**: Hierarchical folder structure with nested organization
- **File Sharing**: Generate shareable links with permissions
- **User Management**: Profile management and user settings
- **Security**: Rate limiting, input validation, CORS protection
- **Real-time**: WebSocket support for live updates
- **Analytics**: File usage and storage analytics

## 📋 Prerequisites

- Node.js >= 16.0.0
- MongoDB >= 4.4
- npm or yarn

## 🛠️ Installation

1. **Clone and navigate to backend directory**
   ```bash
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   NODE_ENV=development
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/ransfer-inspired
   JWT_SECRET=your-super-secret-jwt-key
   JWT_EXPIRE=7d
   FRONTEND_URL=http://localhost:5173
   ```

4. **Start MongoDB**
   ```bash
   # Make sure MongoDB is running on your system
   mongod
   ```

## 🏃‍♂️ Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm run build
npm start
```

## 🧪 Testing

### Run All Tests
```bash
npm test
```

### Run Integration Tests Only
```bash
npm run test:integration
```

### Manual API Testing
```bash
npm run test:api
```

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

### Folder Endpoints

#### Create Folder
```http
POST /api/folders
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "My Documents",
  "description": "Important documents folder",
  "parent": "optional_parent_folder_id",
  "tags": ["work", "important"]
}
```

#### Get User Folders
```http
GET /api/folders
Authorization: Bearer <token>
```

#### Get Specific Folder
```http
GET /api/folders/:folderId
Authorization: Bearer <token>
```

#### Update Folder
```http
PUT /api/folders/:folderId
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Updated Folder Name",
  "description": "Updated description"
}
```

### File Endpoints

#### Upload File
```http
POST /api/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <file>
folder: <optional_folder_id>
```

#### Download File
```http
GET /api/download/:fileId
Authorization: Bearer <token>
```

#### Get User Files
```http
GET /api/files
Authorization: Bearer <token>
```

### User Endpoints

#### Get Profile
```http
GET /api/user/profile
Authorization: Bearer <token>
```

#### Update Profile
```http
PUT /api/user/profile
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "new_username",
  "bio": "Updated bio"
}
```

### Sharing Endpoints

#### Create Share Link
```http
POST /api/share
Authorization: Bearer <token>
Content-Type: application/json

{
  "fileId": "file_id",
  "expiresAt": "2024-12-31T23:59:59Z",
  "password": "optional_password"
}
```

## 🏗️ Project Structure

```
backend/
├── src/
│   ├── models/          # Mongoose models
│   ├── routes/          # API route handlers
│   ├── middleware/      # Custom middleware
│   ├── types/           # TypeScript type definitions
│   ├── utils/           # Utility functions
│   └── index.ts         # Main application entry
├── tests/
│   └── integration.test.js  # Integration tests
├── uploads/             # File upload directory
├── package.json
├── tsconfig.json
└── README.md
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `5000` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/ransfer-inspired` |
| `JWT_SECRET` | JWT signing secret | Required |
| `JWT_EXPIRE` | JWT expiration time | `7d` |
| `FRONTEND_URL` | Frontend URL for CORS | `http://localhost:5173` |

### Database Models

- **User**: User accounts and profiles
- **File**: File metadata and storage info
- **Folder**: Folder hierarchy and organization
- **Share**: File sharing links and permissions

## 🚀 Deployment

### Docker Deployment
```bash
# Build image
docker build -t ransfer-backend .

# Run container
docker run -p 5000:5000 ransfer-backend
```

### Environment Setup
1. Set production environment variables
2. Configure MongoDB connection
3. Set up reverse proxy (nginx)
4. Configure SSL certificates

## 🔒 Security Features

- **JWT Authentication**: Secure token-based auth
- **Rate Limiting**: Prevent abuse with request limits
- **Input Validation**: Sanitize and validate all inputs
- **CORS Protection**: Configured for frontend access
- **Helmet Security**: HTTP security headers
- **Password Hashing**: bcrypt for password security

## 📊 Monitoring

### Health Check
```http
GET /health
```

Response:
```json
{
  "status": "OK",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 3600
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For issues and questions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with details

---

**Built with ❤️ for secure file sharing** 