# OAuth2 Client Demo

A complete React.js application demonstrating OAuth2 integration with an authorization server, including automatic token refresh and protected API calls.

## Features

- 🔐 **OAuth2 Authorization Code Flow** - Complete implementation of the OAuth2 authorization code grant
- 🔄 **Automatic Token Refresh** - Seamlessly refresh expired access tokens
- 🛡️ **Protected API Calls** - Make authenticated requests with Bearer token authentication
- 💾 **Secure Token Storage** - Store tokens securely in localStorage
- 🚪 **Secure Logout** - Complete logout with token cleanup
- 📱 **Responsive Design** - Works on desktop and mobile devices

## Prerequisites

Before running this application, make sure you have:

1. **OAuth2 Server Running** - Your OAuth2 server should be running on `http://localhost:8080`
2. **Node.js** - Install Node.js (version 16 or higher)
3. **npm** - Node package manager

## Installation

1. **Install Dependencies**
   ```bash
   cd oauth2-client
   npm install
   ```

2. **Configure OAuth2 Server URL**
   Edit `src/services/oauth2Service.ts` if your OAuth2 server runs on a different URL:
   ```typescript
   private readonly OAUTH2_SERVER_URL = 'http://localhost:8080'; // Change if needed
   ```

3. **Start the Application**
   ```bash
   npm start
   ```

4. **Open Browser**
   Navigate to `http://localhost:3000`

## Usage

### 1. Login Process

1. **Click "Login with OAuth2 Server"** on the home page
2. **You'll be redirected** to your OAuth2 server's login page
3. **Enter credentials**:
   - Username: `admin`, Password: `admin` (Admin user)
   - Username: `testuser`, Password: `password` (Regular user)
4. **Grant permissions** if prompted
5. **You'll be redirected back** to the client application
6. **Authorization code is exchanged** for access and refresh tokens automatically

### 2. Dashboard Features

Once logged in, you can:

- **View User Information** - See your username and roles
- **Check Token Details** - View token expiration and scopes
- **Call Protected APIs** - Test authenticated API calls
- **Refresh Tokens** - Manually refresh access tokens
- **Logout** - Securely logout and clear all tokens

## OAuth2 Configuration

The client is configured to work with your OAuth2 server:

```typescript
// OAuth2 Server Configuration
private readonly OAUTH2_SERVER_URL = 'http://localhost:8080';
private readonly CLIENT_ID = 'client1';
private readonly CLIENT_SECRET = 'secret';
private readonly REDIRECT_URI = window.location.origin + '/callback';
```

### Available Endpoints

- **Authorization**: `GET /oauth2/authorize`
- **Token Exchange**: `POST /oauth2/token`
- **Token Refresh**: `POST /oauth2/token` (with `grant_type=refresh_token`)
- **Token Introspection**: `POST /oauth2/introspect`

## API Integration

### Making Authenticated API Calls

```typescript
import { oauth2Service } from './services/oauth2Service';

// Make authenticated API call
const response = await oauth2Service.authenticatedFetch('/api/protected-endpoint');

// The service automatically:
// 1. Adds Bearer token to Authorization header
// 2. Refreshes token if expired
// 3. Handles 401 responses by refreshing token
// 4. Retries the request with new token
```

### Token Management

```typescript
// Check if user is authenticated
const isAuthenticated = oauth2Service.isAuthenticated();

// Get current access token
const token = oauth2Service.getAccessToken();

// Get user information from token
const userInfo = oauth2Service.getUserInfo();

// Manually refresh token
await oauth2Service.refreshAccessToken();

// Logout
oauth2Service.logout();
```

## Security Features

- **Automatic Token Refresh** - Tokens are refreshed before expiration
- **Secure Storage** - Tokens stored in localStorage with expiration tracking
- **CSRF Protection** - Built-in CSRF protection for forms
- **Secure Logout** - Complete cleanup of tokens and session data
- **Error Handling** - Comprehensive error handling for authentication failures

## Project Structure

```
oauth2-client/
├── src/
│   ├── components/
│   │   ├── LoginPage.tsx          # Login page component
│   │   ├── CallbackPage.tsx       # OAuth2 callback handler
│   │   ├── Dashboard.tsx          # Protected dashboard
│   │   └── ProtectedRoute.tsx     # Route protection component
│   ├── services/
│   │   └── oauth2Service.ts       # OAuth2 service with token management
│   ├── App.tsx                    # Main application component
│   ├── App.css                    # Application styles
│   ├── index.tsx                  # Application entry point
│   └── index.css                  # Global styles
├── public/
│   └── index.html                 # HTML template
├── package.json                   # Dependencies and scripts
└── README.md                      # This file
```

## Troubleshooting

### Common Issues

1. **"Failed to connect to localhost:8080"**
   - Make sure your OAuth2 server is running
   - Check if the server URL in `oauth2Service.ts` is correct

2. **"Authentication failed"**
   - Verify OAuth2 server is properly configured
   - Check client credentials match server configuration
   - Ensure LDAP users are set up correctly

3. **"Token refresh failed"**
   - Check if refresh token is still valid
   - Verify OAuth2 server refresh endpoint is working
   - Clear localStorage and re-authenticate

4. **CORS Issues**
   - Ensure OAuth2 server allows requests from `http://localhost:3000`
   - Check server CORS configuration

### Debug Mode

Enable debug logging by opening browser console (F12) to see:
- Token refresh attempts
- API call details
- Authentication flow steps
- Error messages

## Development

### Adding New Features

1. **New Protected Routes**
   ```tsx
   <Route
     path="/new-protected-route"
     element={
       <ProtectedRoute isAuthenticated={isAuthenticated}>
         <NewComponent />
       </ProtectedRoute>
     }
   />
   ```

2. **New API Calls**
   ```typescript
   const response = await oauth2Service.authenticatedFetch('/api/new-endpoint');
   const data = await response.json();
   ```

3. **Custom Token Handling**
   ```typescript
   // Add custom logic in oauth2Service.ts
   async customAuthenticatedCall(url: string, options: RequestInit = {}) {
     // Custom authentication logic
     return this.authenticatedFetch(url, options);
   }
   ```

## License

This project is for demonstration purposes. Feel free to modify and use in your applications.

## Support

If you encounter issues:

1. Check the browser console for error messages
2. Verify your OAuth2 server configuration
3. Ensure all dependencies are installed
4. Check network tab for API call details

For OAuth2 server issues, refer to your server documentation and logs.
