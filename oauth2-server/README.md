# Spring Boot OAuth2 Server with LDAP Integration

A comprehensive OAuth2 authorization server built with Spring Boot that supports both human-to-machine (H2M) and machine-to-machine (M2M) authentication modes, with JWT tokens containing role and group information. **Now includes a login API for username/password verification against LDAP.**

## Features

- **OAuth2 Authorization Server**: Full OAuth2 implementation with JWT tokens
- **Multiple Grant Types**: Supports Authorization Code, Client Credentials, and Refresh Token flows
- **Role-Based Access Control**: JWT tokens include user roles and groups from LDAP
- **H2M and M2M Support**: Both user authentication and client credentials flows
- **LDAP Integration**: User authentication and role/group management via LDAP
- **JWT Customization**: Custom JWT claims including roles, groups, and authorities
- **REST API**: Endpoints for user management and resource access
- **Login API**: Username/password authentication against LDAP
- **Swagger UI**: Interactive API documentation and testing interface

## Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- LDAP server (OpenLDAP, Apache DS, or Active Directory)

## Quick Start

### 1. Build the Project

```bash
mvn clean install
```

### 2. LDAP Setup

1. Set up an LDAP server (e.g., OpenLDAP, Apache DS, or Active Directory)
2. Import the sample LDIF file: `ldap-sample.ldif`
3. Update the LDAP configuration in `application.yml` with your server details

### 3. Run the Application

```bash
mvn spring-boot:run
```

The server will start on `http://localhost:8080`

## Login API

### Endpoint
```
POST /api/auth/login
```

### Request Body
```json
{
  "username": "admin",
  "password": "password"
}
```

### Response (Success)
```json
{
  "success": true,
  "message": "Authentication successful",
  "username": "admin",
  "authorities": [
    "ROLE_ADMIN",
    "GROUP_ADMIN"
  ],
  "commonName": "Administrator",
  "surname": "Admin",
  "givenName": "Admin",
  "email": "admin@example.com",
  "groups": ["ADMIN"],
  "roles": ["ADMIN"]
}
```

### Response (Failure)
```json
{
  "success": false,
  "message": "Authentication failed: Invalid credentials"
}
```

## OAuth2 Endpoints

### Authorization Endpoint
```
GET /oauth2/authorize
```

### Token Endpoint
```
POST /oauth2/token
```

### User Info Endpoint
```
GET /oauth2/userinfo
```

### JWK Set Endpoint
```
GET /oauth2/jwks
```

### OpenID Connect Discovery
```
GET /.well-known/openid_configuration
```

## Pre-configured Clients

### Client 1 (Authorization Code + Refresh Token)
- **Client ID**: `client1`
- **Client Secret**: `secret1`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Redirect URI**: `http://localhost:3000/callback`
- **Scopes**: `openid`, `profile`, `read`, `write`, `user`

### Client 2 (Client Credentials)
- **Client ID**: `client2`
- **Client Secret**: `secret2`
- **Grant Types**: `client_credentials`
- **Scopes**: `read`, `write`, `api`

## LDAP Users (from sample LDIF)

### Admin User
- **Username**: `admin`
- **Password**: `password` (SHA hash: W6ph5Mm5Pz8GgiULbPgzG37mj9g=)
- **Groups**: `ADMIN`

### Regular Users
- **Username**: `user1` / **Password**: `password` / **Groups**: `DEVELOPERS`
- **Username**: `user2` / **Password**: `password` / **Groups**: `TESTERS`
- **Username**: `manager1` / **Password**: `password` / **Groups**: `DEVELOPERS`, `MANAGERS`

## Swagger UI

The application includes Swagger UI for interactive API documentation and testing:

- **Swagger UI**: `http://localhost:8080/swagger-ui.html`
- **API Documentation**: `http://localhost:8080/api-docs`
- **OpenAPI JSON**: `http://localhost:8080/v3/api-docs`

### Using Swagger UI with OAuth2

1. **For H2M Testing**: Use the authorization code flow to get a JWT token, then use it in Swagger UI
2. **For M2M Testing**: Use the client credentials flow to get a JWT token, then use it in Swagger UI

## API Endpoints

### Public Endpoints
- **GET** `/api/public/info` - Public information (no auth required)

### Authentication Endpoints
- **POST** `/api/auth/login` - User login with username/password
- **POST** `/api/auth/register` - User registration (not supported via LDAP)
- **GET** `/api/auth/user/{username}` - Get user information from LDAP
- **GET** `/api/auth/groups` - Get all LDAP groups

### Protected Endpoints
- **GET** `/api/user/profile` - User profile (requires USER role)
- **GET** `/api/admin/users` - Admin users (requires ADMIN role)
- **GET** `/api/admin/roles` - Admin roles (requires ADMIN role)
- **GET** `/api/client/info` - Client information (requires client credentials)

## Testing the Login API

### 1. Test with Valid Credentials
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'
```

### 2. Test with Invalid Credentials
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "wrongpassword"
  }'
```

### 3. Test with Non-existent User
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent",
    "password": "password"
  }'
```

## JWT Token Claims

### H2M Token Claims
```json
{
  "username": "admin",
  "authorities": ["ROLE_ADMIN", "GROUP_ADMIN"],
  "roles": ["ADMIN"],
  "groups": ["ADMIN"],
  "grant_type": "authorization_code"
}
```

### M2M Token Claims
```json
{
  "client_id": "client2",
  "grant_type": "client_credentials",
  "scopes": ["read", "write", "api"]
}
```

## Configuration

### LDAP Configuration (`application.yml`)
```yaml
spring:
  ldap:
    urls: ldap://localhost:389
    base: dc=example,dc=com
    username: cn=admin,dc=example,dc=com
    password: admin
```

### JWT Configuration
```yaml
jwt:
  secret: your-256-bit-secret-key-here-make-it-long-and-secure
  expiration: 86400000 # 24 hours in milliseconds
```

## Security Features

- **Password Verification**: Username/password verification against LDAP
- **Role-Based Access Control**: Access control based on LDAP groups
- **JWT Token Security**: Secure JWT tokens with custom claims
- **CORS Support**: Cross-origin resource sharing enabled
- **Input Validation**: Request validation using Bean Validation

## Development

### Project Structure
```
src/main/java/com/example/oauth2server/
├── OAuth2ServerApplication.java          # Main Spring Boot application
├── config/
│   ├── AuthorizationServerConfig.java    # OAuth2 authorization server config
│   ├── LdapConfig.java                  # LDAP connection configuration
│   ├── SecurityConfig.java              # Spring Security configuration
│   └── SwaggerConfig.java               # Swagger UI configuration
├── controller/
│   ├── AuthController.java              # Authentication endpoints (including login)
│   └── ResourceController.java          # Protected resource endpoints
├── dto/
│   └── LoginRequest.java                # Login request DTO
├── security/
│   └── LdapUserDetailsService.java      # LDAP user authentication service
└── service/
    ├── AuthenticationService.java        # Login authentication logic
    └── LdapUserService.java             # LDAP user operations service
```

### Key Components

1. **AuthenticationService**: Handles username/password verification against LDAP
2. **LoginRequest DTO**: Validates login request data
3. **LdapUserDetailsService**: Integrates with Spring Security for LDAP authentication
4. **SecurityConfig**: Configures security rules and allows access to login endpoint

## Troubleshooting

### Common Issues

1. **LDAP Connection Failed**
   - Verify LDAP server is running
   - Check LDAP connection details in `application.yml`
   - Ensure LDAP server is accessible from the application

2. **Login Authentication Failed**
   - Verify user exists in LDAP
   - Check password hash format in LDAP
   - Ensure user is in the correct organizational unit

3. **Swagger UI Not Loading**
   - Ensure application is running on port 8080
   - Check if `/swagger-ui/**` endpoints are accessible

### Debug Information
- Enable debug logging in `application.yml`
- Check LDAP server logs for connection issues
- Verify user and group structure in LDAP

## Security Notes

- **Never share JWT tokens** in production environments
- **Use HTTPS** in production for all endpoints
- **Implement proper token validation** on client applications
- **Regularly rotate client secrets** for production use
- **Secure LDAP connection** in production environments

## Next Steps

1. **Test the login API** with various credentials
2. **Verify LDAP integration** with your directory server
3. **Test OAuth2 flows** using Swagger UI
4. **Customize JWT claims** as needed for your use case
5. **Implement client applications** using the OAuth2 flows
6. **Add additional security measures** for production deployment

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review LDAP server logs
3. Enable debug logging in the application
4. Verify LDAP data structure matches the sample LDIF



