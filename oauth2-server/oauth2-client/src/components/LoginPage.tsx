import React from 'react';
import { oauth2Service } from '../services/oauth2Service';
import './LoginPage.css';

interface LoginPageProps {
  onLoginSuccess: () => void;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const handleOAuth2Login = () => {
    oauth2Service.initiateLogin();
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>Welcome to OAuth2 Client Demo</h2>
        <p>This demo shows how to integrate with an OAuth2 server using the Authorization Code flow.</p>

        <div className="login-section">
          <h3>OAuth2 Login</h3>
          <p>Click the button below to start the OAuth2 authorization flow:</p>
          <button
            onClick={handleOAuth2Login}
            className="oauth2-login-btn"
          >
            Login with OAuth2 Server
          </button>
        </div>

        <div className="info-section">
          <h4>How it works:</h4>
          <ol>
            <li>Click "Login with OAuth2 Server"</li>
            <li>You'll be redirected to the OAuth2 server's login page</li>
            <li>Enter your credentials (admin/admin or testuser/password)</li>
            <li>Grant permission for the requested scopes</li>
            <li>You'll be redirected back with an authorization code</li>
            <li>The code will be exchanged for access and refresh tokens</li>
            <li>You're now logged in and can access protected resources!</li>
          </ol>
        </div>

        <div className="test-credentials">
          <h4>Test Credentials:</h4>
          <ul>
            <li><strong>Username:</strong> admin, <strong>Password:</strong> admin</li>
            <li><strong>Username:</strong> testuser, <strong>Password:</strong> password</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;