import React, { useState, useEffect } from 'react';
import { oauth2Service } from '../services/oauth2Service';
import './Dashboard.css';

interface ApiResponse {
  message: string;
  timestamp: string;
  user: string;
}

const Dashboard: React.FC = () => {
  const [userInfo, setUserInfo] = useState<any>(null);
  const [apiResponse, setApiResponse] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const user = oauth2Service.getUserInfo();
    setUserInfo(user);
  }, []);

  const callProtectedApi = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await oauth2Service.authenticatedFetch('/api/test');

      if (response.ok) {
        const data = await response.json();
        setApiResponse(data);
      } else if (response.status === 404) {
        setApiResponse({
          message: 'This is a demo response. In a real application, this would be data from your protected API.',
          timestamp: new Date().toISOString(),
          user: userInfo?.username || 'Unknown'
        });
      } else {
        throw new Error(`API call failed: ${response.status} ${response.statusText}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'API call failed');
    } finally {
      setLoading(false);
    }
  };

  const testTokenRefresh = async () => {
    setLoading(true);
    setError('');

    try {
      await oauth2Service.refreshAccessToken();
      alert('Token refreshed successfully!');

      const user = oauth2Service.getUserInfo();
      setUserInfo(user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Token refresh failed');
    } finally {
      setLoading(false);
    }
  };

  const getTokenInfo = () => {
    const accessToken = oauth2Service.getAccessToken();
    if (!accessToken) return null;

    try {
      const payload = accessToken.split('.')[1];
      const decoded = JSON.parse(atob(payload));

      return {
        issuedAt: new Date(decoded.iat * 1000).toLocaleString(),
        expiresAt: new Date(decoded.exp * 1000).toLocaleString(),
        issuer: decoded.iss || 'Unknown',
        subject: decoded.sub || 'Unknown',
        scopes: decoded.scope || 'None'
      };
    } catch (error) {
      return null;
    }
  };

  const tokenInfo = getTokenInfo();

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Dashboard</h2>
        <p>Welcome to your OAuth2 protected area!</p>
      </div>

      <div className="dashboard-content">
        <div className="user-info-section">
          <h3>User Information</h3>
          <div className="info-card">
            <div className="info-item">
              <strong>Username:</strong> {userInfo?.username || 'Unknown'}
            </div>
            <div className="info-item">
              <strong>Roles:</strong> {userInfo?.roles?.join(', ') || 'None'}
            </div>
            <div className="info-item">
              <strong>Status:</strong>
              <span className="status-badge authenticated">Authenticated</span>
            </div>
          </div>
        </div>

        {tokenInfo && (
          <div className="token-info-section">
            <h3>Token Information</h3>
            <div className="info-card">
              <div className="info-item">
                <strong>Issued At:</strong> {tokenInfo.issuedAt}
              </div>
              <div className="info-item">
                <strong>Expires At:</strong> {tokenInfo.expiresAt}
              </div>
              <div className="info-item">
                <strong>Scopes:</strong> {tokenInfo.scopes}
              </div>
            </div>
          </div>
        )}

        <div className="actions-section">
          <h3>Actions</h3>
          <div className="action-buttons">
            <button
              onClick={callProtectedApi}
              disabled={loading}
              className="action-btn api-btn"
            >
              {loading ? 'Calling API...' : 'Call Protected API'}
            </button>

            <button
              onClick={testTokenRefresh}
              disabled={loading}
              className="action-btn refresh-btn"
            >
              {loading ? 'Refreshing...' : 'Refresh Token'}
            </button>
          </div>

          {error && (
            <div className="error-message">
              <strong>Error:</strong> {error}
            </div>
          )}
        </div>

        {apiResponse && (
          <div className="api-response-section">
            <h3>API Response</h3>
            <div className="response-card">
              <pre>{JSON.stringify(apiResponse, null, 2)}</pre>
            </div>
          </div>
        )}

        <div className="features-section">
          <h3>OAuth2 Features Demonstrated</h3>
          <div className="features-list">
            <div className="feature-item">
              <h4>🔐 Authorization Code Flow</h4>
              <p>Complete OAuth2 authorization code grant flow with redirect</p>
            </div>
            <div className="feature-item">
              <h4>🔄 Automatic Token Refresh</h4>
              <p>Tokens are automatically refreshed when expired</p>
            </div>
            <div className="feature-item">
              <h4>🛡️ Protected API Calls</h4>
              <p>All API calls include Bearer token authentication</p>
            </div>
            <div className="feature-item">
              <h4>💾 Secure Token Storage</h4>
              <p>Tokens are stored securely in localStorage</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;