import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { oauth2Service } from '../services/oauth2Service';
import './CallbackPage.css';

interface CallbackPageProps {
  onAuthSuccess: () => void;
}

const CallbackPage: React.FC<CallbackPageProps> = ({ onAuthSuccess }) => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const code = searchParams.get('code');
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');

        if (error) {
          setStatus('error');
          setError(errorDescription || error);
          return;
        }

        if (!code) {
          setStatus('error');
          setError('No authorization code received');
          return;
        }

        const tokenResponse = await oauth2Service.handleCallback(code);

        setStatus('success');

        onAuthSuccess();

        setTimeout(() => {
          navigate('/dashboard');
        }, 2000);

      } catch (err) {
        setStatus('error');
        setError(err instanceof Error ? err.message : 'Authentication failed');
      }
    };

    handleCallback();
  }, [searchParams, navigate, onAuthSuccess]);

  const handleRetry = () => {
    navigate('/login');
  };

  const handleContinue = () => {
    navigate('/dashboard');
  };

  return (
    <div className="callback-container">
      <div className="callback-card">
        {status === 'loading' && (
          <div className="status-section">
            <div className="spinner"></div>
            <h3>Processing Authentication...</h3>
            <p>Please wait while we exchange your authorization code for access tokens.</p>
          </div>
        )}

        {status === 'success' && (
          <div className="status-section success">
            <div className="success-icon">✓</div>
            <h3>Authentication Successful!</h3>
            <p>Your authorization code has been successfully exchanged for access tokens.</p>
            <p>You will be redirected to the dashboard shortly...</p>
            <button onClick={handleContinue} className="continue-btn">
              Continue to Dashboard
            </button>
          </div>
        )}

        {status === 'error' && (
          <div className="status-section error">
            <div className="error-icon">✗</div>
            <h3>Authentication Failed</h3>
            <p>{error}</p>
            <div className="error-actions">
              <button onClick={handleRetry} className="retry-btn">
                Try Again
              </button>
              <button onClick={() => navigate('/')} className="home-btn">
                Go Home
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CallbackPage;