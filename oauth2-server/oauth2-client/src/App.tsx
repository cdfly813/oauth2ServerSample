import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { oauth2Service } from './services/oauth2Service';
import LoginPage from './components/LoginPage';
import CallbackPage from './components/CallbackPage';
import Dashboard from './components/Dashboard';
import ProtectedRoute from './components/ProtectedRoute';
import './App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = () => {
      const authenticated = oauth2Service.isAuthenticated();
      setIsAuthenticated(authenticated);
      setLoading(false);
    };

    checkAuth();

    const interval = setInterval(() => {
      if (oauth2Service.isTokenExpired() && oauth2Service.getAccessToken()) {
        oauth2Service.refreshAccessToken()
          .then(() => {
            console.log('Token refreshed successfully');
          })
          .catch((error) => {
            console.error('Token refresh failed:', error);
            setIsAuthenticated(false);
          });
      }
    }, 60000);

    return () => clearInterval(interval);
  }, []);

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    oauth2Service.logout();
    setIsAuthenticated(false);
  };

  if (loading) {
    return (
      <div className="loading">
        <div>Loading...</div>
      </div>
    );
  }

  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>OAuth2 Client Demo</h1>
          {isAuthenticated && (
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          )}
        </header>

        <main>
          <Routes>
            <Route
              path="/"
              element={
                isAuthenticated ? (
                  <Navigate to="/dashboard" replace />
                ) : (
                  <LoginPage onLoginSuccess={handleLoginSuccess} />
                )
              }
            />
            <Route
              path="/login"
              element={<LoginPage onLoginSuccess={handleLoginSuccess} />}
            />
            <Route
              path="/callback"
              element={<CallbackPage onAuthSuccess={handleLoginSuccess} />}
            />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute isAuthenticated={isAuthenticated}>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;