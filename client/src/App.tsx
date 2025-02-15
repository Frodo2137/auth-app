// src/App.tsx
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, NavLink, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Profile from './components/Profile';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);

  // Sprawdzamy, czy token istnieje w localStorage przy starcie
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token && token.trim() !== "" && token !== "null" && token !== "undefined") {
      setIsAuthenticated(true);
    } else {
      localStorage.removeItem('token');
      setIsAuthenticated(false);
    }
  }, []);

  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsAuthenticated(false);
  };

  return (
    <Router>
      <header style={headerStyle}>
        <nav style={navStyle}>
          {!isAuthenticated ? (
            <>
              <NavLink
                to="/"
                style={({ isActive }) => ({
                  ...linkStyle,
                  borderBottom: isActive ? '2px solid #fff' : 'none',
                })}
              >
                Logowanie
              </NavLink>
              <NavLink
                to="/register"
                style={({ isActive }) => ({
                  ...linkStyle,
                  borderBottom: isActive ? '2px solid #fff' : 'none',
                })}
              >
                Rejestracja
              </NavLink>
            </>
          ) : (
            <NavLink
              to="/profile"
              style={({ isActive }) => ({
                ...linkStyle,
                borderBottom: isActive ? '2px solid #fff' : 'none',
              })}
            >
              Profil
            </NavLink>
          )}
        </nav>
      </header>
      <main style={mainStyle}>
        <Routes>
          {!isAuthenticated ? (
            <>
              <Route path="/" element={<Login onLogin={handleLogin} />} />
              <Route path="/register" element={<Register />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </>
          ) : (
            <>
              <Route path="/profile" element={<Profile onLogout={handleLogout} />} />
              <Route path="*" element={<Navigate to="/profile" replace />} />
            </>
          )}
        </Routes>
      </main>
    </Router>
  );
};

const headerStyle: React.CSSProperties = {
  backgroundColor: '#4CAF50',
  padding: '15px 30px',
  boxShadow: '0 2px 5px rgba(0,0,0,0.2)',
};

const navStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'center',
  gap: '40px',
};

const linkStyle: React.CSSProperties = {
  color: '#fff',
  textDecoration: 'none',
  fontSize: '18px',
  fontWeight: 600,
  paddingBottom: '5px',
  minWidth: '120px',
  textAlign: 'center',
};

const mainStyle: React.CSSProperties = {
  padding: '20px',
  minHeight: 'calc(100vh - 80px)',
};

export default App;
