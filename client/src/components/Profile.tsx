// src/components/Profile.tsx
import React, { useEffect, useState } from 'react';

interface ProfileData {
  user: {
    id: number;
    email: string;
  };
  error?: string;
}

interface ProfileProps {
  onLogout: () => void;
}

const Profile: React.FC<ProfileProps> = ({ onLogout }) => {
  const [profile, setProfile] = useState<{ id: number; email: string } | null>(null);
  const [message, setMessage] = useState<string>('');

  useEffect(() => {
    const token = localStorage.getItem('token');
    fetch('http://localhost:3000/profile', {
      headers: { 'Authorization': `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data: ProfileData) => {
        if (data.error) {
          setMessage(data.error);
        } else {
          setProfile(data.user);
        }
      })
      .catch((error) => {
        console.error(error);
        setMessage('Wystąpił błąd podczas pobierania profilu.');
      });
  }, []);

  return (
    <div style={containerStyle}>
      <h2 style={headingStyle}>Profil użytkownika</h2>
      {message && <p style={messageStyle}>{message}</p>}
      {profile ? (
        <div style={profileContainerStyle}>
          <p><strong>ID:</strong> {profile.id}</p>
          <p><strong>Email:</strong> {profile.email}</p>
          <button onClick={onLogout} style={logoutButtonStyle}>Wyloguj się</button>
        </div>
      ) : (
        <p style={loadingStyle}>Ładowanie profilu...</p>
      )}
    </div>
  );
};

const containerStyle: React.CSSProperties = {
  maxWidth: '450px',
  margin: '80px auto',
  padding: '40px',
  borderRadius: '15px',
  background: 'linear-gradient(135deg, #ffffff, #f1f1f1)',
  boxShadow: '0 8px 20px rgba(0,0,0,0.15)',
  fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
  textAlign: 'center',
};

const headingStyle: React.CSSProperties = {
  marginBottom: '30px',
  fontSize: '28px',
  fontWeight: 700,
  color: '#333',
};

const messageStyle: React.CSSProperties = {
  color: '#e53935',
  marginTop: '20px',
  fontSize: '16px',
};

const profileContainerStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '20px',
  border: '1px solid #ccc',
  borderRadius: '8px',
  backgroundColor: '#fff',
};

const loadingStyle: React.CSSProperties = {
  fontSize: '18px',
  color: '#555',
};

const logoutButtonStyle: React.CSSProperties = {
  marginTop: '20px',
  padding: '10px 20px',
  backgroundColor: '#e53935',
  color: '#fff',
  border: 'none',
  borderRadius: '5px',
  cursor: 'pointer',
};

export default Profile;
