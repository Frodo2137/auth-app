// src/components/Register.tsx
import React, { useState } from 'react';
import { FaGoogle, FaFacebook } from 'react-icons/fa';

interface RegisterResponse {
  message: string;
  token?: string;
  error?: string;
}

const Register: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState<string>('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password.trim() !== confirmPassword.trim()) {
      setMessage('Błąd: Hasła muszą być identyczne.');
      return;
    }

    try {
      const res = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, confirmPassword }),
      });
      const data: RegisterResponse = await res.json();
      if (data.error) {
        setMessage(`Błąd: ${data.error}`);
      } else {
        setMessage(`Sukces: ${data.message}`);
        if (data.token) {
          localStorage.setItem('token', data.token);
        }
      }
    } catch (error) {
      console.error(error);
      setMessage('Wystąpił błąd podczas rejestracji.');
    }
  };

  const handleGoogleRegister = () => {
    window.location.href = "http://localhost:3000/auth/google";
  };

  const handleFacebookRegister = () => {
    window.location.href = "http://localhost:3000/auth/facebook";
  };

  return (
    <div style={containerStyle}>
      <h2 style={headingStyle}>Rejestracja</h2>
      <form onSubmit={handleSubmit} style={formStyle}>
        <div style={formGroupStyle}>
          <label style={labelStyle}>Email:</label>
          <input 
            type="email" 
            placeholder="Wpisz adres email"
            value={email} 
            onChange={(e) => setEmail(e.target.value)}
            required 
            style={inputStyle}
          />
        </div>
        <div style={formGroupStyle}>
          <label style={labelStyle}>Hasło:</label>
          <input 
            type="password" 
            placeholder="Wpisz hasło"
            value={password} 
            onChange={(e) => setPassword(e.target.value)}
            required 
            style={inputStyle}
          />
        </div>
        <div style={formGroupStyle}>
          <label style={labelStyle}>Potwierdź hasło:</label>
          <input 
            type="password" 
            placeholder="Potwierdź hasło"
            value={confirmPassword} 
            onChange={(e) => setConfirmPassword(e.target.value)}
            required 
            style={inputStyle}
          />
        </div>
        <button type="submit" style={buttonStyle}>Zarejestruj się</button>
      </form>
      {message && <p style={messageStyle}>{message}</p>}
      <div style={dividerStyle}>lub</div>
      <div style={socialContainerStyle}>
        <button onClick={handleGoogleRegister} style={{ ...socialButtonStyle, backgroundColor: '#DB4437' }}>
          <span style={iconStyle}><FaGoogle /></span>
          <span style={socialButtonTextStyle}>Zaloguj się przez Google</span>
        </button>
        <button onClick={handleFacebookRegister} style={{ ...socialButtonStyle, backgroundColor: '#4267B2' }}>
          <span style={iconStyle}><FaFacebook /></span>
          <span style={socialButtonTextStyle}>Zaloguj się przez Facebooka</span>
        </button>
      </div>
    </div>
  );
};

// Style
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

const formStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
};

const formGroupStyle: React.CSSProperties = {
  width: '100%',
  marginBottom: '20px',
  textAlign: 'left',
};

const labelStyle: React.CSSProperties = {
  marginBottom: '5px',
  fontSize: '16px',
  color: '#555',
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '14px',
  border: '1px solid #ccc',
  borderRadius: '8px',
  fontSize: '16px',
  outline: 'none',
  transition: 'border-color 0.3s ease',
};

const buttonStyle: React.CSSProperties = {
  width: '100%',
  padding: '14px',
  backgroundColor: '#4CAF50',
  color: '#fff',
  border: 'none',
  borderRadius: '8px',
  cursor: 'pointer',
  fontSize: '18px',
  fontWeight: 600,
  marginTop: '10px',
  transition: 'background-color 0.3s ease',
};

const messageStyle: React.CSSProperties = {
  color: '#e53935',
  marginTop: '20px',
  fontSize: '16px',
};

const dividerStyle: React.CSSProperties = {
  margin: '30px 0',
  fontSize: '16px',
  color: '#aaa',
};

const socialContainerStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: '15px',
};

const socialButtonStyle: React.CSSProperties = {
  width: '100%',
  padding: '14px',
  color: '#fff',
  border: 'none',
  borderRadius: '8px',
  cursor: 'pointer',
  fontSize: '18px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  transition: 'background-color 0.3s ease',
};

const iconStyle: React.CSSProperties = {
  marginRight: '10px',
  fontSize: '22px',
};

const socialButtonTextStyle: React.CSSProperties = {
  fontWeight: 600,
};

export default Register;
