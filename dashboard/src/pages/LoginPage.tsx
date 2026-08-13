import React, { useState } from 'react';
import { api } from '../services/api';
import { ShieldAlert } from 'lucide-react';

export const LoginPage: React.FC<{ onLogin: () => void }> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.login(username, password);
      onLogin();
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: 'var(--bg-primary)' }}>
      <div className="glass-card" style={{ width: '420px', padding: '40px', borderColor: 'var(--border-glow)' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <div style={{ display: 'inline-flex', padding: '12px', background: 'rgba(147, 51, 234, 0.15)', borderRadius: '50%', marginBottom: '12px', border: '1px solid var(--border-glow)' }}>
            <ShieldAlert color="var(--accent-purple-light)" size={36} />
          </div>
          <h2 style={{ color: 'var(--accent-purple-light)', fontSize: '1.6rem', marginBottom: '6px', letterSpacing: '0.5px' }}>Zero Trust EDR</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Analyst Control Console Authentication</p>
        </div>

        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid var(--accent-red)',
            borderRadius: '8px',
            padding: '12px 16px',
            marginBottom: '20px',
            color: 'var(--accent-red)',
            fontSize: '0.85rem'
          }}>
            ⚠ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Username</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              style={{
                width: '100%',
                padding: '12px',
                background: 'rgba(18, 11, 36, 0.8)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                color: '#fff',
                boxSizing: 'border-box',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              required
              autoFocus
              placeholder="Enter username"
            />
          </div>
          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '12px',
                background: 'rgba(18, 11, 36, 0.8)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                color: '#fff',
                boxSizing: 'border-box',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              required
              placeholder="••••••••"
            />
          </div>
          <button type="submit" className="btn" style={{ marginTop: '10px', width: '100%', padding: '12px', opacity: loading ? 0.7 : 1 }} disabled={loading}>
            {loading ? 'Authenticating...' : 'Sign In to Console'}
          </button>
        </form>
      </div>
    </div>
  );
};
