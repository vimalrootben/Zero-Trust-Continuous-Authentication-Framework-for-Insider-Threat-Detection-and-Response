import React from 'react';
import { User, Signal, LogOut } from 'lucide-react';
import { useLive } from '../contexts/LiveContext';

export const Header: React.FC = () => {
  const { connected, onLogout } = useLive();

  return (
    <header style={{
      height: '60px',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border-color)',
      padding: '0 25px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
        <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Kali Defense Command Console</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: connected ? 'var(--accent-green)' : 'var(--text-muted)' }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: connected ? 'var(--accent-green)' : 'var(--text-muted)',
            boxShadow: connected ? '0 0 8px var(--accent-green)' : 'none',
            display: 'inline-block',
          }} />
          <Signal size={16} />
          <span>{connected ? 'LIVE WEBSOCKET ACTIVE' : 'OFFLINE'}</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '6px 14px', background: 'rgba(147, 51, 234, 0.15)', border: '1px solid var(--border-color)', borderRadius: '20px' }}>
          <User size={16} color="var(--accent-purple-light)" />
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>SOC Analyst</span>
        </div>

        <button
          onClick={onLogout}
          title="Logout"
          style={{
            background: 'transparent',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            cursor: 'pointer',
            padding: '6px 12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            color: 'var(--text-secondary)',
            fontSize: '0.8rem',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = 'var(--accent-red)';
            e.currentTarget.style.color = 'var(--accent-red)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = 'var(--border-color)';
            e.currentTarget.style.color = 'var(--text-secondary)';
          }}
        >
          <LogOut size={15} />
          Logout
        </button>
      </div>
    </header>
  );
};
