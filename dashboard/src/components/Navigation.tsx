import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  Monitor, 
  AlertTriangle, 
  Grid, 
  Zap, 
  Clock, 
  FileCheck, 
  CheckSquare, 
  Settings, 
  Users, 
  BarChart, 
  List,
  Terminal
} from 'lucide-react';

export const Navigation: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Overview', icon: Activity },
    { to: '/endpoints', label: 'Endpoints', icon: Monitor },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
    { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
    { to: '/mitre', label: 'MITRE Matrix', icon: Grid },
    { to: '/threat-intel', label: 'Threat Intel', icon: Zap },
    { to: '/timeline', label: 'Timeline', icon: Clock },
    { to: '/policies', label: 'Policies', icon: FileCheck },
    { to: '/rules', label: 'Rules', icon: CheckSquare },
    { to: '/settings', label: 'Settings', icon: Settings },
    { to: '/users', label: 'Users', icon: Users },
    { to: '/reports', label: 'Reports', icon: BarChart },
    { to: '/audit-log', label: 'Audit Log', icon: List },
    { to: '/live-logs', label: 'Live Logs', icon: Terminal },
  ];

  return (
    <aside style={{
      width: '240px',
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border-color)',
      padding: '20px 10px',
      display: 'flex',
      flexDirection: 'column',
      minHeight: '100vh',
      flexShrink: 0
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 10px 20px 10px', borderBottom: '1px solid var(--border-color)', marginBottom: '15px' }}>
        <div style={{ padding: '6px', background: 'rgba(147, 51, 234, 0.2)', borderRadius: '8px', border: '1px solid var(--border-glow)' }}>
          <ShieldAlert color="var(--accent-purple-light)" size={24} />
        </div>
        <div>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#fff', letterSpacing: '0.5px' }}>ZERO TRUST EDR</h2>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Kali Cyber Console</span>
        </div>
      </div>
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 14px',
                borderRadius: '8px',
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                background: isActive ? 'rgba(147, 51, 234, 0.22)' : 'transparent',
                textDecoration: 'none',
                fontWeight: isActive ? 600 : 400,
                fontSize: '0.88rem',
                borderLeft: isActive ? '3px solid var(--accent-purple-light)' : '3px solid transparent',
                transition: 'all 0.15s ease'
              })}
            >
              <Icon size={18} color="var(--accent-purple-light)" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
};
