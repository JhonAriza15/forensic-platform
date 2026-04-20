import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'

const icons = {
  dashboard: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
      <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
    </svg>
  ),
  shield: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  scanner: (
    
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  logout: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
      <polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  )
}

export default function Sidebar() {
  const navigate = useNavigate()
  const location = useLocation()

  const handleLogout = () => {
    localStorage.removeItem('token')
    navigate('/login')
  }

  const navItems = [
    { label: 'Dashboard', path: '/dashboard', icon: icons.dashboard },
    { label: 'Hallazgos', path: '/findings', icon: icons.shield },
    { label: 'Vuln Scanner', path: '/vuln-scanner', icon: icons.scanner },
  ]

  return (
    <div style={styles.sidebar}>
      <div style={styles.logo}>
        <div style={styles.logoIcon}>FL</div>
        <div>
          <p style={styles.logoTitle}>ForensiLog</p>
          <p style={styles.logoSub}>Security Platform</p>
        </div>
      </div>

      <nav style={styles.nav}>
        {navItems.map(item => (
          <div
            key={item.path}
            style={{
              ...styles.navItem,
              ...(location.pathname === item.path ? styles.navItemActive : {})
            }}
            onClick={() => navigate(item.path)}>
            <span style={{ opacity: location.pathname === item.path ? 1 : 0.6 }}>
              {item.icon}
            </span>
            <span>{item.label}</span>
          </div>
        ))}
      </nav>

      <div style={styles.bottom}>
        <div style={styles.navItem} onClick={handleLogout}>
          <span style={{ opacity: 0.6 }}>{icons.logout}</span>
          <span>Cerrar sesión</span>
        </div>
      </div>
    </div>
  )
}

const styles = {
  sidebar: {
    width: '220px',
    minHeight: '100vh',
    background: '#0f172a',
    borderRight: '1px solid #1e293b',
    display: 'flex',
    flexDirection: 'column',
    padding: '1.5rem 0',
    position: 'fixed',
    top: 0,
    left: 0,
    bottom: 0,
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '0 1.25rem 1.5rem',
    borderBottom: '1px solid #1e293b',
    marginBottom: '1rem'
  },
  logoIcon: {
    width: '38px',
    height: '38px',
    background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
    borderRadius: '10px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#fff',
    fontWeight: 700,
    fontSize: '14px'
  },
  logoTitle: { color: '#f1f5f9', fontWeight: 600, fontSize: '15px', margin: 0 },
  logoSub: { color: '#64748b', fontSize: '11px', margin: 0 },
  nav: { flex: 1, padding: '0 0.75rem' },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    borderRadius: '8px',
    cursor: 'pointer',
    color: '#94a3b8',
    fontSize: '14px',
    marginBottom: '4px',
    transition: 'all 0.15s'
  },
  navItemActive: {
    background: '#1e293b',
    color: '#f1f5f9',
  },
  bottom: { padding: '0 0.75rem', borderTop: '1px solid #1e293b', paddingTop: '1rem' }
}