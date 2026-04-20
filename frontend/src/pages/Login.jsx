import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import axios from 'axios'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const form = new FormData()
      form.append('username', email)
      form.append('password', password)
      const res = await axios.post('http://localhost:8000/auth/login', form)
      localStorage.setItem('token', res.data.access_token)
      navigate('/dashboard')
    } catch {
      setError('Credenciales incorrectas')
    }
    setLoading(false)
  }

  return (
    <div style={styles.container}>
      <div style={styles.left}>
        <div style={styles.leftContent}>
          <div style={styles.logo}>FL</div>
          <h1 style={styles.brand}>ForensiLog</h1>
          <p style={styles.tagline}>Plataforma de análisis forense de logs y detección de amenazas en tiempo real</p>
          <div style={styles.features}>
            {['Detección de fuerza bruta', 'Análisis de IPs con AbuseIPDB', 'Score de riesgo automático', 'Pipeline DevSecOps'].map(f => (
              <div key={f} style={styles.feature}>
                <span style={styles.check}>✓</span>
                <span>{f}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={styles.right}>
        <div style={styles.card}>
          <h2 style={styles.title}>Iniciar sesión</h2>
          <p style={styles.subtitle}>Ingresa tus credenciales para continuar</p>

          {error && <div style={styles.error}>{error}</div>}

          <form onSubmit={handleSubmit}>
            <div style={styles.field}>
              <label style={styles.label}>Email</label>
              <input
                style={styles.input}
                type="email"
                placeholder="tu@email.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
              />
            </div>
            <div style={styles.field}>
              <label style={styles.label}>Contraseña</label>
              <input
                style={styles.input}
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
            </div>
            <button style={styles.button} type="submit" disabled={loading}>
              {loading ? 'Ingresando...' : 'Ingresar'}
            </button>
          </form>

          <p style={styles.link}>
            ¿No tienes cuenta? <Link to="/register" style={{ color: '#3b82f6' }}>Regístrate</Link>
          </p>
        </div>
      </div>
    </div>
  )
}

const styles = {
  container: { display: 'flex', minHeight: '100vh', background: '#0b1120' },
  left: { flex: 1, background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem' },
  leftContent: { maxWidth: '400px' },
  logo: { width: '52px', height: '52px', background: 'linear-gradient(135deg, #3b82f6, #6366f1)', borderRadius: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 700, fontSize: '18px', marginBottom: '1.5rem' },
  brand: { color: '#f1f5f9', fontSize: '32px', fontWeight: 700, marginBottom: '0.75rem' },
  tagline: { color: '#94a3b8', fontSize: '15px', lineHeight: 1.6, marginBottom: '2rem' },
  features: { display: 'flex', flexDirection: 'column', gap: '12px' },
  feature: { display: 'flex', alignItems: 'center', gap: '10px', color: '#cbd5e1', fontSize: '14px' },
  check: { width: '20px', height: '20px', background: 'rgba(59,130,246,0.2)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6', fontSize: '11px', fontWeight: 700, flexShrink: 0 },
  right: { width: '480px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' },
  card: { width: '100%', maxWidth: '380px' },
  title: { color: '#f1f5f9', fontSize: '24px', fontWeight: 600, marginBottom: '6px' },
  subtitle: { color: '#64748b', fontSize: '14px', marginBottom: '2rem' },
  error: { background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171', padding: '10px 14px', borderRadius: '8px', fontSize: '13px', marginBottom: '1rem' },
  field: { marginBottom: '1rem' },
  label: { display: 'block', color: '#94a3b8', fontSize: '13px', marginBottom: '6px', fontWeight: 500 },
  input: { width: '100%', padding: '10px 14px', background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', color: '#f1f5f9', fontSize: '14px', boxSizing: 'border-box', outline: 'none' },
  button: { width: '100%', padding: '11px', background: 'linear-gradient(135deg, #3b82f6, #6366f1)', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '15px', fontWeight: 500, cursor: 'pointer', marginTop: '0.5rem', marginBottom: '1.5rem' },
  link: { color: '#64748b', textAlign: 'center', fontSize: '13px' }
}