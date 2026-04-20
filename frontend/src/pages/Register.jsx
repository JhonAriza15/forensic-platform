import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import axios from 'axios'

export default function Register() {
  const [form, setForm] = useState({ email: '', username: '', password: '' })
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      await axios.post('http://localhost:8000/auth/register', form)
      navigate('/login')
    } catch {
      setError('Error al registrar, el email ya existe')
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>Crear cuenta</h2>
        <p style={styles.subtitle}>Regístrate para usar la plataforma</p>
        {error && <p style={styles.error}>{error}</p>}
        <form onSubmit={handleSubmit}>
          <input
            style={styles.input}
            type="email"
            placeholder="Email"
            value={form.email}
            onChange={e => setForm({...form, email: e.target.value})}
            required
          />
          <input
            style={styles.input}
            type="text"
            placeholder="Usuario"
            value={form.username}
            onChange={e => setForm({...form, username: e.target.value})}
            required
          />
          <input
            style={styles.input}
            type="password"
            placeholder="Contraseña"
            value={form.password}
            onChange={e => setForm({...form, password: e.target.value})}
            required
          />
          <button style={styles.button} type="submit">Registrarse</button>
        </form>
        <p style={styles.link}>
          ¿Ya tienes cuenta? <Link to="/login">Inicia sesión</Link>
        </p>
      </div>
    </div>
  )
}

const styles = {
  container: { minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0f172a' },
  card: { background: '#1e293b', padding: '2rem', borderRadius: '12px', width: '360px', boxShadow: '0 4px 24px rgba(0,0,0,0.4)' },
  title: { color: '#f1f5f9', textAlign: 'center', marginBottom: '4px' },
  subtitle: { color: '#94a3b8', textAlign: 'center', marginBottom: '1.5rem', fontSize: '14px' },
  input: { width: '100%', padding: '10px', marginBottom: '12px', borderRadius: '8px', border: '1px solid #334155', background: '#0f172a', color: '#f1f5f9', fontSize: '14px', boxSizing: 'border-box' },
  button: { width: '100%', padding: '10px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '15px', cursor: 'pointer' },
  error: { color: '#ef4444', fontSize: '13px', marginBottom: '12px' },
  link: { color: '#94a3b8', textAlign: 'center', marginTop: '1rem', fontSize: '13px' }
}