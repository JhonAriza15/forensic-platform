import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function Findings() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [filtroSeveridad, setFiltroSeveridad] = useState('todos')
  const navigate = useNavigate()

  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  const fetchAllFindings = async () => {
    try {
      const logsRes = await axios.get('http://localhost:8000/logs/', { headers })
      const logs = logsRes.data.filter(l => l.findings_count > 0)

      const allFindings = []
      for (const log of logs) {
        const res = await axios.get(`http://localhost:8000/logs/${log.id}/findings`, { headers })
        res.data.forEach(f => allFindings.push({ ...f, log_filename: log.original_filename }))
      }
      setFindings(allFindings)
    } catch {
      navigate('/login')
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchAllFindings()
  }, [])

  const severityColor = (severity) => {
    if (severity === 'critical') return '#ef4444'
    if (severity === 'high') return '#f97316'
    if (severity === 'medium') return '#f59e0b'
    return '#22c55e'
  }

  const filtrados = filtroSeveridad === 'todos'
    ? findings
    : findings.filter(f => f.severity === filtroSeveridad)

  const criticos = findings.filter(f => f.severity === 'critical').length
  const altos = findings.filter(f => f.severity === 'high').length
  const medios = findings.filter(f => f.severity === 'medium').length

  return (
    <div>
      <h1 style={styles.title}>Hallazgos de seguridad</h1>
      <p style={styles.subtitle}>Todos los hallazgos detectados en tus logs</p>

      <div style={styles.statsRow}>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Total hallazgos</p>
          <p style={styles.statValue}>{findings.length}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Críticos</p>
          <p style={{ ...styles.statValue, color: '#ef4444' }}>{criticos}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Altos</p>
          <p style={{ ...styles.statValue, color: '#f97316' }}>{altos}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Medios</p>
          <p style={{ ...styles.statValue, color: '#f59e0b' }}>{medios}</p>
        </div>
      </div>

      <div style={styles.filterRow}>
        <select style={styles.select} value={filtroSeveridad} onChange={e => setFiltroSeveridad(e.target.value)}>
          <option value="todos">Todos</option>
          <option value="critical">Crítico</option>
          <option value="high">Alto</option>
          <option value="medium">Medio</option>
          <option value="low">Bajo</option>
        </select>
      </div>

      {loading ? (
        <p style={{ color: '#64748b', textAlign: 'center', marginTop: '2rem' }}>Cargando hallazgos...</p>
      ) : filtrados.length === 0 ? (
        <p style={{ color: '#64748b', textAlign: 'center', marginTop: '2rem' }}>No hay hallazgos con ese filtro.</p>
      ) : (
        <div style={styles.list}>
          {filtrados.map(f => (
            <div key={f.id} style={styles.card}>
              <div style={styles.cardHeader}>
                <div style={styles.cardLeft}>
                  <span style={{ ...styles.badge, background: severityColor(f.severity) + '20', color: severityColor(f.severity) }}>
                    {f.severity.toUpperCase()}
                  </span>
                  <span style={styles.cardTitle}>{f.title}</span>
                </div>
                <span style={styles.filename}>{f.log_filename}</span>
              </div>
              <p style={styles.desc}>{f.description}</p>
              <div style={styles.cardFooter}>
                <span style={styles.meta}>Categoría: {f.category.replace(/_/g, ' ')}</span>
                <span style={styles.meta}>Confianza: {Math.round(f.confidence_score * 100)}%</span>
              </div>
              {f.recommendation && (
                <p style={styles.rec}>💡 {f.recommendation}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

const styles = {
  title: { color: '#f1f5f9', fontSize: '22px', fontWeight: 600, marginBottom: '4px' },
  subtitle: { color: '#64748b', fontSize: '14px', marginBottom: '1.5rem' },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' },
  statCard: { background: '#0f172a', border: '1px solid #1e293b', padding: '1rem', borderRadius: '10px', textAlign: 'center' },
  statLabel: { color: '#64748b', fontSize: '12px', margin: '0 0 4px' },
  statValue: { color: '#f1f5f9', fontSize: '26px', fontWeight: 600, margin: 0 },
  filterRow: { marginBottom: '1rem' },
  select: { background: '#0f172a', color: '#f1f5f9', border: '1px solid #1e293b', padding: '6px 12px', borderRadius: '8px', fontSize: '13px' },
  list: { display: 'flex', flexDirection: 'column', gap: '12px' },
  card: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1rem 1.25rem' },
  cardHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' },
  cardLeft: { display: 'flex', alignItems: 'center', gap: '10px' },
  badge: { padding: '3px 10px', borderRadius: '20px', fontSize: '11px', fontWeight: 600 },
  cardTitle: { color: '#f1f5f9', fontWeight: 500, fontSize: '14px' },
  filename: { color: '#475569', fontSize: '12px' },
  desc: { color: '#94a3b8', fontSize: '13px', margin: '4px 0 8px' },
  cardFooter: { display: 'flex', gap: '16px' },
  meta: { color: '#475569', fontSize: '12px' },
  rec: { color: '#22c55e', fontSize: '13px', marginTop: '8px', padding: '8px', background: 'rgba(34,197,94,0.05)', borderRadius: '6px' }
}