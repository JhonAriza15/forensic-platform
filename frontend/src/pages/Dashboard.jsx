import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { generateReport } from "../utils/reportGenerator.js"


export default function Dashboard() {
  const [timeline, setTimeline] = useState(null)
  const [logs, setLogs] = useState([])
  const [uploading, setUploading] = useState(false)
  const [message, setMessage] = useState('')
  const [selectedFindings, setSelectedFindings] = useState(null)
  const [modalLog, setModalLog] = useState(null)
  const [filtroEstado, setFiltroEstado] = useState('todos')
  const [activeTab, setActiveTab] = useState('logs')
  const [scanUrl, setScanUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanResults, setScanResults] = useState(null)
  const navigate = useNavigate()

  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  const fetchLogs = async () => {
    try {
      const res = await axios.get('http://localhost:8000/logs/', { headers })
      setLogs(res.data)
    } catch {
      navigate('/login')
    }
  }

  useEffect(() => {
    fetchLogs()
    const interval = setInterval(fetchLogs, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setUploading(true)
    const form = new FormData()
    form.append('file', file)
    try {
      await axios.post('http://localhost:8000/logs/upload', form, { headers })
      setMessage('Archivo subido, procesando...')
      fetchLogs()
    } catch {
      setMessage('Error al subir el archivo')
    }
    setUploading(false)
  }

  const handleDelete = async (logId, filename) => {
    if (window.confirm(`¿Eliminar "${filename}"?`)) {
      try {
        await axios.delete(`http://localhost:8000/logs/${logId}`, { headers })
        fetchLogs()
      } catch {
        console.error('Error eliminando log')
      }
    }
  }

  const handleViewFindings = async (log) => {
    try {
      const res = await axios.get(`http://localhost:8000/logs/${log.id}/findings`, { headers })
      setSelectedFindings(res.data)
      setModalLog(log)
    } catch {
      console.error('Error obteniendo hallazgos')
    }
  }

  const handleViewTimeline = async (log) => {
    try {
      const res = await axios.get(`http://localhost:8000/logs/${log.id}/timeline`, { headers })
      setTimeline(res.data)
      setModalLog(log)
    } catch {
      console.error('Error obteniendo timeline')
    }
  }

  const handleGenerateReport = async (log) => {
  try {
    const res = await axios.get(`http://localhost:8000/logs/${log.id}/findings`, { headers })
    generateReport(log, res.data)
    } catch {
    alert('Error generando el informe')
    }
  }

  const handleScan = async () => {
    if (!scanUrl) return
    setScanning(true)
    setScanResults(null)
    try {
      const res = await axios.post('http://localhost:8000/scanner/url', { url: scanUrl }, { headers })
      setScanResults(res.data)
    } catch {
      alert('Error al escanear la URL')
    }
    setScanning(false)
  }

  const statusColor = (status) => {
    if (status === 'done') return '#22c55e'
    if (status === 'error') return '#ef4444'
    if (status === 'processing') return '#f59e0b'
    return '#94a3b8'
  }

  const severityColor = (severity) => {
    if (severity === 'critical') return '#ef4444'
    if (severity === 'high') return '#f97316'
    if (severity === 'medium') return '#f59e0b'
    return '#22c55e'
  }

  const dotColor = (level) => {
    if (level === 'critical') return '#ef4444'
    if (level === 'error') return '#f97316'
    return '#f59e0b'
  }

  const logsFiltrados = filtroEstado === 'todos' ? logs : logs.filter(l => l.status === filtroEstado)
  const totalHallazgos = logs.reduce((acc, l) => acc + (l.findings_count || 0), 0)
  const logsAnalizados = logs.filter(l => l.status === 'done').length
  const logsPendientes = logs.filter(l => l.status === 'pending').length

  const chartData = [
    { name: 'Analizados', value: logsAnalizados, color: '#22c55e' },
    { name: 'Pendientes', value: logsPendientes, color: '#94a3b8' },
    { name: 'Con hallazgos', value: logs.filter(l => l.findings_count > 0).length, color: '#ef4444' },
  ].filter(d => d.value > 0)

  return (
    <div style={styles.container}>

      <div style={styles.tabs}>
        <button style={{ ...styles.tab, ...(activeTab === 'logs' ? styles.tabActive : {}) }} onClick={() => setActiveTab('logs')}>
          Subir Log
        </button>
        <button style={{ ...styles.tab, ...(activeTab === 'scanner' ? styles.tabActive : {}) }} onClick={() => setActiveTab('scanner')}>
          Escanear URL
        </button>
      </div>

      {activeTab === 'logs' && (
        <div style={styles.uploadBox}>
          <p style={styles.uploadText}>Sube un archivo de log para analizar</p>
          <label style={styles.uploadBtn}>
            {uploading ? 'Subiendo...' : 'Seleccionar archivo'}
            <input type="file" onChange={handleUpload} style={{ display: 'none' }} />
          </label>
          {message && <p style={styles.message}>{message}</p>}
        </div>
      )}

      {activeTab === 'scanner' && (
        <div style={styles.uploadBox}>
          <p style={styles.uploadText}>Escanea una URL para detectar vulnerabilidades</p>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
            <input
              style={styles.scanInput}
              type="text"
              placeholder="https://ejemplo.com"
              value={scanUrl}
              onChange={e => setScanUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
            />
            <button style={styles.scanBtn} onClick={handleScan} disabled={scanning}>
              {scanning ? 'Escaneando...' : 'Escanear'}
            </button>
          </div>
          {scanResults && (
            <div style={styles.scanResults}>
              <div style={styles.scanHeader}>
                <span style={{ color: scanResults.reachable ? '#22c55e' : '#ef4444', fontWeight: 600 }}>
                  {scanResults.reachable ? '✓ Sitio accesible' : '✗ No accesible'}
                </span>
                <span style={{ color: '#64748b', fontSize: '13px' }}>
                  {scanResults.status_code && `HTTP ${scanResults.status_code}`}
                  {scanResults.response_time_ms && ` · ${scanResults.response_time_ms}ms`}
                </span>
                <span style={{ color: scanResults.https ? '#22c55e' : '#ef4444', fontSize: '13px' }}>
                  {scanResults.https ? '🔒 HTTPS' : '⚠️ Sin HTTPS'}
                </span>
              </div>
              {scanResults.missing_headers?.length > 0 && (
                <div style={{ marginTop: '12px' }}>
                  <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '8px' }}>
                    Headers faltantes ({scanResults.missing_headers.length}):
                  </p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {scanResults.missing_headers.map(h => (
                      <span key={h} style={styles.missingBadge}>{h}</span>
                    ))}
                  </div>
                </div>
              )}
              {scanResults.findings?.length > 0 && (
                <div style={{ marginTop: '12px' }}>
                  <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '8px' }}>
                    Hallazgos ({scanResults.findings.length}):
                  </p>
                  {scanResults.findings.map((f, i) => (
                    <div key={i} style={styles.scanFinding}>
                      <span style={{ color: severityColor(f.severity), fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>{f.severity}</span>
                      <span style={{ color: '#f1f5f9', fontSize: '13px', marginLeft: '8px' }}>{f.title}</span>
                      {f.recommendation && <p style={{ color: '#64748b', fontSize: '12px', margin: '4px 0 0' }}>💡 {f.recommendation}</p>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div style={styles.filterRow}>
        <h2 style={styles.subtitle}>Logs analizados</h2>
        <select style={styles.select} value={filtroEstado} onChange={e => setFiltroEstado(e.target.value)}>
          <option value="todos">Todos</option>
          <option value="pending">Pending</option>
          <option value="processing">Processing</option>
          <option value="done">Done</option>
          <option value="error">Error</option>
        </select>
      </div>

      <div style={styles.statsRow}>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Total logs</p>
          <p style={styles.statValue}>{logs.length}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Analizados</p>
          <p style={{ ...styles.statValue, color: '#22c55e' }}>{logsAnalizados}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Hallazgos totales</p>
          <p style={{ ...styles.statValue, color: totalHallazgos > 0 ? '#ef4444' : '#22c55e' }}>{totalHallazgos}</p>
        </div>
      </div>

      {chartData.length > 0 && (
        <div style={styles.chartBox}>
          <div style={styles.chartHeader}>
            <p style={styles.chartTitle}>Resumen de análisis</p>
            <span style={styles.chartBadge}>{logs.length} archivos totales</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={chartData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                  {chartData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} strokeWidth={0} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', color: '#f1f5f9' }} itemStyle={{ color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', minWidth: '160px' }}>
              {chartData.map((item, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: item.color, flexShrink: 0 }} />
                  <div>
                    <p style={{ color: '#94a3b8', fontSize: '12px', margin: 0 }}>{item.name}</p>
                    <p style={{ color: '#f1f5f9', fontSize: '18px', fontWeight: 600, margin: 0 }}>{item.value}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {logsFiltrados.length === 0 ? (
        <p style={styles.empty}>No hay logs con ese filtro.</p>
      ) : (
        <div style={styles.table}>
          <div style={styles.tableHeader}>
            <span>Archivo</span>
            <span>Tamaño</span>
            <span>Estado</span>
            <span>Eventos</span>
            <span>Hallazgos</span>
            <span>Riesgo</span>
            <span>Acciones</span>
          </div>
          {logsFiltrados.map(log => (
            <div key={log.id} style={styles.tableRow}>
              <span style={styles.filename}>{log.original_filename}</span>
              <span>{(log.file_size / 1024).toFixed(1)} KB</span>
              <span style={{ color: statusColor(log.status), fontWeight: 500 }}>{log.status}</span>
              <span>{log.events_extracted ?? '-'}</span>
              <span style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{ color: '#3b82f6', cursor: 'pointer', fontSize: '12px' }} onClick={() => handleViewTimeline(log)}>Timeline</span>
              <span style={{ color: '#22c55e', cursor: 'pointer', fontSize: '12px' }} onClick={() => handleGenerateReport(log)}>Informe</span>
              <span style={{ color: '#ef4444', cursor: 'pointer', fontSize: '12px' }} onClick={() => handleDelete(log.id, log.original_filename)}>Eliminar</span>
              </span>
              <span style={{ color: log.findings_count > 0 ? '#ef4444' : '#22c55e', fontWeight: 500, cursor: log.findings_count > 0 ? 'pointer' : 'default', textDecoration: log.findings_count > 0 ? 'underline' : 'none' }}
                    onClick={() => log.findings_count > 0 && handleViewFindings(log)}>
              {log.findings_count ?? '-'}
              </span>
              <span style={{ color: log.risk_level === 'CRÍTICO' ? '#ef4444' : log.risk_level === 'ALTO' ? '#f97316' : log.risk_level === 'MEDIO' ? '#f59e0b' : '#22c55e', fontWeight: 500, fontSize: '12px' }}>
                {log.risk_score ? `${log.risk_score}% ${log.risk_level}` : '-'}
              </span>
             
            </div>
          ))}
        </div>
      )}

      {selectedFindings && (
        <div style={styles.modalOverlay} onClick={() => setSelectedFindings(null)}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={styles.modalTitle}>Hallazgos — {modalLog?.original_filename}</h3>
              <button style={styles.closeBtn} onClick={() => setSelectedFindings(null)}>✕</button>
            </div>
            {selectedFindings.map(f => (
              <div key={f.id} style={styles.findingCard}>
                <div style={styles.findingHeader}>
                  <span style={styles.findingTitle}>{f.title}</span>
                  <span style={{ color: severityColor(f.severity), fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>{f.severity}</span>
                </div>
                <p style={styles.findingDesc}>{f.description}</p>
                <p style={styles.findingCategory}>Categoría: {f.category.replace('_', ' ')}</p>
                <p style={styles.findingConf}>Confianza: {Math.round(f.confidence_score * 100)}%</p>
                {f.recommendation && <p style={styles.findingRec}>💡 {f.recommendation}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      {timeline && (
        <div style={styles.modalOverlay} onClick={() => setTimeline(null)}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={styles.modalTitle}>Línea de tiempo — {modalLog?.original_filename}</h3>
              <button style={styles.closeBtn} onClick={() => setTimeline(null)}>✕</button>
            </div>
            {timeline.length === 0 ? (
              <p style={{ color: '#94a3b8' }}>No hay eventos relevantes.</p>
            ) : (
              timeline.map((event, index) => (
                <div key={index} style={{ display: 'flex', gap: '12px', marginBottom: '12px', alignItems: 'flex-start' }}>
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', marginTop: '4px', flexShrink: 0, background: dotColor(event.level) }} />
                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px' }}>Línea {event.line_number}</span>
                    <p style={{ color: '#94a3b8', fontSize: '13px', margin: '2px 0 0' }}>{event.message}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}

const styles = {
  container: { minHeight: '100vh', background: '#0b1120', padding: '2rem', color: '#f1f5f9' },
  tabs: { display: 'flex', gap: '4px', marginBottom: '1rem', background: '#0f172a', padding: '4px', borderRadius: '10px', width: 'fit-content' },
  tab: { padding: '8px 20px', borderRadius: '8px', border: 'none', background: 'transparent', color: '#64748b', cursor: 'pointer', fontSize: '14px', fontWeight: 500 },
  tabActive: { background: '#1e293b', color: '#f1f5f9' },
  uploadBox: { background: '#0f172a', border: '1px solid #1e293b', padding: '1.5rem', borderRadius: '12px', marginBottom: '1.5rem', textAlign: 'center' },
  uploadText: { color: '#94a3b8', marginBottom: '1rem' },
  uploadBtn: { background: '#3b82f6', color: '#fff', padding: '10px 24px', borderRadius: '8px', cursor: 'pointer', fontSize: '14px' },
  message: { color: '#22c55e', marginTop: '1rem', fontSize: '13px' },
  scanInput: { padding: '10px 14px', background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#f1f5f9', fontSize: '14px', width: '320px', outline: 'none' },
  scanBtn: { padding: '10px 20px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '14px', cursor: 'pointer', fontWeight: 500 },
  scanResults: { marginTop: '1rem', background: '#1e293b', borderRadius: '8px', padding: '1rem', textAlign: 'left' },
  scanHeader: { display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' },
  missingBadge: { background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '3px 10px', borderRadius: '20px', fontSize: '11px' },
  scanFinding: { background: '#0f172a', borderRadius: '8px', padding: '10px', marginBottom: '6px' },
  filterRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' },
  subtitle: { color: '#f1f5f9', margin: 0 },
  select: { background: '#0f172a', color: '#f1f5f9', border: '1px solid #1e293b', padding: '6px 12px', borderRadius: '8px', fontSize: '13px' },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' },
  statCard: { background: '#0f172a', border: '1px solid #1e293b', padding: '1rem', borderRadius: '10px', textAlign: 'center' },
  statLabel: { color: '#64748b', fontSize: '13px', margin: '0 0 4px' },
  statValue: { color: '#f1f5f9', fontSize: '28px', fontWeight: 600, margin: 0 },
  chartBox: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.25rem', marginBottom: '1.5rem' },
  chartHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' },
  chartTitle: { color: '#94a3b8', fontSize: '13px', margin: 0 },
  chartBadge: { background: '#1e293b', color: '#64748b', fontSize: '12px', padding: '4px 10px', borderRadius: '20px' },
  empty: { color: '#94a3b8', textAlign: 'center', marginTop: '2rem' },
  table: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', overflow: 'hidden' },
  tableHeader: { display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 1fr 1fr', padding: '12px 16px', background: '#1e293b', color: '#64748b', fontSize: '13px', fontWeight: 500 },
  tableRow: { display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 1fr 1fr', padding: '12px 16px', borderTop: '1px solid #1e293b', fontSize: '14px' },
  filename: { color: '#f1f5f9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  modalOverlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
  modal: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem', width: '560px', maxHeight: '80vh', overflowY: 'auto' },
  modalHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' },
  modalTitle: { color: '#f1f5f9', margin: 0, fontSize: '16px' },
  closeBtn: { background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '18px', cursor: 'pointer' },
  findingCard: { background: '#1e293b', borderRadius: '8px', padding: '1rem', marginBottom: '1rem', borderLeft: '3px solid #3b82f6' },
  findingHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' },
  findingTitle: { color: '#f1f5f9', fontWeight: 500, fontSize: '14px' },
  findingDesc: { color: '#94a3b8', fontSize: '13px', margin: '4px 0' },
  findingCategory: { color: '#64748b', fontSize: '12px', margin: '4px 0' },
  findingConf: { color: '#64748b', fontSize: '12px', margin: '4px 0' },
  findingRec: { color: '#22c55e', fontSize: '13px', margin: '8px 0 0', padding: '8px', background: 'rgba(34,197,94,0.05)', borderRadius: '6px' }
}