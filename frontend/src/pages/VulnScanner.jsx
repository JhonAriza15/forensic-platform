import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function VulnScanner() {
  const [scans, setScans] = useState([])
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [launching, setLaunching] = useState(false)
  const [selectedScan, setSelectedScan] = useState(null)
  const [detailData, setDetailData] = useState(null)
  const [now, setNow] = useState(Date.now())
  const navigate = useNavigate()

  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  const fetchScans = async () => {
    try {
      const res = await axios.get('http://localhost:8000/scanner/vuln-scans', { headers })
      setScans(res.data)
    } catch {
      navigate('/login')
    }
  }

  useEffect(() => {
    fetchScans()
    const hasRunning = scans.some(s => s.status === 'running' || s.status === 'pending')
    const interval = setInterval(fetchScans, hasRunning ? 3000 : 8000)
    return () => clearInterval(interval)
  }, [scans.length])

  // Live clock tick for elapsed timers
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])

  const handleLaunchScan = async () => {
    if (!target) return
    setLaunching(true)
    try {
      await axios.post('http://localhost:8000/scanner/vuln-scan', { target, scan_type: scanType }, { headers })
      setTarget('')
      fetchScans()
    } catch {
      alert('Error al lanzar el escaneo')
    }
    setLaunching(false)
  }

  const handleViewDetails = async (scan) => {
    try {
      const res = await axios.get(`http://localhost:8000/scanner/vuln-scans/${scan.id}`, { headers })
      setDetailData(res.data)
      setSelectedScan(scan)
    } catch {
      alert('Error al obtener detalles')
    }
  }

  const handleDelete = async (scanId) => {
    if (!window.confirm('¿Eliminar este escaneo?')) return
    try {
      await axios.delete(`http://localhost:8000/scanner/vuln-scans/${scanId}`, { headers })
      fetchScans()
    } catch {
      alert('Error al eliminar')
    }
  }

  const statusColor = (status) => {
    if (status === 'completed') return '#22c55e'
    if (status === 'error') return '#ef4444'
    if (status === 'running') return '#f59e0b'
    return '#94a3b8'
  }

  const statusLabel = (status) => {
    const labels = { pending: 'Pendiente', running: 'Escaneando...', completed: 'Completado', error: 'Error' }
    return labels[status] || status
  }

  const severityColor = (severity) => {
    if (severity === 'critical') return '#ef4444'
    if (severity === 'high') return '#f97316'
    if (severity === 'medium') return '#f59e0b'
    return '#22c55e'
  }

  const scanTypeLabel = (type) => {
    const labels = { full: 'Completo', network: 'Red (Nmap)', web: 'Web (Nikto)', ssl: 'SSL/TLS' }
    return labels[type] || type
  }

  const stageLabel = (stage) => {
    const labels = { starting: 'Iniciando...', nmap: 'Nmap (red)', nikto: 'Nikto (web)', ssl: 'SSLyze (TLS)', saving: 'Guardando...', done: 'Listo', error: 'Error' }
    return labels[stage] || stage || ''
  }

  const stageStep = (stage, scanType) => {
    const stageOrder = scanType === 'full' ? ['nmap', 'nikto', 'ssl'] :
      scanType === 'network' ? ['nmap'] : scanType === 'web' ? ['nikto'] : ['ssl']
    const idx = stageOrder.indexOf(stage)
    if (stage === 'saving' || stage === 'done') return { current: stageOrder.length, total: stageOrder.length }
    return { current: Math.max(0, idx) + 1, total: stageOrder.length }
  }

  const formatDuration = (seconds) => {
    if (seconds == null) return '-'
    const m = Math.floor(seconds / 60)
    const s = Math.floor(seconds % 60)
    return m > 0 ? `${m}m ${s}s` : `${s}s`
  }

  const getElapsed = (scan) => {
    if (scan.duration_seconds != null && scan.status === 'completed') return scan.duration_seconds
    if (scan.started_at) return (now - new Date(scan.started_at + 'Z').getTime()) / 1000
    if (scan.created_at) return (now - new Date(scan.created_at + 'Z').getTime()) / 1000
    return null
  }

  const totalVulns = scans.reduce((acc, s) => acc + (s.total_vulnerabilities || 0), 0)
  const completed = scans.filter(s => s.status === 'completed').length
  const running = scans.filter(s => s.status === 'running' || s.status === 'pending').length

  return (
    <div style={styles.container}>
      {/* Launch scan box */}
      <div style={styles.launchBox}>
        <h2 style={styles.launchTitle}>Escáner de Vulnerabilidades</h2>
        <p style={styles.launchDesc}>Ingresa una IP o dominio para escanear con Nmap, Nikto y SSLyze</p>
        <div style={styles.inputRow}>
          <input
            style={styles.input}
            type="text"
            placeholder="ejemplo.com o 192.168.1.1"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLaunchScan()}
          />
          <select style={styles.select} value={scanType} onChange={e => setScanType(e.target.value)}>
            <option value="full">Completo (Nmap + Nikto + SSL)</option>
            <option value="network">Solo Red (Nmap)</option>
            <option value="web">Solo Web (Nikto)</option>
            <option value="ssl">Solo SSL/TLS</option>
          </select>
          <button style={styles.launchBtn} onClick={handleLaunchScan} disabled={launching}>
            {launching ? 'Lanzando...' : 'Escanear'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={styles.statsRow}>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Escaneos totales</p>
          <p style={styles.statValue}>{scans.length}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Completados</p>
          <p style={{ ...styles.statValue, color: '#22c55e' }}>{completed}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>En progreso</p>
          <p style={{ ...styles.statValue, color: '#f59e0b' }}>{running}</p>
        </div>
        <div style={styles.statCard}>
          <p style={styles.statLabel}>Vulnerabilidades</p>
          <p style={{ ...styles.statValue, color: totalVulns > 0 ? '#ef4444' : '#22c55e' }}>{totalVulns}</p>
        </div>
      </div>

      {/* Scans table */}
      {scans.length === 0 ? (
        <p style={styles.empty}>No hay escaneos aún. Lanza tu primer escaneo arriba.</p>
      ) : (
        <div style={styles.table}>
          <div style={styles.tableHeader}>
            <span>Objetivo</span>
            <span>Tipo</span>
            <span>Estado / Progreso</span>
            <span>Vulnerabilidades</span>
            <span>Tiempo</span>
            <span>Acciones</span>
          </div>
          {scans.map(scan => {
            const elapsed = getElapsed(scan)
            const isActive = scan.status === 'running' || scan.status === 'pending'
            const step = scan.current_stage ? stageStep(scan.current_stage, scan.scan_type) : null
            return (
            <div key={scan.id} style={styles.tableRow}>
              <span style={styles.target}>{scan.target}</span>
              <span style={styles.badge}>{scanTypeLabel(scan.scan_type)}</span>
              <span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {isActive && <span style={styles.pulse} />}
                  <span style={{ color: statusColor(scan.status), fontWeight: 500 }}>
                    {statusLabel(scan.status)}
                  </span>
                </div>
                {isActive && scan.current_stage && (
                  <div style={{ marginTop: '4px' }}>
                    <div style={{ color: '#94a3b8', fontSize: '11px', marginBottom: '3px' }}>
                      {stageLabel(scan.current_stage)} {step && `(${step.current}/${step.total})`}
                    </div>
                    {step && (
                      <div style={{ background: '#1e293b', borderRadius: '4px', height: '4px', width: '100%', overflow: 'hidden' }}>
                        <div style={{ background: '#8b5cf6', height: '100%', width: `${(step.current / step.total) * 100}%`, borderRadius: '4px', transition: 'width 0.5s ease' }} />
                      </div>
                    )}
                  </div>
                )}
              </span>
              <span style={{ color: scan.total_vulnerabilities > 0 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                {scan.total_vulnerabilities ?? '-'}
              </span>
              <span style={{ color: isActive ? '#f59e0b' : '#64748b', fontSize: '13px', fontVariantNumeric: 'tabular-nums' }}>
                {isActive ? (
                  <span>{formatDuration(elapsed)} ⏱</span>
                ) : scan.status === 'completed' ? (
                  <span>{formatDuration(scan.duration_seconds)}</span>
                ) : '-'}
              </span>
              <span style={{ display: 'flex', gap: '8px' }}>
                {scan.status === 'completed' && (
                  <button style={styles.actionBtn} onClick={() => handleViewDetails(scan)}>Ver detalles</button>
                )}
                <button style={{ ...styles.actionBtn, color: '#ef4444' }} onClick={() => handleDelete(scan.id)}>Eliminar</button>
              </span>
            </div>
            )
          })}
        </div>
      )}

      {/* Detail Modal */}
      {detailData && (
        <div style={styles.modalOverlay} onClick={() => { setDetailData(null); setSelectedScan(null) }}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <div>
                <h3 style={styles.modalTitle}>Resultados — {detailData.target}</h3>
                <p style={{ color: '#64748b', fontSize: '12px', margin: '4px 0 0' }}>
                  Tipo: {scanTypeLabel(detailData.scan_type)} · {detailData.total_vulnerabilities} vulnerabilidades
                  {detailData.duration_seconds != null && ` · Duración: ${formatDuration(detailData.duration_seconds)}`}
                </p>
              </div>
              <button style={styles.closeBtn} onClick={() => { setDetailData(null); setSelectedScan(null) }}>✕</button>
            </div>

            {/* Summary by severity */}
            <div style={styles.severitySummary}>
              {['critical', 'high', 'medium', 'low'].map(sev => {
                const count = detailData.vulnerabilities?.filter(v => v.severity === sev).length || 0
                return (
                  <div key={sev} style={{ ...styles.sevBadge, borderColor: severityColor(sev) }}>
                    <span style={{ color: severityColor(sev), fontWeight: 700, fontSize: '18px' }}>{count}</span>
                    <span style={{ color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase' }}>{sev}</span>
                  </div>
                )
              })}
            </div>

            {/* Vulnerability list */}
            {detailData.vulnerabilities?.length > 0 ? (
              detailData.vulnerabilities.map((v, i) => (
                <div key={i} style={{ ...styles.vulnCard, borderLeftColor: severityColor(v.severity) }}>
                  <div style={styles.vulnHeader}>
                    <span style={styles.vulnTitle}>{v.title}</span>
                    <span style={{ color: severityColor(v.severity), fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>
                      {v.severity}
                    </span>
                  </div>
                  <p style={styles.vulnDesc}>{v.description}</p>
                  <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    {v.port && <span style={styles.vulnMeta}>Puerto: {v.port}</span>}
                    {v.cve && <span style={{ ...styles.vulnMeta, color: '#ef4444' }}>{v.cve}</span>}
                    {v.osvdb && <span style={styles.vulnMeta}>OSVDB-{v.osvdb}</span>}
                  </div>
                </div>
              ))
            ) : (
              <p style={{ color: '#22c55e', textAlign: 'center', padding: '2rem' }}>
                No se encontraron vulnerabilidades.
              </p>
            )}

            {/* Nmap raw results section */}
            {detailData.nmap_results && (
              <details style={styles.rawSection}>
                <summary style={styles.rawSummary}>Resultados Nmap (raw)</summary>
                <div style={styles.rawContent}>
                  {detailData.nmap_results.open_ports?.length > 0 && (
                    <div>
                      <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '6px' }}>Puertos abiertos:</p>
                      {detailData.nmap_results.open_ports.map((p, i) => (
                        <span key={i} style={styles.portBadge}>{p.port}/{p.protocol} — {p.service}</span>
                      ))}
                    </div>
                  )}
                  {detailData.nmap_results.os_detection && (
                    <p style={{ color: '#94a3b8', fontSize: '13px', marginTop: '8px' }}>
                      SO detectado: <span style={{ color: '#f1f5f9' }}>{detailData.nmap_results.os_detection}</span>
                    </p>
                  )}
                </div>
              </details>
            )}

            {/* SSL results section */}
            {detailData.ssl_results?.tls_info && (
              <details style={styles.rawSection}>
                <summary style={styles.rawSummary}>Información SSL/TLS</summary>
                <div style={styles.rawContent}>
                  <p style={{ color: '#94a3b8', fontSize: '13px' }}>
                    TLS 1.2: <span style={{ color: detailData.ssl_results.tls_info.tls_1_2 ? '#22c55e' : '#ef4444' }}>
                      {detailData.ssl_results.tls_info.tls_1_2 ? 'Soportado' : 'No soportado'}
                    </span>
                  </p>
                  <p style={{ color: '#94a3b8', fontSize: '13px' }}>
                    TLS 1.3: <span style={{ color: detailData.ssl_results.tls_info.tls_1_3 ? '#22c55e' : '#f59e0b' }}>
                      {detailData.ssl_results.tls_info.tls_1_3 ? 'Soportado' : 'No soportado'}
                    </span>
                  </p>
                  {detailData.ssl_results.tls_info.cert_expires && (
                    <p style={{ color: '#94a3b8', fontSize: '13px' }}>
                      Certificado expira: <span style={{ color: '#f1f5f9' }}>
                        {new Date(detailData.ssl_results.tls_info.cert_expires).toLocaleDateString()}
                      </span>
                    </p>
                  )}
                </div>
              </details>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

const styles = {
  container: { minHeight: '100vh', background: '#0b1120', padding: '2rem', color: '#f1f5f9' },
  launchBox: { background: '#0f172a', border: '1px solid #1e293b', padding: '1.5rem', borderRadius: '12px', marginBottom: '1.5rem', textAlign: 'center' },
  launchTitle: { color: '#f1f5f9', margin: '0 0 6px', fontSize: '20px' },
  launchDesc: { color: '#64748b', fontSize: '14px', margin: '0 0 1rem' },
  inputRow: { display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' },
  input: { padding: '10px 14px', background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#f1f5f9', fontSize: '14px', width: '280px', outline: 'none' },
  select: { padding: '10px 12px', background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#f1f5f9', fontSize: '13px', outline: 'none' },
  launchBtn: { padding: '10px 24px', background: '#8b5cf6', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '14px', cursor: 'pointer', fontWeight: 600 },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' },
  statCard: { background: '#0f172a', border: '1px solid #1e293b', padding: '1rem', borderRadius: '10px', textAlign: 'center' },
  statLabel: { color: '#64748b', fontSize: '13px', margin: '0 0 4px' },
  statValue: { color: '#f1f5f9', fontSize: '28px', fontWeight: 600, margin: 0 },
  empty: { color: '#94a3b8', textAlign: 'center', marginTop: '2rem' },
  table: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', overflow: 'hidden' },
  tableHeader: { display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1.5fr 1.5fr', padding: '12px 16px', background: '#1e293b', color: '#64748b', fontSize: '13px', fontWeight: 500 },
  tableRow: { display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1.5fr 1.5fr', padding: '12px 16px', borderTop: '1px solid #1e293b', fontSize: '14px', alignItems: 'center' },
  target: { color: '#f1f5f9', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  badge: { background: '#1e293b', color: '#94a3b8', padding: '3px 10px', borderRadius: '20px', fontSize: '12px', width: 'fit-content' },
  pulse: { display: 'inline-block', width: '8px', height: '8px', background: '#f59e0b', borderRadius: '50%', marginRight: '6px', animation: 'pulse 1.5s infinite' },
  actionBtn: { background: 'none', border: 'none', color: '#3b82f6', cursor: 'pointer', fontSize: '12px', padding: '4px 8px' },
  modalOverlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
  modal: { background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem', width: '700px', maxHeight: '85vh', overflowY: 'auto' },
  modalHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' },
  modalTitle: { color: '#f1f5f9', margin: 0, fontSize: '16px' },
  closeBtn: { background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '18px', cursor: 'pointer' },
  severitySummary: { display: 'flex', gap: '12px', marginBottom: '1.5rem', justifyContent: 'center' },
  sevBadge: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px', padding: '12px 20px', background: '#1e293b', borderRadius: '10px', borderBottom: '3px solid' },
  vulnCard: { background: '#1e293b', borderRadius: '8px', padding: '1rem', marginBottom: '10px', borderLeft: '3px solid #64748b' },
  vulnHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' },
  vulnTitle: { color: '#f1f5f9', fontWeight: 500, fontSize: '14px' },
  vulnDesc: { color: '#94a3b8', fontSize: '13px', margin: '4px 0 8px' },
  vulnMeta: { color: '#64748b', fontSize: '12px', background: '#0f172a', padding: '2px 8px', borderRadius: '4px' },
  rawSection: { marginTop: '12px', background: '#1e293b', borderRadius: '8px', padding: '12px' },
  rawSummary: { color: '#94a3b8', fontSize: '13px', cursor: 'pointer', fontWeight: 500 },
  rawContent: { marginTop: '10px', padding: '10px', background: '#0f172a', borderRadius: '6px' },
  portBadge: { display: 'inline-block', background: 'rgba(59,130,246,0.1)', color: '#60a5fa', padding: '3px 10px', borderRadius: '4px', fontSize: '12px', margin: '3px' },
}
