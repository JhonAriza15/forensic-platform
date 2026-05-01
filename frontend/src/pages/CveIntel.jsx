import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

// ─────────────────────────────────────────────
// Configuración de las tres fuentes
// ─────────────────────────────────────────────
const SOURCES = {
  nvd: {
    key:      'nvd',
    label:    'NVD',
    fullName: 'National Vulnerability Database',
    org:      'NIST',
    color:    '#3b82f6',
    bg:       'rgba(59,130,246,0.12)',
    border:   'rgba(59,130,246,0.4)',
    url:      'https://nvd.nist.gov',
    desc:     'Fuente principal de NIST que enriquece los CVEs con análisis, severidad CVSS y enlaces a parches.',
  },
  mitre: {
    key:      'mitre',
    label:    'MITRE CVE',
    fullName: 'Diccionario Oficial CVE',
    org:      'MITRE / cve.org',
    color:    '#a855f7',
    bg:       'rgba(168,85,247,0.12)',
    border:   'rgba(168,85,247,0.4)',
    url:      'https://cve.mitre.org',
    desc:     'Diccionario oficial que lista las vulnerabilidades públicamente conocidas asignadas por MITRE.',
  },
  cisa: {
    key:      'cisa',
    label:    'CISA KEV',
    fullName: 'Known Exploited Vulnerabilities',
    org:      'CISA (EEUU)',
    color:    '#ef4444',
    bg:       'rgba(239,68,68,0.12)',
    border:   'rgba(239,68,68,0.4)',
    url:      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    desc:     'Catálogo de vulnerabilidades activamente explotadas por atacantes reales. Requiere acción inmediata.',
  },
}

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#22c55e',
  NONE:     '#94a3b8',
}

const API_BASE = ''

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—'
  return iso.replace('T', ' ').slice(0, 16) + ' UTC'
}

function severityBadge(sev) {
  const color = SEVERITY_COLORS[(sev || '').toUpperCase()] || '#94a3b8'
  return (
    <span style={{
      background: `${color}22`,
      color,
      border:     `1px solid ${color}55`,
      borderRadius: 4,
      padding:    '2px 8px',
      fontSize:   11,
      fontWeight: 700,
      letterSpacing: 1,
    }}>
      {(sev || 'N/A').toUpperCase()}
    </span>
  )
}

function sourceBadge(src) {
  const s = SOURCES[src]
  return (
    <span style={{
      background:   s.bg,
      color:        s.color,
      border:       `1px solid ${s.border}`,
      borderRadius: 4,
      padding:      '2px 10px',
      fontSize:     11,
      fontWeight:   700,
      letterSpacing: 0.5,
    }}>
      {s.label}
    </span>
  )
}

function ransomwareBadge(val) {
  const isKnown = (val || '').toLowerCase() === 'known'
  return (
    <span style={{
      background: isKnown ? 'rgba(239,68,68,0.15)' : 'rgba(148,163,184,0.1)',
      color:      isKnown ? '#ef4444' : '#94a3b8',
      border:     `1px solid ${isKnown ? '#ef444455' : '#94a3b822'}`,
      borderRadius: 4,
      padding:    '2px 8px',
      fontSize:   11,
      fontWeight: 600,
    }}>
      {isKnown ? '⚠ Ransomware' : 'Sin ransomware'}
    </span>
  )
}

// ─────────────────────────────────────────────
// Componente principal
// ─────────────────────────────────────────────
export default function CveIntel() {
  const [activeSource, setActiveSource]     = useState('nvd')
  const [data,         setData]             = useState(null)
  const [loading,      setLoading]          = useState(false)
  const [error,        setError]            = useState(null)
  const [expanded,     setExpanded]         = useState(null)
  const [year,         setYear]             = useState(new Date().getFullYear())
  const [limit,        setLimit]            = useState(20)
  const [userRole,     setUserRole]         = useState('Analista')
  const [summaryCache, setSummaryCache]     = useState({})
  const navigate = useNavigate()

  const token   = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  // Años disponibles (1999 – año actual)
  const currentYear = new Date().getFullYear()
  const years = Array.from({ length: currentYear - 1998 }, (_, i) => currentYear - i)

  // ── Cargar resumen del caché al montar ──
  useEffect(() => {
    axios.get(`${API_BASE}/cve-intel/summary`, { headers })
      .then(r => {
        setSummaryCache(r.data.sources || {})
        setUserRole(r.data.user_role || 'Analista')
      })
      .catch(() => {})
  }, [])

  // ── Consultar fuente activa ──
  const fetchSource = useCallback(async (forceRefresh = false) => {
    setLoading(true)
    setError(null)
    setExpanded(null)
    try {
      let url = ''
      if (activeSource === 'nvd')   url = `${API_BASE}/cve-intel/nvd?year=${year}&limit=${limit}&force_refresh=${forceRefresh}`
      if (activeSource === 'mitre') url = `${API_BASE}/cve-intel/mitre?limit=${limit}&force_refresh=${forceRefresh}`
      if (activeSource === 'cisa')  url = `${API_BASE}/cve-intel/cisa?force_refresh=${forceRefresh}`
      const res = await axios.get(url, { headers })
      setData(res.data)
      setUserRole(res.data.user_role || userRole)
      // Refrescar summary
      const s = await axios.get(`${API_BASE}/cve-intel/summary`, { headers })
      setSummaryCache(s.data.sources || {})
    } catch (e) {
      if (e.response?.status === 401) navigate('/login')
      else setError(e.response?.data?.detail || 'Error al conectar con la API')
    }
    setLoading(false)
  }, [activeSource, year, limit])

  useEffect(() => { fetchSource() }, [fetchSource])

  const toggleExpand = (id) => setExpanded(prev => prev === id ? null : id)

  // ─────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────
  const src = SOURCES[activeSource]

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>

      {/* ── Encabezado ── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>
            Inteligencia CVE
          </h1>
          {/* Badge de rol */}
          <span style={{
            background: userRole === 'Administrador' ? 'rgba(234,179,8,0.15)' : 'rgba(59,130,246,0.12)',
            color:      userRole === 'Administrador' ? '#eab308' : '#60a5fa',
            border:     `1px solid ${userRole === 'Administrador' ? '#eab30844' : '#3b82f644'}`,
            borderRadius: 4,
            padding:    '3px 10px',
            fontSize:   11,
            fontWeight: 700,
            letterSpacing: 0.5,
          }}>
            {userRole === 'Administrador' ? '★ ' : ''}ROL: {userRole.toUpperCase()}
          </span>
        </div>
        <p style={{ margin: 0, color: '#94a3b8', fontSize: 14 }}>
          Consulta en tiempo real las últimas vulnerabilidades de las tres fuentes oficiales.
          {userRole === 'Administrador' && (
            <span style={{ color: '#eab308', marginLeft: 8 }}>
              Como administrador puedes forzar la actualización del caché.
            </span>
          )}
        </p>
      </div>

      {/* ── Tarjetas de fuente (selector) ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 24 }}>
        {Object.values(SOURCES).map(s => {
          const isActive = activeSource === s.key
          const cache    = summaryCache[s.key]
          return (
            <div
              key={s.key}
              onClick={() => setActiveSource(s.key)}
              style={{
                background:   isActive ? s.bg : 'rgba(30,41,59,0.6)',
                border:       `2px solid ${isActive ? s.border : 'rgba(51,65,85,0.6)'}`,
                borderRadius: 10,
                padding:      '14px 16px',
                cursor:       'pointer',
                transition:   'all 0.18s ease',
                userSelect:   'none',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                <div>
                  <span style={{ fontSize: 13, fontWeight: 700, color: isActive ? s.color : '#cbd5e1' }}>
                    {s.label}
                  </span>
                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{s.org}</div>
                </div>
                {isActive && (
                  <span style={{
                    background: s.color + '22',
                    color: s.color,
                    border: `1px solid ${s.color}55`,
                    borderRadius: 4,
                    padding: '1px 7px',
                    fontSize: 10,
                    fontWeight: 700,
                  }}>
                    ACTIVO
                  </span>
                )}
              </div>
              {/* Info de versión del caché */}
              {cache ? (
                <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
                  {s.key === 'nvd' && (
                    <>
                      <div>API v{cache.api_version} · Año {cache.year_queried}</div>
                      <div style={{ color: '#64748b' }}>Caché: {Math.floor(cache.cache_age_s / 60)} min atrás</div>
                    </>
                  )}
                  {s.key === 'mitre' && (
                    <>
                      <div>Versión: <span style={{ color: s.color }}>{cache.catalog_version}</span></div>
                      <div style={{ color: '#64748b' }}>Publicado: {cache.version_date}</div>
                    </>
                  )}
                  {s.key === 'cisa' && (
                    <>
                      <div>Versión: <span style={{ color: s.color }}>{cache.catalog_version}</span></div>
                      <div style={{ color: '#64748b' }}>{cache.total_count?.toLocaleString()} vulnerabilidades</div>
                    </>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>Sin datos en caché</div>
              )}
            </div>
          )
        })}
      </div>

      {/* ── Panel de controles ── */}
      <div style={{
        background: 'rgba(30,41,59,0.5)',
        border:     '1px solid rgba(51,65,85,0.5)',
        borderRadius: 10,
        padding:    '14px 20px',
        marginBottom: 20,
        display:    'flex',
        gap:        16,
        alignItems: 'center',
        flexWrap:   'wrap',
      }}>
        {/* Selector de fuente (texto) */}
        <div style={{ fontSize: 13, color: '#94a3b8' }}>
          Fuente: <span style={{ color: src.color, fontWeight: 700 }}>{src.fullName}</span>
          <span style={{ color: '#475569', marginLeft: 6 }}>({src.org})</span>
        </div>

        {/* Año – solo NVD */}
        {activeSource === 'nvd' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ fontSize: 12, color: '#94a3b8' }}>Año:</label>
            <select
              value={year}
              onChange={e => setYear(Number(e.target.value))}
              style={selectStyle}
            >
              {years.map(y => <option key={y} value={y}>{y}</option>)}
            </select>
          </div>
        )}

        {/* Límite – NVD y MITRE */}
        {activeSource !== 'cisa' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ fontSize: 12, color: '#94a3b8' }}>Mostrar:</label>
            <select
              value={limit}
              onChange={e => setLimit(Number(e.target.value))}
              style={selectStyle}
            >
              {[10, 20, 30, 50].map(l => (
                <option key={l} value={l}>{l} resultados</option>
              ))}
            </select>
          </div>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
          {/* Botón refrescar (admin only) */}
          {userRole === 'Administrador' && (
            <button
              onClick={() => fetchSource(true)}
              disabled={loading}
              style={{
                ...btnStyle,
                background: 'rgba(234,179,8,0.15)',
                color:      '#eab308',
                border:     '1px solid rgba(234,179,8,0.4)',
              }}
            >
              ↻ Forzar actualización
            </button>
          )}
          {/* Botón consultar */}
          <button
            onClick={() => fetchSource(false)}
            disabled={loading}
            style={{
              ...btnStyle,
              background: src.bg,
              color:      src.color,
              border:     `1px solid ${src.border}`,
            }}
          >
            {loading ? 'Consultando…' : '⟳ Actualizar'}
          </button>
        </div>
      </div>

      {/* ── Info de versión (datos cargados) ── */}
      {data && !loading && (
        <VersionCard data={data} src={src} />
      )}

      {/* ── Error ── */}
      {error && (
        <div style={{
          background: 'rgba(239,68,68,0.1)',
          border: '1px solid rgba(239,68,68,0.4)',
          borderRadius: 8,
          padding: '12px 16px',
          color: '#ef4444',
          marginBottom: 16,
          fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* ── Spinner ── */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#64748b' }}>
          <div style={{ fontSize: 28, marginBottom: 10 }}>⟳</div>
          <div style={{ fontSize: 14 }}>Consultando {src.fullName}…</div>
          <div style={{ fontSize: 12, marginTop: 4, color: '#475569' }}>Esto puede tardar unos segundos</div>
        </div>
      )}

      {/* ── Tabla de resultados ── */}
      {!loading && data && data.vulnerabilities?.length > 0 && (
        <div>
          {activeSource === 'nvd'   && <NvdTable vulns={data.vulnerabilities} expanded={expanded} onToggle={toggleExpand} />}
          {activeSource === 'mitre' && <MitreTable vulns={data.vulnerabilities} expanded={expanded} onToggle={toggleExpand} />}
          {activeSource === 'cisa'  && <CisaTable vulns={data.vulnerabilities} expanded={expanded} onToggle={toggleExpand} />}
        </div>
      )}

      {!loading && data && data.vulnerabilities?.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#64748b', fontSize: 14 }}>
          No se encontraron vulnerabilidades para los criterios seleccionados.
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────
// Tarjeta de versión / metadatos de la fuente
// ─────────────────────────────────────────────
function VersionCard({ data, src }) {
  return (
    <div style={{
      background:   src.bg,
      border:       `1px solid ${src.border}`,
      borderRadius: 10,
      padding:      '14px 20px',
      marginBottom: 16,
      display:      'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
      gap:          14,
    }}>
      <MetaItem label="Fuente" value={
        <a href={src.url} target="_blank" rel="noreferrer" style={{ color: src.color, textDecoration: 'none' }}>
          {src.fullName} ↗
        </a>
      } />

      {/* NVD */}
      {data.source === 'NVD' && <>
        <MetaItem label="Versión API"     value={`v${data.api_version}`} />
        <MetaItem label="Año consultado"  value={data.year_queried} />
        <MetaItem label="Total en año"    value={data.total_results?.toLocaleString()} />
        <MetaItem label="Mostrando"       value={`${data.results_shown} de ${data.total_results?.toLocaleString()}`} />
        <MetaItem label="Timestamp NVD"   value={data.timestamp ? data.timestamp.slice(0, 16).replace('T', ' ') + ' UTC' : '—'} />
      </>}

      {/* MITRE */}
      {data.source === 'MITRE' && <>
        <MetaItem label="Versión catálogo" value={
          data.release_url
            ? <a href={data.release_url} target="_blank" rel="noreferrer" style={{ color: src.color, textDecoration: 'none' }}>
                {data.catalog_version} ↗
              </a>
            : data.catalog_version
        } />
        <MetaItem label="Fecha de versión"  value={data.version_date} />
        <MetaItem label="Año consultado"    value={data.year_queried} />
        <MetaItem label="Total en año"      value={data.total_results?.toLocaleString()} />
        <MetaItem label="Mostrando"         value={`${data.results_shown}`} />
      </>}

      {/* CISA */}
      {data.source === 'CISA' && <>
        <MetaItem label="Versión catálogo" value={data.catalog_version} />
        <MetaItem label="Fecha publicación" value={data.date_released ? data.date_released.slice(0, 10) : '—'} />
        <MetaItem label="Total KEV"         value={data.total_count?.toLocaleString()} />
        <MetaItem label="Mostrando (recientes)" value={data.results_shown} />
      </>}

      {/* Caché */}
      <MetaItem
        label="Caché"
        value={
          data.cached
            ? `Sí (${Math.floor((data.cache_age_seconds || 0) / 60)} min atrás)`
            : 'Actualizado ahora'
        }
      />
    </div>
  )
}

function MetaItem({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>{value ?? '—'}</div>
    </div>
  )
}

// ─────────────────────────────────────────────
// Tabla NVD
// ─────────────────────────────────────────────
function NvdTable({ vulns, expanded, onToggle }) {
  return (
    <div style={tableWrap}>
      <table style={tableStyle}>
        <thead>
          <tr>
            {['CVE ID', 'Publicado', 'CVSS', 'Severidad', 'Descripción (resumen)', ''].map(h => (
              <th key={h} style={thStyle}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => (
            <>
              <tr key={v.id} onClick={() => onToggle(v.id)} style={trStyle(expanded === v.id)}>
                <td style={tdStyle}>
                  <a href={v.url} target="_blank" rel="noreferrer" style={{ color: '#60a5fa', textDecoration: 'none', fontFamily: 'monospace', fontSize: 12 }}
                     onClick={e => e.stopPropagation()}>
                    {v.id}
                  </a>
                </td>
                <td style={{ ...tdStyle, fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap' }}>{v.published?.slice(0, 10)}</td>
                <td style={{ ...tdStyle, fontWeight: 700, color: v.cvss_score >= 9 ? '#ef4444' : v.cvss_score >= 7 ? '#f97316' : v.cvss_score >= 4 ? '#f59e0b' : '#22c55e' }}>
                  {v.cvss_score ?? '—'}
                </td>
                <td style={tdStyle}>{severityBadge(v.severity)}</td>
                <td style={{ ...tdStyle, maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12, color: '#cbd5e1' }}>
                  {v.description}
                </td>
                <td style={{ ...tdStyle, color: '#64748b', fontSize: 12 }}>
                  {expanded === v.id ? '▲' : '▼'}
                </td>
              </tr>
              {expanded === v.id && (
                <tr key={v.id + '_exp'}>
                  <td colSpan={6} style={{ background: 'rgba(59,130,246,0.06)', padding: '12px 16px', border: 'none', borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: 12 }}>
                      <b style={{ color: '#94a3b8' }}>Descripción:</b>
                      <span style={{ color: '#e2e8f0' }}>{v.description}</span>
                      <b style={{ color: '#94a3b8' }}>Última modificación:</b>
                      <span style={{ color: '#e2e8f0' }}>{fmtDate(v.lastModified)}</span>
                      <b style={{ color: '#94a3b8' }}>CVSS Vector:</b>
                      <span style={{ color: '#e2e8f0', fontFamily: 'monospace', fontSize: 11 }}>{v.cvss_vector || '—'}</span>
                      <b style={{ color: '#94a3b8' }}>Fuente:</b>
                      <a href={v.url} target="_blank" rel="noreferrer" style={{ color: '#60a5fa' }}>{v.url}</a>
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─────────────────────────────────────────────
// Tabla MITRE CVE
// ─────────────────────────────────────────────
function MitreTable({ vulns, expanded, onToggle }) {
  return (
    <div style={tableWrap}>
      <table style={tableStyle}>
        <thead>
          <tr>
            {['CVE ID', 'Publicado', 'Última modificación', 'Descripción (resumen)', ''].map(h => (
              <th key={h} style={thStyle}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => (
            <>
              <tr key={v.id} onClick={() => onToggle(v.id)} style={trStyle(expanded === v.id)}>
                <td style={tdStyle}>
                  <a href={v.url} target="_blank" rel="noreferrer" style={{ color: '#c084fc', textDecoration: 'none', fontFamily: 'monospace', fontSize: 12 }}
                     onClick={e => e.stopPropagation()}>
                    {v.id}
                  </a>
                </td>
                <td style={{ ...tdStyle, fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap' }}>{v.published?.slice(0, 10)}</td>
                <td style={{ ...tdStyle, fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap' }}>{v.lastModified?.slice(0, 10)}</td>
                <td style={{ ...tdStyle, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12, color: '#cbd5e1' }}>
                  {v.description}
                </td>
                <td style={{ ...tdStyle, color: '#64748b', fontSize: 12 }}>
                  {expanded === v.id ? '▲' : '▼'}
                </td>
              </tr>
              {expanded === v.id && (
                <tr key={v.id + '_exp'}>
                  <td colSpan={5} style={{ background: 'rgba(168,85,247,0.06)', padding: '12px 16px', border: 'none', borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: 12 }}>
                      <b style={{ color: '#94a3b8' }}>Descripción:</b>
                      <span style={{ color: '#e2e8f0' }}>{v.description}</span>
                      {v.references?.length > 0 && <>
                        <b style={{ color: '#94a3b8' }}>Referencias:</b>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                          {v.references.map((r, i) => (
                            <a key={i} href={r} target="_blank" rel="noreferrer" style={{ color: '#c084fc', fontSize: 11 }}>{r}</a>
                          ))}
                        </div>
                      </>}
                      <b style={{ color: '#94a3b8' }}>Registro oficial:</b>
                      <a href={v.url} target="_blank" rel="noreferrer" style={{ color: '#c084fc' }}>{v.url}</a>
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─────────────────────────────────────────────
// Tabla CISA KEV
// ─────────────────────────────────────────────
function CisaTable({ vulns, expanded, onToggle }) {
  return (
    <div style={tableWrap}>
      <table style={tableStyle}>
        <thead>
          <tr>
            {['CVE ID', 'Proveedor', 'Producto', 'Fecha agregado', 'Vencimiento', 'Ransomware', ''].map(h => (
              <th key={h} style={thStyle}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => (
            <>
              <tr key={v.id} onClick={() => onToggle(v.id)} style={trStyle(expanded === v.id)}>
                <td style={tdStyle}>
                  <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer"
                     style={{ color: '#f87171', textDecoration: 'none', fontFamily: 'monospace', fontSize: 12 }}
                     onClick={e => e.stopPropagation()}>
                    {v.id}
                  </a>
                </td>
                <td style={{ ...tdStyle, fontSize: 12, color: '#cbd5e1' }}>{v.vendor}</td>
                <td style={{ ...tdStyle, fontSize: 12, color: '#cbd5e1' }}>{v.product}</td>
                <td style={{ ...tdStyle, fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap' }}>{v.dateAdded}</td>
                <td style={{ ...tdStyle, fontSize: 11, color: '#f59e0b', whiteSpace: 'nowrap' }}>{v.dueDate}</td>
                <td style={tdStyle}>{ransomwareBadge(v.ransomware)}</td>
                <td style={{ ...tdStyle, color: '#64748b', fontSize: 12 }}>
                  {expanded === v.id ? '▲' : '▼'}
                </td>
              </tr>
              {expanded === v.id && (
                <tr key={v.id + '_exp'}>
                  <td colSpan={7} style={{ background: 'rgba(239,68,68,0.06)', padding: '12px 16px', border: 'none', borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: 12 }}>
                      <b style={{ color: '#94a3b8' }}>Nombre:</b>
                      <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{v.name}</span>
                      <b style={{ color: '#94a3b8' }}>Descripción:</b>
                      <span style={{ color: '#e2e8f0' }}>{v.description}</span>
                      <b style={{ color: '#94a3b8' }}>Acción requerida:</b>
                      <span style={{ color: '#fcd34d' }}>{v.action}</span>
                      <b style={{ color: '#94a3b8' }}>Catálogo CISA:</b>
                      <a href={v.url} target="_blank" rel="noreferrer" style={{ color: '#f87171' }}>{v.url}</a>
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─────────────────────────────────────────────
// Estilos reutilizables
// ─────────────────────────────────────────────
const tableWrap = {
  overflowX: 'auto',
  borderRadius: 10,
  border: '1px solid rgba(51,65,85,0.5)',
}

const tableStyle = {
  width: '100%',
  borderCollapse: 'collapse',
  background: 'rgba(15,23,42,0.7)',
  fontSize: 13,
}

const thStyle = {
  padding: '10px 14px',
  background: 'rgba(30,41,59,0.9)',
  color: '#64748b',
  fontWeight: 700,
  fontSize: 11,
  textTransform: 'uppercase',
  letterSpacing: 0.5,
  textAlign: 'left',
  borderBottom: '1px solid rgba(51,65,85,0.6)',
}

const tdStyle = {
  padding: '10px 14px',
  borderBottom: '1px solid rgba(30,41,59,0.8)',
  verticalAlign: 'middle',
}

const trStyle = (isExpanded) => ({
  cursor: 'pointer',
  background: isExpanded ? 'rgba(51,65,85,0.3)' : 'transparent',
  transition: 'background 0.15s',
})

const selectStyle = {
  background: 'rgba(15,23,42,0.8)',
  color: '#e2e8f0',
  border: '1px solid rgba(51,65,85,0.6)',
  borderRadius: 6,
  padding: '4px 8px',
  fontSize: 12,
  cursor: 'pointer',
}

const btnStyle = {
  padding: '6px 14px',
  borderRadius: 6,
  cursor: 'pointer',
  fontSize: 12,
  fontWeight: 600,
  transition: 'opacity 0.15s',
}
