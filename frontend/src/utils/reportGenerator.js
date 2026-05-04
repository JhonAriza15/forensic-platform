import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

const CWE_MAPPING = {
  brute_force: { cwe: 'CWE-307', name: 'Improper Restriction of Excessive Authentication Attempts' },
  privilege_escalation: { cwe: 'CWE-269', name: 'Improper Privilege Management' },
  malware_indicator: { cwe: 'CWE-506', name: 'Embedded Malicious Code' },
  unauthorized_access: { cwe: 'CWE-284', name: 'Improper Access Control' },
  suspicious_ip: { cwe: 'CWE-918', name: 'Server-Side Request Forgery' },
  unusual_hour: { cwe: 'CWE-862', name: 'Missing Authorization' },
  other: { cwe: 'CWE-400', name: 'Uncontrolled Resource Consumption' },
  configuration_change: { cwe: 'CWE-16', name: 'Configuration' },
}

const SEVERITY_COLORS = {
  critical: [239, 68, 68],
  high: [249, 115, 22],
  medium: [245, 158, 11],
  low: [34, 197, 94],
}

export function generateReport(logFile, findings) {
  const doc = new jsPDF()
  const pageWidth = doc.internal.pageSize.getWidth()
  const now = new Date()

  // Header
  doc.setFillColor(15, 23, 42)
  doc.rect(0, 0, pageWidth, 45, 'F')

  doc.setTextColor(255, 255, 255)
  doc.setFontSize(20)
  doc.setFont('helvetica', 'bold')
  doc.text('ForensiLog', 14, 18)

  doc.setFontSize(11)
  doc.setFont('helvetica', 'normal')
  doc.text('Informe Ejecutivo de Seguridad', 14, 28)

  doc.setFontSize(9)
  doc.setTextColor(148, 163, 184)
  doc.text(`Generado: ${now.toLocaleDateString('es-CO')} ${now.toLocaleTimeString('es-CO')}`, 14, 38)

  // Risk badge
  const riskColor = logFile.risk_level === 'CRÍTICO' ? [239, 68, 68] :
    logFile.risk_level === 'ALTO' ? [249, 115, 22] :
    logFile.risk_level === 'MEDIO' ? [245, 158, 11] : [34, 197, 94]

  doc.setFillColor(...riskColor)
  doc.roundedRect(pageWidth - 55, 10, 42, 25, 3, 3, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(16)
  doc.setFont('helvetica', 'bold')
  doc.text(`${logFile.risk_score || 0}%`, pageWidth - 44, 22)
  doc.setFontSize(8)
  doc.text(logFile.risk_level || 'BAJO', pageWidth - 44, 30)

  let y = 55

  // Resumen ejecutivo
  doc.setTextColor(30, 41, 59)
  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.text('Resumen Ejecutivo', 14, y)
  y += 8

  doc.setDrawColor(59, 130, 246)
  doc.setLineWidth(0.5)
  doc.line(14, y, pageWidth - 14, y)
  y += 8

  const summaryData = [
    ['Archivo analizado', logFile.original_filename],
    ['Total de eventos', String(logFile.events_extracted || 0)],
    ['Hallazgos detectados', String(findings.length)],
    ['Score de riesgo', `${logFile.risk_score || 0}% — ${logFile.risk_level || 'BAJO'}`],
    ['Fecha de análisis', new Date(logFile.processed_at || logFile.uploaded_at).toLocaleString('es-CO')],
  ]

  autoTable(doc, {
    startY: y,
    body: summaryData,
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 60, fillColor: [248, 250, 252], textColor: [51, 65, 85] },
      1: { textColor: [30, 41, 59] }
    },
    styles: { fontSize: 10, cellPadding: 4 },
    theme: 'plain',
    margin: { left: 14, right: 14 },
  })

  y = doc.lastAutoTable.finalY + 12

  // Estadísticas por severidad
  const criticos = findings.filter(f => f.severity === 'critical').length
  const altos = findings.filter(f => f.severity === 'high').length
  const medios = findings.filter(f => f.severity === 'medium').length
  const bajos = findings.filter(f => f.severity === 'low').length

  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(30, 41, 59)
  doc.text('Distribución de Hallazgos', 14, y)
  y += 8
  doc.setDrawColor(59, 130, 246)
  doc.line(14, y, pageWidth - 14, y)
  y += 6

  const severities = [
    { label: 'Crítico', count: criticos, color: [239, 68, 68] },
    { label: 'Alto', count: altos, color: [249, 115, 22] },
    { label: 'Medio', count: medios, color: [245, 158, 11] },
    { label: 'Bajo', count: bajos, color: [34, 197, 94] },
  ]

  const boxW = (pageWidth - 28 - 12) / 4
  severities.forEach((s, i) => {
    const x = 14 + i * (boxW + 4)
    doc.setFillColor(248, 250, 252)
    doc.roundedRect(x, y, boxW, 22, 2, 2, 'F')
    doc.setFillColor(...s.color)
    doc.roundedRect(x, y, 4, 22, 1, 1, 'F')
    doc.setFontSize(16)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(...s.color)
    doc.text(String(s.count), x + boxW / 2, y + 11, { align: 'center' })
    doc.setFontSize(8)
    doc.setTextColor(100, 116, 139)
    doc.text(s.label, x + boxW / 2, y + 18, { align: 'center' })
  })

  y += 30

  // Tabla de hallazgos
  doc.setFontSize(13)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(30, 41, 59)
  doc.text('Detalle de Hallazgos', 14, y)
  y += 8
  doc.setDrawColor(59, 130, 246)
  doc.line(14, y, pageWidth - 14, y)
  y += 4

  if (findings.length === 0) {
    doc.setFontSize(10)
    doc.setTextColor(100, 116, 139)
    doc.text('No se detectaron hallazgos en este análisis.', 14, y + 8)
    y += 20
  } else {
    autoTable(doc, {
      startY: y,
      head: [['#', 'Severidad', 'Hallazgo', 'CWE', 'Confianza']],
      body: findings.map((f, i) => [
        i + 1,
        f.severity.toUpperCase(),
        f.title,
        CWE_MAPPING[f.category]?.cwe || 'N/A',
        `${Math.round(f.confidence_score * 100)}%`
      ]),
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 9 },
      bodyStyles: { fontSize: 9, textColor: [30, 41, 59] },
      columnStyles: {
        0: { cellWidth: 10 },
        1: { cellWidth: 22 },
        2: { cellWidth: 90 },
        3: { cellWidth: 28 },
        4: { cellWidth: 20 },
      },
      didDrawCell: (data) => {
        if (data.column.index === 1 && data.section === 'body') {
          const severity = data.cell.raw.toLowerCase()
          const color = SEVERITY_COLORS[severity] || [100, 116, 139]
          doc.setTextColor(...color)
          doc.setFont('helvetica', 'bold')
          doc.text(data.cell.raw, data.cell.x + 2, data.cell.y + data.cell.height / 2 + 1)
          doc.setFont('helvetica', 'normal')
          doc.setTextColor(30, 41, 59)
          return false
        }
      },
      margin: { left: 14, right: 14 },
      theme: 'grid',
    })
    y = doc.lastAutoTable.finalY + 10
  }

  // Recomendaciones
  if (findings.length > 0) {
    if (y > 220) { doc.addPage(); y = 20 }

    doc.setFontSize(13)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(30, 41, 59)
    doc.text('Recomendaciones', 14, y)
    y += 8
    doc.setDrawColor(59, 130, 246)
    doc.line(14, y, pageWidth - 14, y)
    y += 6

    findings.filter(f => f.recommendation).slice(0, 5).forEach((f, i) => {
      if (y > 260) { doc.addPage(); y = 20 }
      const cwe = CWE_MAPPING[f.category]
      doc.setFillColor(248, 250, 252)
      doc.roundedRect(14, y, pageWidth - 28, 18, 2, 2, 'F')
      doc.setFontSize(9)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...(SEVERITY_COLORS[f.severity] || [100, 116, 139]))
      doc.text(`${i + 1}. [${f.severity.toUpperCase()}]`, 18, y + 7)
      doc.setTextColor(30, 41, 59)
      doc.text(f.title, 18 + 28, y + 7)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(100, 116, 139)
      doc.setFontSize(8)
      const rec = doc.splitTextToSize(`→ ${f.recommendation}${cwe ? ` (${cwe.cwe})` : ''}`, pageWidth - 36)
      doc.text(rec[0], 18, y + 14)
      y += 22
    })
  }

  // Footer
  const pageCount = doc.internal.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFillColor(15, 23, 42)
    doc.rect(0, doc.internal.pageSize.getHeight() - 12, pageWidth, 12, 'F')
    doc.setFontSize(7)
    doc.setTextColor(148, 163, 184)
    doc.text('ForensiLog — Plataforma de Análisis Forense de Seguridad', 14, doc.internal.pageSize.getHeight() - 4)
    doc.text(`Página ${i} de ${pageCount}`, pageWidth - 14, doc.internal.pageSize.getHeight() - 4, { align: 'right' })
  }

  doc.save(`informe_${logFile.original_filename}_${now.toISOString().slice(0, 10)}.pdf`)
}

// Extrae el titulo legible de una vulnerabilidad.
// Si el titulo ya viene enriquecido desde la BD (no es un CVE-ID ni el prefijo generico)
// lo devuelve directamente. De lo contrario intenta extraer resumen real.
function getVulnTitle(v) {
  const raw = (v.title || '').trim()

  // Caso 1: titulo es solo un CVE-ID ("CVE-2010-0382")
  const isBareCve = /^CVE-\d{4}-\d+$/i.test(raw)
  // Caso 2: titulo es el prefijo generico viejo ("Vulnerabilidad detectada: CVE-X")
  const isGenericPrefix = /^Vulnerabilidad detectada:\s*CVE-/i.test(raw)

  // Si ya tiene titulo real, devolverlo tal cual
  if (!isBareCve && !isGenericPrefix && raw.length > 0) return raw

  // Intentar extraer "Resumen NVD: <texto>" del campo description (datos enriquecidos al momento del escaneo)
  const desc = v.description || ''
  const nvdMatch = desc.match(/Resumen NVD:\s*(.+?)(\s*\||\s*--|$)/i)
  if (nvdMatch && nvdMatch[1].trim().length > 5) {
    const summary = nvdMatch[1].trim()
    return summary.length > 90 ? summary.slice(0, 87) + '...' : summary
  }

  // Fallback: el CVE-ID limpio
  const cveMatch = raw.match(/(CVE-\d{4}-\d+)/)
  return cveMatch ? cveMatch[1] : (raw || v.cve || '(sin titulo)')
}

// ─────────────────────────────────────────────────────────────────────────────
// Traducción en lote via backend (evita CORS del navegador)
// ─────────────────────────────────────────────────────────────────────────────
async function translateAll(texts, token) {
  if (!texts.length) return []
  try {
    const res = await fetch('/scanner/translate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ texts }),
    })
    if (!res.ok) return texts  // si falla, devolver originales
    const data = await res.json()
    return data.translations || texts
  } catch {
    return texts  // fallback: inglés
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Informe ejecutivo para escaneos de vulnerabilidades (VulnScanner)
// ─────────────────────────────────────────────────────────────────────────────
function parseDate(s) {
  if (!s) return '-'
  try {
    const normalized = s.toString().replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1')
    const withZ = normalized.includes('Z') || normalized.includes('+') ? normalized : normalized + 'Z'
    const d = new Date(withZ)
    return isNaN(d.getTime()) ? s.toString().slice(0, 19).replace('T', ' ') : d.toLocaleString('es-CO')
  } catch { return s }
}

const SEV_ES = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MEDIO', low: 'BAJO' }
const STATE_ES = { open: 'Abierto', closed: 'Cerrado', filtered: 'Filtrado' }

export async function generateVulnReport(scan, onProgress, token) {
  const doc = new jsPDF()
  const pw = doc.internal.pageSize.getWidth()
  const ph = doc.internal.pageSize.getHeight()
  const now = new Date()

  const vulns = scan.vulnerabilities || []
  const critical = vulns.filter(v => v.severity === 'critical').length
  const high     = vulns.filter(v => v.severity === 'high').length
  const medium   = vulns.filter(v => v.severity === 'medium').length
  const low      = vulns.filter(v => v.severity === 'low').length
  const total    = vulns.length

  // ── Traducir descripciones al español ──────────────────────────────────────
  if (onProgress) onProgress('Traduciendo al español...')
  const rawTitles = vulns.map(v => getVulnTitle(v))
  const translatedTitles = await translateAll(rawTitles, token)
  const titleMap = new Map(vulns.map((v, i) => [i, translatedTitles[i] || rawTitles[i]]))

  const riskLevel = critical > 0 ? 'CRÍTICO' : high > 5 ? 'ALTO' : high > 0 ? 'MEDIO' : 'BAJO'
  const riskColor = riskLevel === 'CRÍTICO' ? [239,68,68] : riskLevel === 'ALTO' ? [249,115,22] : riskLevel === 'MEDIO' ? [245,158,11] : [34,197,94]

  const scanTypeLabels = { full: 'Completo (Nmap + Nikto + SSL)', network: 'Red (Nmap)', web: 'Web (Nikto)', ssl: 'SSL/TLS' }
  const formatDur = (s) => { if (!s) return '-'; const m = Math.floor(s/60); return m > 0 ? `${m}m ${Math.floor(s%60)}s` : `${Math.floor(s)}s` }

  // ── HEADER ─────────────────────────────────────────────────────────────────
  doc.setFillColor(15, 23, 42)
  doc.rect(0, 0, pw, 48, 'F')

  doc.setFillColor(139, 92, 246)
  doc.rect(0, 44, pw, 4, 'F')

  doc.setTextColor(255, 255, 255)
  doc.setFontSize(22)
  doc.setFont('helvetica', 'bold')
  doc.text('ForensiLog', 14, 18)

  doc.setFontSize(11)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(148, 163, 184)
  doc.text('Informe Ejecutivo — Escaneo de Vulnerabilidades', 14, 29)

  doc.setFontSize(8)
  doc.text(`Generado: ${now.toLocaleDateString('es-CO')} ${now.toLocaleTimeString('es-CO')}`, 14, 39)

  // Badge de riesgo
  doc.setFillColor(...riskColor)
  doc.roundedRect(pw - 58, 8, 45, 28, 3, 3, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(18)
  doc.setFont('helvetica', 'bold')
  doc.text(riskLevel, pw - 36, 22, { align: 'center' })
  doc.setFontSize(8)
  doc.setFont('helvetica', 'normal')
  doc.text('Nivel de riesgo', pw - 36, 31, { align: 'center' })

  let y = 58

  // ── RESUMEN EJECUTIVO ──────────────────────────────────────────────────────
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(13)
  doc.setTextColor(30, 41, 59)
  doc.text('Resumen Ejecutivo', 14, y)
  y += 6
  doc.setDrawColor(139, 92, 246)
  doc.setLineWidth(0.5)
  doc.line(14, y, pw - 14, y)
  y += 4

  autoTable(doc, {
    startY: y,
    body: [
      ['Objetivo',          scan.target || '-'],
      ['Tipo de escaneo',   scanTypeLabels[scan.scan_type] || scan.scan_type || '-'],
      ['Total vulnerab.',   String(total)],
      ['Duracion',          formatDur(scan.duration_seconds)],
      ['Fecha de escaneo',  parseDate(scan.created_at)],
    ],
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 55, fillColor: [248,250,252], textColor: [51,65,85] },
      1: { textColor: [30,41,59] },
    },
    styles: { fontSize: 10, cellPadding: 4 },
    theme: 'plain',
    margin: { left: 14, right: 14 },
  })

  y = doc.lastAutoTable.finalY + 14

  // ── GRÁFICA DE BARRAS POR SEVERIDAD ───────────────────────────────────────
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(13)
  doc.setTextColor(30, 41, 59)
  doc.text('Distribucion por Severidad', 14, y)
  y += 6
  doc.setDrawColor(139, 92, 246)
  doc.line(14, y, pw - 14, y)
  y += 8

  const sevs = [
    { label: 'Critico', count: critical, color: [239,68,68] },
    { label: 'Alto',    count: high,     color: [249,115,22] },
    { label: 'Medio',   count: medium,   color: [245,158,11] },
    { label: 'Bajo',    count: low,      color: [34,197,94] },
  ]

  // Tarjetas de conteo
  const boxW = (pw - 28 - 9) / 4
  sevs.forEach((s, i) => {
    const x = 14 + i * (boxW + 3)
    doc.setFillColor(248, 250, 252)
    doc.roundedRect(x, y, boxW, 26, 2, 2, 'F')
    doc.setFillColor(...s.color)
    doc.roundedRect(x, y, boxW, 5, 1, 1, 'F')
    doc.setFontSize(20)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(...s.color)
    doc.text(String(s.count), x + boxW / 2, y + 18, { align: 'center' })
    doc.setFontSize(8)
    doc.setTextColor(100, 116, 139)
    doc.setFont('helvetica', 'normal')
    doc.text(s.label, x + boxW / 2, y + 23, { align: 'center' })
  })

  y += 34

  // Grafica de barras horizontales
  const maxCount = Math.max(...sevs.map(s => s.count), 1)
  const barAreaW = pw - 28 - 28
  const barH = 11
  const barGap = 6

  doc.setFontSize(8)
  sevs.forEach(s => {
    const barW = (s.count / maxCount) * barAreaW
    doc.setFillColor(230, 234, 240)
    doc.roundedRect(42, y, barAreaW, barH, 2, 2, 'F')
    if (s.count > 0) {
      doc.setFillColor(...s.color)
      doc.roundedRect(42, y, Math.max(barW, 4), barH, 2, 2, 'F')
    }
    doc.setTextColor(51, 65, 85)
    doc.setFont('helvetica', 'bold')
    doc.text(s.label, 40, y + 7.5, { align: 'right' })
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(30, 41, 59)
    doc.text(String(s.count), 42 + Math.max(barW, 4) + 3, y + 7.5)
    y += barH + barGap
  })

  y += 10

  // ── PUERTOS ABIERTOS ──────────────────────────────────────────────────────
  const openPorts = scan.nmap_results?.open_ports || []
  if (openPorts.length > 0) {
    if (y > ph - 60) { doc.addPage(); y = 20 }

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(30, 41, 59)
    doc.text('Puertos Abiertos Detectados', 14, y)
    y += 6
    doc.setDrawColor(139, 92, 246)
    doc.line(14, y, pw - 14, y)
    y += 4

    autoTable(doc, {
      startY: y,
      head: [['Puerto', 'Protocolo', 'Servicio', 'Estado']],
      body: openPorts.map(p => [
        String(p.port || '-'),
        p.protocol || 'tcp',
        p.service || '-',
        STATE_ES[p.state] || p.state || 'Abierto',
      ]),
      headStyles: { fillColor: [15,23,42], textColor: [255,255,255], fontSize: 9 },
      bodyStyles: { fontSize: 9, textColor: [30,41,59] },
      columnStyles: {
        0: { cellWidth: 22 },
        1: { cellWidth: 25 },
        2: { cellWidth: 80 },
        3: { cellWidth: 25 },
      },
      theme: 'grid',
      margin: { left: 14, right: 14 },
    })
    y = doc.lastAutoTable.finalY + 12
  }

  // ── TABLA DE VULNERABILIDADES ──────────────────────────────────────────────
  if (y > ph - 60) { doc.addPage(); y = 20 }

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(13)
  doc.setTextColor(30, 41, 59)
  doc.text('Detalle de Vulnerabilidades', 14, y)
  y += 6
  doc.setDrawColor(139, 92, 246)
  doc.line(14, y, pw - 14, y)
  y += 4

  if (total === 0) {
    doc.setFontSize(10)
    doc.setTextColor(34, 197, 94)
    doc.text('No se encontraron vulnerabilidades en este escaneo.', 14, y + 8)
    y += 18
  } else {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 }
    const sorted = [...vulns].sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4))

    autoTable(doc, {
      startY: y,
      head: [['#', 'Severidad', 'Descripcion', 'Puerto', 'CVE']],
      body: sorted.map((v, i) => [
        i + 1,
        SEV_ES[v.severity] || (v.severity || 'low').toUpperCase(),
        titleMap.get(vulns.indexOf(v)) || getVulnTitle(v),
        v.port ? String(v.port) : '-',
        v.cve || '-',
      ]),
      headStyles: { fillColor: [15,23,42], textColor: [255,255,255], fontSize: 9 },
      bodyStyles: { fontSize: 8, textColor: [30,41,59] },
      columnStyles: {
        0: { cellWidth: 10 },
        1: { cellWidth: 24 },
        2: { cellWidth: 100 },
        3: { cellWidth: 16 },
        4: { cellWidth: 32 },
      },
      didParseCell: (data) => {
        if (data.column.index === 1 && data.section === 'body') {
          const raw = (data.cell.raw || '').toLowerCase()
          // Mapear severidad en español al color correcto
          const sevKey = Object.keys(SEV_ES).find(k => SEV_ES[k] === data.cell.raw) || raw
          const c = SEVERITY_COLORS[sevKey] || [100, 116, 139]
          data.cell.styles.textColor = c
          data.cell.styles.fontStyle = 'bold'
        }
      },
      theme: 'grid',
      margin: { left: 14, right: 14 },
    })
    y = doc.lastAutoTable.finalY + 12
  }

  // ── RECOMENDACIONES ────────────────────────────────────────────────────────
  const withDesc = vulns.filter(v => v.description && v.severity !== 'low').slice(0, 5)
  if (withDesc.length > 0) {
    if (y > ph - 60) { doc.addPage(); y = 20 }

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(30, 41, 59)
    doc.text('Recomendaciones Prioritarias', 14, y)
    y += 6
    doc.setDrawColor(139, 92, 246)
    doc.line(14, y, pw - 14, y)
    y += 6

    const recGeneral = {
      critical: 'Parchar inmediatamente. Restringir acceso al servicio hasta resolver.',
      high:     'Actualizar a la version parcheada indicada en el aviso oficial del proveedor.',
      medium:   'Planificar actualizacion en el proximo ciclo de mantenimiento.',
      low:      'Revisar configuracion y aplicar hardening en la proxima ventana de cambios.',
    }

    withDesc.forEach((v, i) => {
      if (y > ph - 30) { doc.addPage(); y = 20 }
      const c = SEVERITY_COLORS[v.severity] || [100,116,139]
      const boxH = 20
      doc.setFillColor(248, 250, 252)
      doc.roundedRect(14, y, pw - 28, boxH, 2, 2, 'F')
      doc.setFillColor(...c)
      doc.roundedRect(14, y, 4, boxH, 1, 1, 'F')
      doc.setFontSize(8)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(...c)
      doc.text(`${i + 1}. [${(v.severity || '').toUpperCase()}]`, 22, y + 7)
      doc.setTextColor(30, 41, 59)
      const titleLines = doc.splitTextToSize(getVulnTitle(v), pw - 70)
      doc.text(titleLines[0], 22 + 32, y + 7)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(100, 116, 139)
      doc.setFontSize(7.5)
      const rec = doc.splitTextToSize(`→ ${recGeneral[v.severity] || ''}`, pw - 36)
      doc.text(rec[0], 22, y + 15)
      y += boxH + 4
    })
  }

  // ── FOOTER ─────────────────────────────────────────────────────────────────
  const pages = doc.internal.getNumberOfPages()
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i)
    doc.setFillColor(15, 23, 42)
    doc.rect(0, ph - 12, pw, 12, 'F')
    doc.setFontSize(7)
    doc.setTextColor(148, 163, 184)
    doc.text('ForensiLog — Informe de Escaneo de Vulnerabilidades', 14, ph - 4)
    doc.text(`Pagina ${i} de ${pages}`, pw - 14, ph - 4, { align: 'right' })
  }

  const safeTarget = (scan.target || 'scan').replace(/[^a-zA-Z0-9._-]/g, '_')
  doc.save(`vuln_report_${safeTarget}_${now.toISOString().slice(0, 10)}.pdf`)
}