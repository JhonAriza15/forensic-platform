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