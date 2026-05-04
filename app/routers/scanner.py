from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.routers.logs import get_current_user
from app.models.finding import Finding, FindingSeverity, FindingCategory
from app.models.scan import Scan, ScanStatus, ScanType, ScanVulnerability
from app.models.cve import CveData
import urllib.request
import ssl
import socket
import json
import re
import pika
import os
from datetime import datetime, timezone
import requests
import io
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Regex para detectar titulos que son solo CVE IDs (sin descripcion real)
_BARE_CVE_RE     = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
_GENERIC_TITLE_RE = re.compile(r'^Vulnerabilidad detectada:\s*CVE-', re.IGNORECASE)




router = APIRouter(prefix="/scanner", tags=["scanner"])

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy"
]


def check_url(url: str):
    if not url.startswith("http"):
        url = "https://" + url
    
    results = {
        "url": url,
        "reachable": False,
        "https": url.startswith("https"),
        "status_code": None,
        "response_time_ms": None,
        "headers": {},
        "missing_headers": [],
        "server": None,
        "tls_version": None,
        "findings": []
    }

    try:
        start = datetime.now(timezone.utc)
        ctx = ssl.create_default_context()
        
        req = urllib.request.Request(url, headers={"User-Agent": "ForensiLog-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx if url.startswith("https") else None) as response:
            end = datetime.now(timezone.utc)
            results["reachable"] = True
            results["status_code"] = response.status
            results["response_time_ms"] = int((end - start).total_seconds() * 1000)
            results["headers"] = dict(response.headers)
            results["server"] = response.headers.get("server", "No revelado")

        # Verificar headers de seguridad faltantes
        headers_lower = {k.lower(): v for k, v in results["headers"].items()}
        for h in SECURITY_HEADERS:
            if h not in headers_lower:
                results["missing_headers"].append(h)
                severity = "high" if h in ["strict-transport-security", "content-security-policy"] else "medium"
                results["findings"].append({
                    "title": f"Header de seguridad faltante: {h}",
                    "description": f"El sitio {url} no incluye el header {h}",
                    "severity": severity,
                    "recommendation": f"Agregar el header {h} en la configuración del servidor"
                })

        # Verificar si no usa HTTPS
        if not url.startswith("https"):
            results["findings"].append({
                "title": "Sitio no usa HTTPS",
                "description": f"El sitio {url} no cifra las comunicaciones",
                "severity": "critical",
                "recommendation": "Configurar certificado SSL/TLS e implementar HSTS"
            })

        # Detectar tecnologías expuestas
        server = results.get("server", "")
        if server and server != "No revelado":
            results["findings"].append({
                "title": f"Versión de servidor expuesta: {server}",
                "description": f"El header Server revela información: {server}",
                "severity": "low",
                "recommendation": "Ocultar la versión del servidor en la configuración"
            })

    except urllib.error.URLError as e:
        results["findings"].append({
            "title": "Sitio no accesible",
            "description": str(e),
            "severity": "high",
            "recommendation": "Verificar que el sitio esté en línea"
        })
    except Exception as e:
        results["findings"].append({
            "title": "Error en el escaneo",
            "description": str(e),
            "severity": "medium",
            "recommendation": "Verificar la URL e intentar de nuevo"
        })

    return results


@router.post("/url")
def scan_url(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL requerida")

    results = check_url(url)
    return results


# ─── Vulnerability Scanner Endpoints ──────────────────────────

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
VULN_QUEUE = "vuln_scanning"


def publish_scan_task(scan_data: dict):
    """Publica una tarea de escaneo en la cola de RabbitMQ."""
    params = pika.URLParameters(RABBITMQ_URL)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=VULN_QUEUE, durable=True)
    channel.basic_publish(
        exchange="",
        routing_key=VULN_QUEUE,
        body=json.dumps(scan_data),
        properties=pika.BasicProperties(delivery_mode=2)
    )
    connection.close()


@router.post("/vuln-scan")
def create_vuln_scan(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Crea un nuevo escaneo de vulnerabilidades."""
    target = (payload.get("target") or "").strip()
    scan_type = payload.get("scan_type", "full")

    if not target:
        raise HTTPException(status_code=400, detail="Target requerido")

    if scan_type not in ("full", "network", "web", "ssl"):
        raise HTTPException(status_code=400, detail="Tipo de escaneo inválido")

    scan = Scan(
        target=target,
        scan_type=ScanType(scan_type),
        status=ScanStatus.PENDING,
        user_id=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Enviar a la cola de RabbitMQ
    try:
        publish_scan_task({
            "scan_id": scan.id,
            "target": target,
            "scan_type": scan_type,
        })
    except Exception as e:
        scan.status = ScanStatus.ERROR
        scan.error_message = f"Error enviando a cola: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail="Error al encolar el escaneo")

    return {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


@router.get("/vuln-scans")
def list_vuln_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista todos los escaneos del usuario."""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
    now = datetime.now(timezone.utc)
    return [
        {
            "id": s.id,
            "target": s.target,
            "scan_type": s.scan_type.value,
            "status": s.status.value,
            "total_vulnerabilities": s.total_vulnerabilities,
            "current_stage": s.current_stage,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": (
                (s.completed_at - s.started_at).total_seconds() if s.completed_at and s.started_at
                else (now - s.started_at).total_seconds() if s.started_at and not s.completed_at
                else None
            ),
        }
        for s in scans
    ]


@router.get("/vuln-scans/{scan_id}")
def get_vuln_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene detalles completos de un escaneo."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    vulns = db.query(ScanVulnerability).filter(ScanVulnerability.scan_id == scan_id).all()
    now = datetime.now(timezone.utc)

    # ── Enriquecer titulos con BD local de CVEs ───────────────────────────────
    # Identifica vulnerabilidades cuyo titulo es solo el CVE-ID o el prefijo generico
    cve_ids_needed = set()
    for v in vulns:
        if v.cve:
            title = (v.title or '').strip()
            if not title or _BARE_CVE_RE.match(title) or _GENERIC_TITLE_RE.match(title):
                cve_ids_needed.add(v.cve)

    cve_summary_map = {}
    if cve_ids_needed:
        try:
            rows = db.query(CveData).filter(CveData.cve_id.in_(list(cve_ids_needed))).all()
            for row in rows:
                if row.summary:
                    cve_summary_map[row.cve_id] = row.summary[:150]
        except Exception:
            pass

    def _best_title(v):
        title = (v.title or '').strip()
        if v.cve and v.cve in cve_summary_map:
            if not title or _BARE_CVE_RE.match(title) or _GENERIC_TITLE_RE.match(title):
                return cve_summary_map[v.cve]
        return v.title or v.cve or '(sin titulo)'
    # ─────────────────────────────────────────────────────────────────────────

    return {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "current_stage": scan.current_stage,
        "error_message": scan.error_message,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": (
            (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at and scan.started_at
            else (now - scan.started_at).total_seconds() if scan.started_at and not scan.completed_at
            else None
        ),
        "nmap_results": json.loads(scan.nmap_results) if scan.nmap_results else None,
        "nikto_results": json.loads(scan.nikto_results) if scan.nikto_results else None,
        "ssl_results": json.loads(scan.ssl_results) if scan.ssl_results else None,
        "vulnerabilities": [
            {
                "id": v.id,
                "title": _best_title(v),
                "description": v.description,
                "severity": v.severity,
                "port": v.port,
                "cve": v.cve,
                "osvdb": v.osvdb,
            }
            for v in vulns
        ],
    }


@router.delete("/vuln-scans/{scan_id}")
def delete_vuln_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Elimina un escaneo."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    db.delete(scan)
    db.commit()
    return {"detail": "Escaneo eliminado"}

@router.get('/cve/{cve_id}')
def get_cve_details(cve_id: str, db: Session = Depends(get_db)):
    """Busca detalles de un CVE: BD local primero (< 1 ms), fallback NVD API 2.0.

    Devuelve: { cve, summary, cvss, references, publishedDate, nvd_url, source }
    """
    import json as _json

    # ── 1. BD local (347k CVEs cargados) ─────────────────────────────────────
    try:
        row = db.query(CveData).filter(CveData.cve_id == cve_id).first()
        if row:
            cvss = None
            if row.cvss_score is not None:
                cvss = {"baseScore": row.cvss_score, "vectorString": row.cvss_vector or ""}
            refs = []
            try:
                refs = _json.loads(row.references) if row.references else []
            except Exception:
                pass
            return {
                "cve":          cve_id,
                "summary":      row.summary or "",
                "cvss":         cvss,
                "references":   refs,
                "publishedDate": row.published_date,
                "severity":     row.severity,
                "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source":       "local",
            }
    except Exception:
        pass

    # ── 2. Fallback: NVD API 2.0 ──────────────────────────────────────────────
    try:
        url  = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "ForensiLog/1.0"})
        if resp.status_code == 200:
            data  = resp.json()
            items = data.get("vulnerabilities", [])
            if items:
                cve_node = items[0].get("cve", {})
                desc = next(
                    (d["value"] for d in cve_node.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                cvss = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metrics = cve_node.get("metrics", {}).get(key)
                    if metrics:
                        d    = metrics[0].get("cvssData", {})
                        cvss = {"baseScore": d.get("baseScore"), "vectorString": d.get("vectorString", "")}
                        break
                refs = [r["url"] for r in cve_node.get("references", []) if r.get("url")][:10]
                return {
                    "cve":          cve_id,
                    "summary":      desc,
                    "cvss":         cvss,
                    "references":   refs,
                    "publishedDate": (cve_node.get("published") or "")[:10],
                    "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source":       "nvd_api",
                }
    except Exception:
        pass

    return {"error": f"CVE {cve_id} no encontrado en BD local ni en NVD", "cve": cve_id}


@router.post("/translate")
def translate_texts(payload: dict, current_user: User = Depends(get_current_user)):
    """Traduce una lista de textos de inglés a español via Google Translate.
    El backend hace la llamada (evita CORS en el navegador).
    """
    import urllib.parse
    texts = payload.get("texts", [])
    if not texts:
        return {"translations": []}

    translations = []
    for text in texts:
        if not text or len(text.strip()) < 3:
            translations.append(text)
            continue
        try:
            q   = urllib.parse.quote(str(text)[:500])
            url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=es&dt=t&q={q}"
            r   = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                data = r.json()
                translated = "".join(x[0] for x in (data[0] or []) if x and x[0])
                translations.append(translated or text)
            else:
                translations.append(text)
        except Exception:
            translations.append(text)

    return {"translations": translations}


    def _generate_scan_pdf_bytes(scan, vulnerabilities):
        import io as _io
        buffer = _io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elems = []

        # Header
        elems.append(Paragraph('ForensiLog — Informe Ejecutivo de Escaneo', styles['Title']))
        elems.append(Spacer(1, 8))

        # Scan metadata
        meta = [
            ['ID', str(scan.id)],
            ['Objetivo', scan.target],
            ['Tipo', scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type)],
            ['Estado', scan.status.value if hasattr(scan.status, 'value') else str(scan.status)],
            ['Fecha creado', scan.created_at.isoformat() if scan.created_at else 'N/A'],
            ['Iniciado', scan.started_at.isoformat() if scan.started_at else 'N/A'],
            ['Finalizado', scan.completed_at.isoformat() if scan.completed_at else 'N/A'],
            ['Total vulnerabilidades', str(scan.total_vulnerabilities or 0)],
        ]
        t = Table(meta, hAlign='LEFT', colWidths=[120, 360])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 12))

        # Vulnerabilities table
        elems.append(Paragraph('Detalle de Vulnerabilidades', styles['Heading2']))
        elems.append(Spacer(1, 6))

        if not vulnerabilities:
            elems.append(Paragraph('No se encontraron vulnerabilidades.', styles['Normal']))
        else:
            data = [['#', 'Severidad', 'Título', 'CVE', 'Puerto']]
            for i, v in enumerate(vulnerabilities, start=1):
                data.append([str(i), v.severity.upper(), v.title, v.cve or '-', str(v.port or '-')])

            table = Table(data, hAlign='LEFT', colWidths=[30, 80, 260, 80, 50])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elems.append(table)

        elems.append(Spacer(1, 12))

        # Recomendaciones (simple)
        elems.append(Paragraph('Recomendaciones', styles['Heading2']))
        elems.append(Spacer(1, 6))
        elems.append(Paragraph('• Actualizar software identificado con CVE a versiones parcheadas.', styles['Normal']))
        elems.append(Paragraph('• Restringir accesos innecesarios y aplicar firewall.', styles['Normal']))
        elems.append(Paragraph('• Reconstruir imágenes de contenedores con base images parcheadas.', styles['Normal']))

        doc.build(elems)
        buffer.seek(0)
        return buffer


    @router.get('/vuln-scans/{scan_id}/report')
    def download_scan_report(
        scan_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
    ):
        """Genera y devuelve un PDF ejecutivo del escaneo identificado por `scan_id`."""
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
        if not scan:
            raise HTTPException(status_code=404, detail='Escaneo no encontrado')

        vulnerabilities = db.query(ScanVulnerability).filter(ScanVulnerability.scan_id == scan_id).all()

        pdf_buffer = _generate_scan_pdf_bytes(scan, vulnerabilities)
        filename = f"informe_escaneo_{scan.id}.pdf"
        return StreamingResponse(pdf_buffer, media_type='application/pdf', headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        })
