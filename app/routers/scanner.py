from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.routers.logs import get_current_user
from app.models.finding import Finding, FindingSeverity, FindingCategory
from app.models.scan import Scan, ScanStatus, ScanType, ScanVulnerability
import urllib.request
import ssl
import socket
import json
import pika
import os
from datetime import datetime, timezone

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
    target = payload.get("target")
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
                "title": v.title,
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