import pika
import json
import os
import sys
import subprocess
import tempfile
import re
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models.scan import Scan, ScanStatus, ScanType, ScanVulnerability

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
QUEUE_NAME = "vuln_scanning"

# Servicios genéricos sin software real, no tienen CVEs específicos
_SKIP_SERVICES = {"tcpwrapped", "unknown", "syn-ack", "filtered", "closed", ""}

# ─── CVE lookup local por versión de servicio ──────────────────
_GENERIC_SECOND_WORDS = {"db", "server", "service", "daemon", "smbd", "nmbd"}

def extract_software_version(service_str: str):
    """Extrae nombre de software y versión del string de servicio de Nmap.

    Ejemplos:
      'vsftpd 2.3.4'                            → ('vsftpd', '2.3.4')
      'OpenSSH 4.7p1 Debian 8ubuntu1 (…)'       → ('OpenSSH', '4.7')
      'Apache httpd 2.2.8 ((Ubuntu) DAV/2)'     → ('Apache httpd', '2.2.8')
      'MySQL 5.0.51a-3ubuntu5'                  → ('MySQL', '5.0.51')
      'PostgreSQL DB 8.3.7 - 8.3.22'            → ('PostgreSQL', '8.3.7')
      'Samba smbd 3.X - 4.X'                    → ('Samba', None)
    """
    s = service_str.strip()
    if not s or s.lower().split()[0] in _SKIP_SERVICES:
        return None, None

    # Version: primer patrón X.Y o X.Y.Z (solo dígitos, sin letras en partes)
    ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', s)
    version = ver_match.group(1) if ver_match else None

    # Nombre: palabras antes del número de versión (o de toda la cadena si no hay versión)
    if ver_match:
        name_part = s[:ver_match.start()].strip()
    else:
        name_part = s

    words = name_part.split()
    if not words:
        return None, None

    # Decidir si usar 1 o 2 palabras para el nombre
    if len(words) >= 2 and words[1].lower().rstrip('/') not in _GENERIC_SECOND_WORDS:
        software = f"{words[0]} {words[1]}"
    else:
        software = words[0]

    # Limpiar caracteres no deseados al final
    software = software.rstrip('/:,')

    return software, version


def find_cves_for_service(software: str, version: str = None, limit: int = 8) -> list:
    """Busca CVEs en la BD local que mencionan el software y versión detectados.

    Usa búsqueda por texto en el campo summary. Si hay versión, busca
    major.minor para mayor cobertura (e.g. '4.7' cubre '4.7p1', '4.7.1', …).
    """
    if not software:
        return []
    try:
        from app.models.cve import CveData
        from sqlalchemy import func

        db = SessionLocal()
        soft_lower = software.lower()

        if version:
            # Major.minor (evita ser muy restrictivo con el patch)
            ver_parts = version.split('.')[:2]
            ver_search = '.'.join(ver_parts)
            rows = (
                db.query(CveData)
                .filter(func.lower(CveData.summary).contains(soft_lower))
                .filter(func.lower(CveData.summary).contains(ver_search))
                .filter(CveData.severity.in_(['CRITICAL', 'HIGH', 'MEDIUM']))
                .order_by(CveData.cvss_score.desc())
                .limit(limit)
                .all()
            )
        else:
            rows = (
                db.query(CveData)
                .filter(func.lower(CveData.summary).contains(soft_lower))
                .filter(CveData.severity.in_(['CRITICAL', 'HIGH']))
                .order_by(CveData.cvss_score.desc())
                .limit(max(limit // 2, 3))
                .all()
            )

        db.close()
        return [
            {
                "cve_id":     r.cve_id,
                "summary":    (r.summary or "")[:200],
                "severity":   (r.severity or "MEDIUM").lower(),
                "cvss_score": r.cvss_score,
            }
            for r in rows
        ]

    except Exception as e:
        print(f"[CVE-local] Error buscando '{software} {version}': {e}", flush=True)
        return []


# ─── Nmap Scanner ──────────────────────────────────────────────
def run_nmap_scan(target: str) -> dict:
    """Ejecuta Nmap y enriquece los resultados con CVEs de la BD local."""
    results = {
        "open_ports": [],
        "services": [],
        "os_detection": None,
        "vulnerabilities": [],
        "raw_output": ""
    }
    try:
        # Detección de versiones + scripts de vulnerabilidad NSE
        # --script-timeout limita cada script para no bloquear si vulners.com no responde
        cmd = [
            "nmap", "-sV", "-sC", "--script=vuln",
            "--script-timeout", "30s",
            "-T4", "--top-ports", "1000",
            "-oN", "-",
            target
        ]

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            try:
                proc = subprocess.Popen(cmd, stdout=tf, stderr=subprocess.STDOUT, text=True)
                proc.wait(timeout=9000)
            except subprocess.TimeoutExpired:
                proc.kill()
                results["vulnerabilities"].append({
                    "title": "Timeout en escaneo Nmap",
                    "description": "El escaneo tardó más de 9000 segundos",
                    "severity": "medium"
                })
            except Exception as e:
                results["vulnerabilities"].append({
                    "title": "Error en escaneo Nmap",
                    "description": str(e),
                    "severity": "low"
                })
            finally:
                tf.flush()
                tf.seek(0)
                output = tf.read()
                results["raw_output"] = output

        # ── Puertos abiertos y detección de servicios ──────────────
        dangerous_ports = {
            21:    "FTP - posible acceso anónimo o backdoor",
            23:    "Telnet - protocolo inseguro sin cifrado",
            25:    "SMTP - posible relay abierto",
            445:   "SMB - riesgo de EternalBlue/ransomware",
            3389:  "RDP - posible ataque de fuerza bruta",
            1433:  "MSSQL - base de datos expuesta",
            3306:  "MySQL - base de datos expuesta",
            5432:  "PostgreSQL - base de datos expuesta",
            6379:  "Redis - posible acceso sin autenticación",
            27017: "MongoDB - posible acceso sin autenticación",
            8080:  "HTTP alternativo - configuracion de riesgo",
            8443:  "HTTPS alternativo - posible misconfiguracion",
        }

        # Nmap -oN formato: PORT  STATE  SERVICE  VERSION
        # Ej:  21/tcp  open  ftp         vsftpd 2.3.4
        # group1=port, group2=proto, group3=state, group4=service_type, group5=version_info
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)"
        for match in re.finditer(port_pattern, output):
            port_num     = int(match.group(1))
            protocol     = match.group(2)
            state        = match.group(3)
            service_type = match.group(4).strip()   # "ftp", "ssh", "http", etc.
            version_info = match.group(5).strip()   # "vsftpd 2.3.4", "OpenSSH 4.7p1 …", etc.

            # Cadena completa para mostrar en UI (service_type + version_info)
            svc_str = f"{service_type} {version_info}".strip()

            port_info = {
                "port":         port_num,
                "protocol":     protocol,
                "state":        state,
                "service":      svc_str,
                "version_info": version_info,   # solo la parte del software/version
            }
            results["open_ports"].append(port_info)

            if state == "open" and port_num in dangerous_ports:
                results["vulnerabilities"].append({
                    "title":       f"Puerto peligroso abierto: {port_num}",
                    "description": dangerous_ports[port_num],
                    "severity":    "high",
                    "port":        port_num,
                })

        # ── CVEs de scripts NSE (vulners/vuln cuando tienen internet) ──
        nse_cve_ids = set()
        vuln_pattern = r"\|\s+(CVE-\d{4}-\d+)"
        for match in re.finditer(vuln_pattern, output):
            cve = match.group(1)
            if cve in nse_cve_ids:
                continue
            nse_cve_ids.add(cve)
            cve_details = fetch_cve_details(cve)
            summary     = cve_details.get("summary", "") if cve_details else ""
            title       = summary[:120] if summary else cve
            results["vulnerabilities"].append({
                "title":       title,
                "description": f"Nmap NSE detectó {cve} en el objetivo",
                "severity":    "critical",
                "cve":         cve,
            })

        # ── CVEs de BD local por versión de servicio (SIEMPRE funciona) ─
        # Para cada puerto abierto con software identificado, buscar CVEs
        # en la base de datos local de 347k CVEs. No depende de internet.
        local_cve_ids = set(nse_cve_ids)  # no duplicar con NSE
        print(f"[CVE-local] Buscando CVEs para {len(results['open_ports'])} servicios...", flush=True)

        for port_info in results["open_ports"]:
            if port_info.get("state") != "open":
                continue

            # Usar version_info (solo la parte del software) para el lookup de CVEs
            # Ej: "vsftpd 2.3.4" en vez de "ftp vsftpd 2.3.4"
            version_info = port_info.get("version_info", "").strip()
            svc_display  = port_info.get("service", "")

            # Si no hay version_info, usar el service_type como fallback
            lookup_str = version_info or svc_display
            if not lookup_str:
                continue

            software, version = extract_software_version(lookup_str)
            if not software:
                continue

            cves = find_cves_for_service(software, version, limit=10)
            added = 0
            for cve in cves:
                cid = cve["cve_id"]
                if cid in local_cve_ids:
                    continue
                local_cve_ids.add(cid)
                added += 1
                results["vulnerabilities"].append({
                    "title":       cve["summary"][:120] or cid,
                    "description": f"Servicio vulnerable detectado: {svc_display} en puerto {port_info['port']}",
                    "severity":    cve["severity"],
                    "cve":         cid,
                    "port":        port_info["port"],
                })
            if added:
                print(f"[CVE-local] {software} {version or ''}: +{added} CVEs", flush=True)

        # ── Detectar OS ────────────────────────────────────────────
        os_match = re.search(r"OS details:\s*(.*)", output)
        if os_match:
            results["os_detection"] = os_match.group(1).strip()

    except Exception as e:
        results["vulnerabilities"].append({
            "title":       "Error en escaneo Nmap",
            "description": str(e),
            "severity":    "low",
        })

    return results


# ─── Nikto Scanner ─────────────────────────────────────────────
def run_nikto_scan(target: str) -> dict:
    """Ejecuta un escaneo Nikto contra el objetivo web."""
    results = {
        "vulnerabilities": [],
        "raw_output": ""
    }

    url = target if target.startswith("http") else f"http://{target}"

    try:
        # Aumentamos timeouts para permitir escaneos largos en hosts lentos
        cmd = [
            "nikto", "-h", url,
            "-Tuning", "1234567890abc",
            "-timeout", "60",
            "-maxtime", "3600s",  # hasta 1 hora
            "-nointeractive",
            "-C", "all"
        ]

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            try:
                proc = subprocess.Popen(cmd, stdout=tf, stderr=subprocess.STDOUT, text=True)
                proc.wait(timeout=9000)
            except subprocess.TimeoutExpired:
                proc.kill()
                results["vulnerabilities"].append({
                    "title": "Timeout en escaneo Nikto",
                    "description": "El escaneo web tardó más de 9000 segundos",
                    "severity": "medium"
                })
            except Exception as e:
                results["vulnerabilities"].append({
                    "title": "Error en escaneo Nikto",
                    "description": str(e),
                    "severity": "low"
                })
            finally:
                tf.flush()
                tf.seek(0)
                output = tf.read()
                results["raw_output"] = output

        # Parsear resultados de Nikto
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Líneas con hallazgos empiezan con +
            if line.startswith("+"):
                finding_text = line.lstrip("+ ").strip()

                severity = "medium"
                if any(w in finding_text.lower() for w in [
                    "sql injection", "xss", "remote code", "rce",
                    "file inclusion", "command injection", "backdoor"
                ]):
                    severity = "critical"
                elif any(w in finding_text.lower() for w in [
                    "directory listing", "default file", "information disclosure",
                    "phpinfo", "server-status", "admin"
                ]):
                    severity = "high"
                elif any(w in finding_text.lower() for w in [
                    "outdated", "version", "header"
                ]):
                    severity = "low"

                # Extraer OSVDB si existe
                osvdb_match = re.search(r"OSVDB-(\d+)", finding_text)
                results["vulnerabilities"].append({
                    "title": finding_text[:120],
                    "description": finding_text,
                    "severity": severity,
                    "osvdb": osvdb_match.group(1) if osvdb_match else None
                })

    except Exception as e:
        results["vulnerabilities"].append({
            "title": "Error en escaneo Nikto",
            "description": str(e),
            "severity": "low"
        })

    return results


# ─── SSL/TLS Scanner ──────────────────────────────────────────
def run_ssl_scan(target: str) -> dict:
    """Analiza la configuración SSL/TLS del objetivo."""
    results = {
        "vulnerabilities": [],
        "tls_info": {}
    }

    hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )

        location = ServerNetworkLocation(hostname=hostname, port=443)
        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.CERTIFICATE_INFO,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for result in scanner.get_results():
            # Verificar SSL 2.0
            ssl2 = result.scan_result.ssl_2_0_cipher_suites
            if ssl2 and ssl2.result and ssl2.result.accepted_cipher_suites:
                results["vulnerabilities"].append({
                    "title": "SSL 2.0 habilitado",
                    "description": "El servidor soporta SSL 2.0 que es extremadamente inseguro",
                    "severity": "critical"
                })

            # Verificar SSL 3.0
            ssl3 = result.scan_result.ssl_3_0_cipher_suites
            if ssl3 and ssl3.result and ssl3.result.accepted_cipher_suites:
                results["vulnerabilities"].append({
                    "title": "SSL 3.0 habilitado (POODLE)",
                    "description": "El servidor soporta SSL 3.0, vulnerable a POODLE",
                    "severity": "critical"
                })

            # Verificar TLS 1.0
            tls10 = result.scan_result.tls_1_0_cipher_suites
            if tls10 and tls10.result and tls10.result.accepted_cipher_suites:
                results["vulnerabilities"].append({
                    "title": "TLS 1.0 habilitado (deprecado)",
                    "description": "TLS 1.0 está deprecado y es vulnerable a BEAST",
                    "severity": "high"
                })

            # Verificar TLS 1.1
            tls11 = result.scan_result.tls_1_1_cipher_suites
            if tls11 and tls11.result and tls11.result.accepted_cipher_suites:
                results["vulnerabilities"].append({
                    "title": "TLS 1.1 habilitado (deprecado)",
                    "description": "TLS 1.1 está deprecado desde 2021",
                    "severity": "medium"
                })

            # TLS 1.2 y 1.3 info
            tls12 = result.scan_result.tls_1_2_cipher_suites
            tls13 = result.scan_result.tls_1_3_cipher_suites
            results["tls_info"]["tls_1_2"] = bool(
                tls12 and tls12.result and tls12.result.accepted_cipher_suites
            )
            results["tls_info"]["tls_1_3"] = bool(
                tls13 and tls13.result and tls13.result.accepted_cipher_suites
            )

            if not results["tls_info"]["tls_1_3"]:
                results["vulnerabilities"].append({
                    "title": "TLS 1.3 no soportado",
                    "description": "Se recomienda habilitar TLS 1.3 para mayor seguridad",
                    "severity": "low"
                })

            # Heartbleed
            heartbleed = result.scan_result.heartbleed
            if heartbleed and heartbleed.result and heartbleed.result.is_vulnerable_to_heartbleed:
                results["vulnerabilities"].append({
                    "title": "VULNERABLE A HEARTBLEED (CVE-2014-0160)",
                    "description": "El servidor es vulnerable a Heartbleed, permite leer memoria del servidor",
                    "severity": "critical"
                })

            # Certificado
            cert_info = result.scan_result.certificate_info
            if cert_info and cert_info.result:
                for deployment in cert_info.result.certificate_deployments:
                    cert = deployment.received_certificate_chain[0]
                    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                    if not_after < datetime.now(timezone.utc):
                        results["vulnerabilities"].append({
                            "title": "Certificado SSL expirado",
                            "description": f"El certificado expiró el {not_after.isoformat()}",
                            "severity": "critical"
                        })
                    results["tls_info"]["cert_subject"] = str(cert.subject)
                    results["tls_info"]["cert_expires"] = not_after.isoformat()

    except Exception as e:
        results["vulnerabilities"].append({
            "title": "Error en análisis SSL/TLS",
            "description": str(e),
            "severity": "low"
        })

    return results


def fetch_cve_details(cve_id: str) -> dict:
    """Busca detalles de un CVE.

    Estrategia:
      1. Consulta la tabla local cve_data (PostgreSQL, < 1 ms).
      2. Si no está en local, intenta la API de NVD como fallback.

    Devuelve dict con: summary, cvss, references, publishedDate, nvd_url.
    """
    if not cve_id:
        return {}

    # ── 1. Buscar en base de datos local ──────────────────────────
    try:
        from app.database import SessionLocal
        from app.models.cve import CveData
        import json as _json

        db = SessionLocal()
        row = db.query(CveData).filter(CveData.cve_id == cve_id).first()
        db.close()

        if row:
            cvss = None
            if row.cvss_score is not None:
                cvss = {"baseScore": row.cvss_score, "vectorString": row.cvss_vector}
            refs = []
            try:
                refs = _json.loads(row.references) if row.references else []
            except Exception:
                pass
            return {
                "summary":       row.summary or "",
                "cvss":          cvss,
                "references":    refs,
                "publishedDate": row.published_date,
                "nvd_url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source":        "local",
            }
    except Exception as e:
        print(f"[CVE-local] Error consultando BD local para {cve_id}: {e}", flush=True)

    # ── 2. Fallback: API NVD (solo si no está en local) ───────────
    print(f"[CVE-fallback] {cve_id} no en BD local, consultando NVD...", flush=True)
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return {}
        data = resp.json()
        item = data.get("result", {}).get("CVE_Items", [])
        if not item:
            return {}
        item = item[0]

        desc = ""
        try:
            desc = item["cve"]["description"]["description_data"][0].get("value", "")
        except Exception:
            pass

        cvss = None
        try:
            metrics = item.get("impact", {})
            if "baseMetricV3" in metrics:
                v3 = metrics["baseMetricV3"]["cvssV3"]
                cvss = {"baseScore": v3.get("baseScore"), "vectorString": v3.get("vectorString")}
            elif "baseMetricV2" in metrics:
                v2 = metrics["baseMetricV2"]["cvssV2"]
                cvss = {"baseScore": v2.get("baseScore"), "vectorString": None}
        except Exception:
            pass

        refs = []
        try:
            for r in item["cve"]["references"]["reference_data"]:
                refs.append(r.get("url"))
        except Exception:
            pass

        return {
            "summary":       desc,
            "cvss":          cvss,
            "references":    refs,
            "publishedDate": item.get("publishedDate"),
            "nvd_url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source":        "nvd_api",
        }
    except Exception:
        return {}


def enrich_vulnerabilities_list(vulns: list):
    """Enriquecer una lista de vulnerabilidades: por cada entrada con 'cve', consulta NVD
    y añade `cve_info` y un resumen legible al campo `description`.
    """
    for v in vulns:
        cve = v.get("cve")
        if cve:
            details = fetch_cve_details(cve)
            if details:
                v["cve_info"] = details
                # Añadir resumen corto a la descripción para persistir en BD
                parts = []
                if details.get("cvss") and details["cvss"].get("baseScore") is not None:
                    parts.append(f"CVSS: {details['cvss']['baseScore']} ({details['cvss'].get('vectorString','')})")
                if details.get("publishedDate"):
                    parts.append(f"Publicado: {details['publishedDate']}")
                if details.get("nvd_url"):
                    parts.append(f"Referencia: {details['nvd_url']}")
                if details.get("summary"):
                    parts.append(f"Resumen NVD: {details['summary']}")
                # Append to description (truncate if muy largo)
                extra = " -- " + " | ".join(parts)
                v["description"] = (v.get("description","") + extra)[:2000]


# ─── Procesador principal ──────────────────────────────────────
def process_scan(scan_data: dict):
    """Procesa una solicitud de escaneo de vulnerabilidades."""
    db = SessionLocal()
    scan_id = scan_data.get("scan_id")
    target = (scan_data.get("target") or "").strip()   # eliminar espacios/newlines
    scan_type = scan_data.get("scan_type", "full")

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            print(f"Scan {scan_id} no encontrado", flush=True)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.current_stage = "starting"
        db.commit()

        all_vulns = []

        # ─── Etapa 1: Nmap ─────────────────────────────
        if scan_type in ("full", "network"):
            scan.current_stage = "nmap"
            db.commit()
            print(f"[NMAP] Escaneando {target}...", flush=True)
            nmap_results = run_nmap_scan(target)
            scan.nmap_results = json.dumps(nmap_results, default=str)
            nmap_vulns = nmap_results.get("vulnerabilities", [])
            all_vulns.extend(nmap_vulns)
            scan.total_vulnerabilities = len(all_vulns)
            db.commit()
            print(f"[NMAP] Completado: {len(nmap_vulns)} hallazgos", flush=True)

        # ─── Etapa 2: Nikto ────────────────────────────
        if scan_type in ("full", "web"):
            scan.current_stage = "nikto"
            db.commit()
            print(f"[NIKTO] Escaneando {target}...", flush=True)
            nikto_results = run_nikto_scan(target)
            scan.nikto_results = json.dumps(nikto_results, default=str)
            nikto_vulns = nikto_results.get("vulnerabilities", [])
            all_vulns.extend(nikto_vulns)
            scan.total_vulnerabilities = len(all_vulns)
            db.commit()
            print(f"[NIKTO] Completado: {len(nikto_vulns)} hallazgos", flush=True)

        # ─── Etapa 3: SSL ──────────────────────────────
        if scan_type in ("full", "ssl"):
            scan.current_stage = "ssl"
            db.commit()
            print(f"[SSL] Analizando {target}...", flush=True)
            ssl_results = run_ssl_scan(target)
            scan.ssl_results = json.dumps(ssl_results, default=str)
            ssl_vulns = ssl_results.get("vulnerabilities", [])
            all_vulns.extend(ssl_vulns)
            scan.total_vulnerabilities = len(all_vulns)
            db.commit()
            print(f"[SSL] Completado: {len(ssl_vulns)} hallazgos", flush=True)

        # ─── Guardar vulnerabilidades en BD ─────────────
        scan.current_stage = "saving"
        db.commit()

        for vuln in all_vulns:
            db_vuln = ScanVulnerability(
                scan_id=scan.id,
                title=vuln.get("title", "Sin título")[:255],
                description=vuln.get("description", "")[:2000],
                severity=vuln.get("severity", "medium"),
                port=vuln.get("port"),
                cve=vuln.get("cve"),
                osvdb=vuln.get("osvdb"),
            )
            db.add(db_vuln)

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_vulnerabilities = len(all_vulns)
        scan.current_stage = "done"
        db.commit()
        
        duration = (scan.completed_at - scan.started_at).total_seconds()
        print(f"[OK] Scan {scan_id} completado en {duration:.1f}s: {len(all_vulns)} vulnerabilidades", flush=True)

    except Exception as e:
        print(f"[ERROR] Scan {scan_id}: {e}", flush=True)
        if scan:
            scan.status = ScanStatus.ERROR
            scan.error_message = str(e)[:500]
            scan.current_stage = "error"
            db.commit()
    finally:
        db.close()


def callback(ch, method, properties, body):
    """Callback para mensajes de RabbitMQ."""
    try:
        scan_data = json.loads(body)
        print(f"[*] Recibida solicitud de escaneo: {scan_data.get('target')}")
        process_scan(scan_data)
    except json.JSONDecodeError:
        print(f"[ERROR] Mensaje inválido: {body}")
    finally:
        ch.basic_ack(delivery_tag=method.delivery_tag)


def main():
    """Inicia el worker de escaneo de vulnerabilidades."""
    print("[*] Vulnerability Scanner Worker iniciado")
    print(f"[*] Conectando a RabbitMQ: {RABBITMQ_URL}")

    params = pika.URLParameters(RABBITMQ_URL)
    # Aumentar heartbeat y timeout de bloqueo para permitir operaciones largas
    params.heartbeat = 3600
    params.blocked_connection_timeout = 1200

    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)

    print(f"[*] Esperando solicitudes de escaneo en cola '{QUEUE_NAME}'...")
    channel.start_consuming()


if __name__ == "__main__":
    main()
