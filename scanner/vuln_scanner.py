import pika
import json
import os
import sys
import subprocess
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models.scan import Scan, ScanStatus, ScanType, ScanVulnerability

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
QUEUE_NAME = "vuln_scanning"


# ─── Nmap Scanner ──────────────────────────────────────────────
def run_nmap_scan(target: str) -> dict:
    """Ejecuta un escaneo Nmap contra el objetivo."""
    results = {
        "open_ports": [],
        "services": [],
        "os_detection": None,
        "vulnerabilities": [],
        "raw_output": ""
    }
    try:
        # Escaneo de puertos + detección de servicios + scripts de vulnerabilidad
        cmd = [
            "nmap", "-sV", "-sC", "--script=vuln",
            "-T4", "--top-ports", "1000",
            "-oN", "-",  # output normal a stdout
            target
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        output = proc.stdout
        results["raw_output"] = output

        # Parsear puertos abiertos
        port_pattern = r"(\d+)/(tcp|udp)\s+(\w+)\s+(.*)"
        for match in re.finditer(port_pattern, output):
            port_info = {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip()
            }
            results["open_ports"].append(port_info)

            # Puertos peligrosos comunes
            dangerous_ports = {
                21: "FTP - posible acceso anónimo",
                23: "Telnet - protocolo inseguro sin cifrado",
                25: "SMTP - posible relay abierto",
                445: "SMB - riesgo de EternalBlue/ransomware",
                3389: "RDP - posible ataque de fuerza bruta",
                1433: "MSSQL - base de datos expuesta",
                3306: "MySQL - base de datos expuesta",
                5432: "PostgreSQL - base de datos expuesta",
                6379: "Redis - posible acceso sin autenticación",
                27017: "MongoDB - posible acceso sin autenticación",
            }
            if port_info["port"] in dangerous_ports:
                results["vulnerabilities"].append({
                    "title": f"Puerto peligroso abierto: {port_info['port']}",
                    "description": dangerous_ports[port_info["port"]],
                    "severity": "high",
                    "port": port_info["port"]
                })

        # Parsear vulnerabilidades de scripts NSE
        vuln_pattern = r"\|\s+(CVE-\d{4}-\d+).*?(\n\|.*?)*"
        for match in re.finditer(vuln_pattern, output):
            cve = match.group(1)
            results["vulnerabilities"].append({
                "title": f"Vulnerabilidad detectada: {cve}",
                "description": f"Nmap NSE detectó {cve} en el objetivo",
                "severity": "critical",
                "cve": cve
            })

        # Detectar OS
        os_pattern = r"OS details:\s*(.*)"
        os_match = re.search(os_pattern, output)
        if os_match:
            results["os_detection"] = os_match.group(1).strip()

    except subprocess.TimeoutExpired:
        results["vulnerabilities"].append({
            "title": "Timeout en escaneo Nmap",
            "description": "El escaneo tardó más de 5 minutos",
            "severity": "medium"
        })
    except Exception as e:
        results["vulnerabilities"].append({
            "title": "Error en escaneo Nmap",
            "description": str(e),
            "severity": "low"
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
        cmd = [
            "nikto", "-h", url,
            "-Tuning", "1234567890abc",
            "-timeout", "10",
            "-maxtime", "300s",
            "-nointeractive",
            "-C", "all"
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=360
        )
        output = proc.stdout
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

    except subprocess.TimeoutExpired:
        results["vulnerabilities"].append({
            "title": "Timeout en escaneo Nikto",
            "description": "El escaneo web tardó más de 6 minutos",
            "severity": "medium"
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


# ─── Procesador principal ──────────────────────────────────────
def process_scan(scan_data: dict):
    """Procesa una solicitud de escaneo de vulnerabilidades."""
    db = SessionLocal()
    scan_id = scan_data.get("scan_id")
    target = scan_data.get("target")
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
    params.heartbeat = 600
    params.blocked_connection_timeout = 300

    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)

    print(f"[*] Esperando solicitudes de escaneo en cola '{QUEUE_NAME}'...")
    channel.start_consuming()


if __name__ == "__main__":
    main()
