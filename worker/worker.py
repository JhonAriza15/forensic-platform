import pika
import json
import re
import os
import sys
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models.log_file import LogFile, LogFileStatus
from app.models.log_event import LogEvent, LogLevel
from app.models.finding import Finding, FindingSeverity, FindingCategory

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
QUEUE_NAME = "log_processing"


def detect_level(line):
    line_lower = line.lower()
    if any(w in line_lower for w in ["critical", "fatal"]):
        return LogLevel.CRITICAL
    elif "error" in line_lower:
        return LogLevel.ERROR
    elif "warning" in line_lower or "warn" in line_lower:
        return LogLevel.WARNING
    elif "info" in line_lower:
        return LogLevel.INFO
    elif "debug" in line_lower:
        return LogLevel.DEBUG
    return LogLevel.UNKNOWN


def extract_ip(line):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(pattern, line)
    return match.group() if match else None


def classify_ip(ip):
    if not ip:
        return None
    if (ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("127.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))):
        return "interna"
    return "externa"


def check_abuseipdb(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or not ip:
        return None
    try:
        import urllib.request
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url)
        req.add_header("Key", api_key)
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=5) as response:
            import json as json_lib
            data = json_lib.loads(response.read())
            return data.get("data", {})
    except Exception as e:
        print(f"Error consultando AbuseIPDB: {e}")
        return None


def analyze_events(db, log_file, events):
    findings = []

    # Detectar brute force
    ip_errors = {}
    for event in events:
        if event.level in [LogLevel.ERROR, LogLevel.WARNING] and event.source_ip:
            ip_errors[event.source_ip] = ip_errors.get(event.source_ip, 0) + 1

    for ip, count in ip_errors.items():
        if count >= 3:
            finding = Finding(
                title=f"Posible fuerza bruta desde {ip}",
                description=f"Se detectaron {count} intentos fallidos desde la IP {ip}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.BRUTE_FORCE,
                confidence_score=0.90,
                recommendation="Bloquear la IP en el firewall e investigar el origen",
                log_file_id=log_file.id
            )
            findings.append(finding)

    # Detectar escalamiento de privilegios
    for event in events:
        if event.raw_line and any(w in event.raw_line.lower() for w in ["privilege escalation", "escalation", "superuser", "sudo", "root"]):
            finding = Finding(
                title="Escalamiento de privilegios detectado",
                description=f"Línea {event.line_number}: {event.raw_line[:200]}",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.PRIVILEGE_ESCALATION,
                confidence_score=0.95,
                recommendation="Verificar si el cambio de privilegios fue autorizado",
                log_file_id=log_file.id,
                event_id=event.id
            )
            findings.append(finding)
            break

    # Detectar comandos peligrosos
    dangerous_commands = ["rm -rf", "chmod 777", "wget", "curl", "nc ", "netcat", "base64"]
    for event in events:
        if event.raw_line and any(cmd in event.raw_line.lower() for cmd in dangerous_commands):
            finding = Finding(
                title="Comando peligroso ejecutado",
                description=f"Línea {event.line_number}: {event.raw_line[:200]}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.MALWARE_INDICATOR,
                confidence_score=0.85,
                recommendation="Revisar quién ejecutó el comando y con qué propósito",
                log_file_id=log_file.id,
                event_id=event.id
            )
            findings.append(finding)

    # Detectar acceso a archivos sensibles
    sensitive_files = ["/root/", "/etc/passwd", "/etc/shadow", "secret", "password", "credentials", "auth.log"]
    for event in events:
        if event.raw_line and any(f in event.raw_line.lower() for f in sensitive_files):
            if "error" in event.raw_line.lower() or "unauthorized" in event.raw_line.lower():
                finding = Finding(
                    title="Acceso no autorizado a archivo sensible",
                    description=f"Línea {event.line_number}: {event.raw_line[:200]}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.UNAUTHORIZED_ACCESS,
                    confidence_score=0.88,
                    recommendation="Verificar permisos de archivos y auditar accesos",
                    log_file_id=log_file.id,
                    event_id=event.id
                )
                findings.append(finding)

    # Detectar malware
    for event in events:
        if event.raw_line and any(w in event.raw_line.lower() for w in ["malware", "malicious", "virus", "trojan", "ransomware"]):
            finding = Finding(
                title="Malware detectado en el sistema",
                description=f"Línea {event.line_number}: {event.raw_line[:200]}",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.MALWARE_INDICATOR,
                confidence_score=0.98,
                recommendation="Aislar el sistema inmediatamente y ejecutar análisis completo",
                log_file_id=log_file.id,
                event_id=event.id
            )
            findings.append(finding)

    # Detectar actividad fuera de horario
    for event in events:
        if event.timestamp:
            hour = event.timestamp.hour
            if hour < 6 or hour >= 22:
                finding = Finding(
                    title="Actividad fuera de horario laboral",
                    description=f"Actividad detectada a las {event.timestamp.strftime('%H:%M')}",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.UNUSUAL_HOUR,
                    confidence_score=0.70,
                    recommendation="Verificar si el acceso fue autorizado fuera de horario",
                    log_file_id=log_file.id,
                    event_id=event.id
                )
                findings.append(finding)
                break

    # Detectar posible DoS
    error_count = sum(1 for e in events if e.level in [LogLevel.ERROR, LogLevel.CRITICAL])
    if error_count >= 3:
        finding = Finding(
            title=f"Posible ataque DoS — {error_count} errores críticos",
            description=f"Se detectaron {error_count} errores en el log que podrían indicar un DoS",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.OTHER,
            confidence_score=0.75,
            recommendation="Verificar disponibilidad del servicio y revisar logs del servidor",
            log_file_id=log_file.id
        )
        findings.append(finding)

    # Detectar IPs externas sospechosas
    for event in events:
        if event.source_ip and classify_ip(event.source_ip) == "externa":
            if event.level in [LogLevel.ERROR, LogLevel.WARNING, LogLevel.CRITICAL]:
                finding = Finding(
                    title=f"Actividad sospechosa desde IP externa {event.source_ip}",
                    description=f"IP externa detectada con actividad anómala en línea {event.line_number}",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.SUSPICIOUS_IP,
                    confidence_score=0.80,
                    recommendation=f"Investigar la IP {event.source_ip} y considerar bloquearla",
                    log_file_id=log_file.id,
                    event_id=event.id
                )
                findings.append(finding)
                break

    # Consultar AbuseIPDB para IPs externas
    ips_consultadas = set()
    for event in events:
        if event.source_ip and classify_ip(event.source_ip) == "externa":
            if event.source_ip not in ips_consultadas:
                ips_consultadas.add(event.source_ip)
                abuse_data = check_abuseipdb(event.source_ip)
                if abuse_data and abuse_data.get("abuseConfidenceScore", 0) > 20:
                    score = abuse_data.get("abuseConfidenceScore", 0)
                    reports = abuse_data.get("totalReports", 0)
                    finding = Finding(
                        title=f"IP maliciosa confirmada: {event.source_ip}",
                        description=f"AbuseIPDB reporta score {score}% con {reports} reportes. País: {abuse_data.get('countryCode', 'desconocido')}",
                        severity=FindingSeverity.CRITICAL if score > 80 else FindingSeverity.HIGH,
                        category=FindingCategory.SUSPICIOUS_IP,
                        confidence_score=score / 100,
                        recommendation=f"Bloquear inmediatamente la IP {event.source_ip} — confirmada como maliciosa",
                        log_file_id=log_file.id,
                        event_id=event.id
                    )
                    findings.append(finding)

    return findings


def calculate_risk_score(findings):
    if not findings:
        return 0, "BAJO"

    score = 0
    for f in findings:
        if f.severity == FindingSeverity.CRITICAL:
            score += 40
        elif f.severity == FindingSeverity.HIGH:
            score += 25
        elif f.severity == FindingSeverity.MEDIUM:
            score += 10
        else:
            score += 5

    score = min(score, 100)

    if score >= 80:
        level = "CRÍTICO"
    elif score >= 60:
        level = "ALTO"
    elif score >= 30:
        level = "MEDIO"
    else:
        level = "BAJO"

    return score, level


def process_log(log_file_id):
    db = SessionLocal()
    try:
        log_file = db.query(LogFile).filter(LogFile.id == log_file_id).first()
        if not log_file:
            print(f"Log {log_file_id} no encontrado")
            return

        log_file.status = LogFileStatus.PROCESSING
        db.commit()

        events = []
        total_lines = 0

        with open(log_file.storage_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                total_lines += 1

                event = LogEvent(
                    line_number=line_num,
                    raw_line=line[:1000],
                    level=detect_level(line),
                    source_ip=extract_ip(line),
                    message=line[:500],
                    log_file_id=log_file.id
                )
                db.add(event)
                db.flush()
                events.append(event)

        findings = analyze_events(db, log_file, events)
        for finding in findings:
            db.add(finding)

        risk_score, risk_level = calculate_risk_score(findings)

        log_file.status = LogFileStatus.DONE
        log_file.total_lines = total_lines
        log_file.events_extracted = len(events)
        log_file.findings_count = len(findings)
        log_file.risk_score = risk_score
        log_file.risk_level = risk_level
        log_file.processed_at = datetime.now(timezone.utc)
        db.commit()

        print(f"Log {log_file_id} procesado: {len(events)} eventos, {len(findings)} hallazgos, riesgo: {risk_score}% {risk_level}")

    except Exception as e:
        db.query(LogFile).filter(LogFile.id == log_file_id).update({"status": LogFileStatus.ERROR, "error_message": str(e)[:500]})
        db.commit()
        print(f"Error procesando log {log_file_id}: {e}")
    finally:
        db.close()


def callback(ch, method, properties, body):
    message = json.loads(body)
    log_file_id = message.get("log_file_id")
    print(f"Procesando log {log_file_id}...")
    process_log(log_file_id)
    ch.basic_ack(delivery_tag=method.delivery_tag)


def start_worker():
    import time
    retries = 0
    while retries < 20:
        try:
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE_NAME, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
            print("Worker esperando mensajes. Ctrl+C para salir.")
            channel.start_consuming()
        except Exception as e:
            retries += 1
            print(f"Error conectando a RabbitMQ, reintento {retries}/20: {e}")
            time.sleep(10)
    print("No se pudo conectar a RabbitMQ después de 20 intentos")


if __name__ == "__main__":
    start_worker()