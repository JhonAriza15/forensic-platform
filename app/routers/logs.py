from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.log_file import LogFile, LogFileStatus, LogFileType
from app.models.user import User
from app.schemas.log_file import LogFileResponse
from app.routers.auth import oauth2_scheme
from jose import JWTError, jwt
from app import auth
import pika
import json
import os
import shutil

router = APIRouter(prefix="/logs", tags=["logs"])

UPLOAD_DIR = "uploads"
QUEUE_NAME = "log_processing"
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    user = auth.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


def send_to_queue(log_file_id: int):
    try:
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel = connection.channel()
        channel.queue_declare(queue=QUEUE_NAME, durable=True)
        message = json.dumps({"log_file_id": log_file_id})
        channel.basic_publish(
            exchange="",
            routing_key=QUEUE_NAME,
            body=message,
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()
    except Exception as e:
        print(f"Error enviando a RabbitMQ: {e}")

        
def validate_file(file: UploadFile):
    # Validar extensión
    allowed_extensions = [".log", ".txt", ".csv", ".json"]
    filename = file.filename.lower()
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Tipo de archivo no permitido. Solo se aceptan: {', '.join(allowed_extensions)}"
        )
    
    # Validar tamaño máximo (10MB)
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)
    if size > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Archivo muy grande. Máximo permitido: 10MB"
        )

@router.post("/upload", response_model=LogFileResponse, status_code=201)
def upload_log(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    validate_file(file)
    # ... resto del código
    
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    file_size = os.path.getsize(file_path)
    log_file = LogFile(
        filename=file.filename,
        original_filename=file.filename,
        file_size=file_size,
        file_type=LogFileType.GENERIC,
        status=LogFileStatus.PENDING,
        storage_path=file_path,
        owner_id=current_user.id
    )
    db.add(log_file)
    db.commit()
    db.refresh(log_file)
    send_to_queue(log_file.id)
    return log_file


@router.get("/", response_model=List[LogFileResponse])
def get_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(LogFile).filter(LogFile.owner_id == current_user.id).all()


@router.get("/{log_id}", response_model=LogFileResponse)
def get_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    log = db.query(LogFile).filter(
        LogFile.id == log_id,
        LogFile.owner_id == current_user.id
    ).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log no encontrado")
    return log


@router.delete("/{log_id}", status_code=204)
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    log = db.query(LogFile).filter(
        LogFile.id == log_id,
        LogFile.owner_id == current_user.id
    ).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log no encontrado")
    db.delete(log)
    db.commit()
from app.models.finding import Finding

@router.get("/{log_id}/findings")
def get_findings(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    log = db.query(LogFile).filter(
        LogFile.id == log_id,
        LogFile.owner_id == current_user.id
    ).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log no encontrado")
    findings = db.query(Finding).filter(Finding.log_file_id == log_id).all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "confidence_score": f.confidence_score,
            "recommendation": f.recommendation,
            "detected_at": f.detected_at
        }
        for f in findings
    ]
    return None

@router.get("/{log_id}/timeline")
def get_timeline(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from app.models.log_event import LogEvent
    log = db.query(LogFile).filter(
        LogFile.id == log_id,
        LogFile.owner_id == current_user.id
    ).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log no encontrado")

    events = db.query(LogEvent).filter(
        LogEvent.log_file_id == log_id,
        LogEvent.level.in_(["error", "warning", "critical"])
    ).order_by(LogEvent.line_number).limit(20).all()

    return [
        {
            "line_number": e.line_number,
            "timestamp": e.timestamp,
            "level": e.level,
            "message": e.raw_line[:150] if e.raw_line else ""
        }
        for e in events
    ]