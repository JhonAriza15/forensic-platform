import enum
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class LogFileStatus(str, enum.Enum):
    PENDING = "pending"       # Recién subido, esperando procesamiento
    PROCESSING = "processing" # Worker lo está procesando
    DONE = "done"             # Procesado exitosamente
    ERROR = "error"           # Falló el procesamiento


class LogFileType(str, enum.Enum):
    SYSLOG = "syslog"
    AUTH = "auth"
    APACHE = "apache"
    NGINX = "nginx"
    WINDOWS_EVENT = "windows_event"
    GENERIC = "generic"


class LogFile(Base):
    __tablename__ = "log_files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_size = Column(BigInteger, nullable=False)  # en bytes
    file_type = Column(Enum(LogFileType), default=LogFileType.GENERIC)
    status = Column(Enum(LogFileStatus), default=LogFileStatus.PENDING, index=True)
    error_message = Column(String(500), nullable=True)
    storage_path = Column(String(500), nullable=False)  # ruta en disco/S3

    # Estadísticas tras el procesamiento
    total_lines = Column(Integer, nullable=True)
    events_extracted = Column(Integer, nullable=True)
    findings_count = Column(Integer, nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(20), nullable=True)

    # Timestamps
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # FK
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Relationships
    owner = relationship("User", back_populates="log_files")
    events = relationship("LogEvent", back_populates="log_file", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="log_file", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<LogFile id={self.id} filename={self.filename} status={self.status}>"
