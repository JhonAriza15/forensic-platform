import enum
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Text, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class FindingSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, enum.Enum):
    BRUTE_FORCE = "brute_force"           # múltiples intentos fallidos de login
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_IP = "suspicious_ip"       # IP en listas negras conocidas
    UNUSUAL_HOUR = "unusual_hour"         # actividad fuera de horario normal
    LARGE_DATA_TRANSFER = "large_data_transfer"
    MALWARE_INDICATOR = "malware_indicator"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CONFIGURATION_CHANGE = "configuration_change"
    OTHER = "other"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False, index=True)
    category = Column(Enum(FindingCategory), default=FindingCategory.OTHER, index=True)
    confidence_score = Column(Float, default=1.0)   # 0.0 - 1.0, qué tan seguro está el worker
    recommendation = Column(Text, nullable=True)     # qué hacer ante este hallazgo
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

    # FK
    log_file_id = Column(Integer, ForeignKey("log_files.id"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("log_events.id"), nullable=True)  # evento que originó el hallazgo

    # Relationships
    log_file = relationship("LogFile", back_populates="findings")
    event = relationship("LogEvent", back_populates="finding")

    def __repr__(self):
        return f"<Finding id={self.id} severity={self.severity} category={self.category}>"
