import enum
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class LogLevel(str, enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    line_number = Column(Integer, nullable=False)
    raw_line = Column(Text, nullable=False)          # línea original del log
    timestamp = Column(DateTime(timezone=True), nullable=True, index=True)
    level = Column(Enum(LogLevel), default=LogLevel.UNKNOWN, index=True)
    source_ip = Column(String(45), nullable=True, index=True)   # IPv4 o IPv6
    username = Column(String(100), nullable=True, index=True)
    action = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    extra_fields = Column(JSON, nullable=True)       # campos adicionales parseados

    # FK
    log_file_id = Column(Integer, ForeignKey("log_files.id"), nullable=False, index=True)

    # Relationships
    log_file = relationship("LogFile", back_populates="events")
    finding = relationship("Finding", back_populates="event", uselist=False)

    def __repr__(self):
        return f"<LogEvent id={self.id} line={self.line_number} level={self.level}>"
