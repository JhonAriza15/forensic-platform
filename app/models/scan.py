import enum
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class ScanType(str, enum.Enum):
    FULL = "full"
    NETWORK = "network"
    WEB = "web"
    SSL = "ssl"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(Enum(ScanType), default=ScanType.FULL)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    total_vulnerabilities = Column(Integer, default=0)
    current_stage = Column(String(50), nullable=True)  # nmap, nikto, ssl, done

    # Resultados crudos de cada herramienta
    nmap_results = Column(Text, nullable=True)
    nikto_results = Column(Text, nullable=True)
    ssl_results = Column(Text, nullable=True)

    error_message = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # FK al usuario que creó el escaneo
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Relationships
    vulnerabilities = relationship("ScanVulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan id={self.id} target={self.target} status={self.status}>"


class ScanVulnerability(Base):
    __tablename__ = "scan_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    cve = Column(String(50), nullable=True)
    osvdb = Column(String(50), nullable=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

    # FK
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<ScanVulnerability id={self.id} severity={self.severity}>"
