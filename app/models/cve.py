"""
Modelo para almacenar datos de CVEs descargados desde los feeds de NVD.
Se usa para consultas locales rápidas durante los escaneos de vulnerabilidades.
"""
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Index
from datetime import datetime
from app.database import Base


class CveData(Base):
    __tablename__ = "cve_data"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    cve_id         = Column(String(30), unique=True, nullable=False, index=True)
    summary        = Column(Text, nullable=True)          # Descripción del CVE
    cvss_score     = Column(Float, nullable=True)         # Puntuación CVSS (v3 preferido, v2 como fallback)
    cvss_vector    = Column(String(200), nullable=True)   # Vector CVSS
    severity       = Column(String(20), nullable=True)    # CRITICAL / HIGH / MEDIUM / LOW / NONE
    published_date = Column(String(30), nullable=True)    # Fecha de publicación ISO
    references     = Column(Text, nullable=True)          # JSON con lista de URLs de referencia
    loaded_at      = Column(DateTime, default=datetime.utcnow)

    # Índice extra para búsquedas por severidad
    __table_args__ = (
        Index("ix_cve_severity", "severity"),
    )

    def to_dict(self):
        import json
        refs = []
        try:
            refs = json.loads(self.references) if self.references else []
        except Exception:
            pass
        return {
            "cve_id":         self.cve_id,
            "summary":        self.summary,
            "cvss_score":     self.cvss_score,
            "cvss_vector":    self.cvss_vector,
            "severity":       self.severity,
            "published_date": self.published_date,
            "references":     refs,
            "nvd_url":        f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
        }
