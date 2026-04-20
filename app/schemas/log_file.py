from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.log_file import LogFileStatus, LogFileType


class LogFileResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    file_size: int
    file_type: LogFileType
    status: LogFileStatus
    total_lines: Optional[int] = None
    events_extracted: Optional[int] = None
    findings_count: Optional[int] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    uploaded_at: datetime
    processed_at: Optional[datetime] = None

    class Config:
        from_attributes = True