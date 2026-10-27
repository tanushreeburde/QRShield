from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)
    submitted_url = Column(String(2048), nullable=False)
    final_url = Column(String(2048), nullable=True)
    verdict = Column(String(32), nullable=False)  # LOW_RISK | SUSPICIOUS | HIGH_RISK
    score = Column(Integer, nullable=False, default=0)
    client_platform = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")
    redirect_hops = relationship("RedirectHopRecord", back_populates="scan", cascade="all, delete-orphan", order_by="RedirectHopRecord.hop_index")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    code = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)  # high | medium | low | info
    description = Column(String(1024), nullable=False)

    scan = relationship("ScanRecord", back_populates="findings")


class RedirectHopRecord(Base):
    __tablename__ = "redirect_hops"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    hop_index = Column(Integer, nullable=False)
    url = Column(String(2048), nullable=False)
    status_code = Column(Integer, nullable=True)
    domain = Column(String(256), nullable=True)

    scan = relationship("ScanRecord", back_populates="redirect_hops")


class AppConfigRecord(Base):
    __tablename__ = "app_config"

    key = Column(String(128), primary_key=True)
    value = Column(String(1024), nullable=False)
