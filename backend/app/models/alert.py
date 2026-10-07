from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from ipaddress import IPv4Address, IPv6Address, ip_address

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AssetCriticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"


class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    source: str
    alert_type: str
    severity: SeverityLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    asset_id: str
    asset_criticality: AssetCriticality
    ioc: Optional[str] = None
    description: str
    mitre_technique: Optional[str] = None
    
    # New fields
    status: AlertStatus = AlertStatus.NEW
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    source_event_id: Optional[str] = None

    @field_validator("severity", "asset_criticality", mode="before")
    @classmethod
    def _lowercase_enums(cls, v):
        if isinstance(v, str):
            return v.lower()
        return v

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def _validate_ips(cls, v):
        if v is not None:
            v = str(v).strip()
            if v == "":
                return None
            try:
                ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address format: {v}")
        return v
