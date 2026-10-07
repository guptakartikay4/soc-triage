import csv
import logging
from pathlib import Path
from typing import Optional

from app.models.alert import Alert

logger = logging.getLogger(__name__)
DEFAULT_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "synthetic_alerts.csv"

def load_dataset_alerts(csv_path: Optional[Path] = None) -> list[Alert]:
    """
    Read synthetic alerts CSV and normalize into Alert instances.
    """
    path = csv_path or DEFAULT_DATA_PATH
    if not path.exists():
        logger.warning("Dataset CSV not found at %s", path)
        return []

    alerts: list[Alert] = []
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cleaned = {
                "alert_id": row["alert_id"],
                "timestamp": row["timestamp"],
                "source": row["source"],
                "alert_type": row["alert_type"],
                "severity": row["severity"].lower(),
                "source_ip": row.get("source_ip") or None,
                "destination_ip": row.get("destination_ip") or None,
                "user": row.get("user") or None,
                "host": row.get("host") or None,
                "asset_id": row["asset_id"],
                "asset_criticality": row["asset_criticality"].lower(),
                "ioc": row.get("ioc") or None,
                "description": row["description"],
                "mitre_technique": row.get("mitre_technique") or None,
            }
            alerts.append(Alert.model_validate(cleaned))
    return alerts
