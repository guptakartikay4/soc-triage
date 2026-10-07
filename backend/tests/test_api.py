"""
Integration tests for SOC API using test DB.
"""
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database.connection import get_db
from app.database.models import Base
import pytest

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    # Populate via triage/run
    client.post("/api/triage/run", json={"source": "dataset", "reset": True})
    yield
    Base.metadata.drop_all(bind=engine)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200

def test_get_incidents_returns_list():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_incidents_are_prioritized_highest_risk_first():
    res = client.get("/api/incidents")
    incidents = res.json()
    assert len(incidents) >= 2
    risk_scores = [inc["risk_score"] for inc in incidents]
    for i in range(len(risk_scores) - 1):
        assert risk_scores[i] >= risk_scores[i + 1]

def test_incident_detail_returns_alert_evidence():
    queue_res = client.get("/api/incidents")
    first_id = queue_res.json()[0]["incident_id"]
    res = client.get(f"/api/incidents/{first_id}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["incident_id"] == first_id

def test_missing_groq_returns_fallback_brief(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]
    res = client.post(f"/api/incidents/{inc_id}/brief")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id

def test_analyst_action_recorded():
    queue_res = client.get("/api/incidents")
    inc_id = queue_res.json()[0]["incident_id"]
    payload = {"action": "investigate", "note": "Test note"}
    res = client.post(f"/api/incidents/{inc_id}/action", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["action"] == "CONFIRM"
