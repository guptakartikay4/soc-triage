from fastapi import FastAPI

from app.api.alerts import router as alerts_router

app = FastAPI(title="SOC Triage API", version="0.1.0")

app.include_router(alerts_router)


@app.get("/api/health")
def health():
    return {"status": "ok"}