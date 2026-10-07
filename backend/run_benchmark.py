import time
import sys
from fastapi.testclient import TestClient
from app.main import app
from app.database.models import Base
from app.database.connection import engine

def main():
    print("Starting 3,000-Alert E2E Benchmark...")
    
    # Initialize DB (just in case)
    Base.metadata.create_all(bind=engine)
    
    client = TestClient(app)
    
    start_time = time.time()
    try:
        response = client.post(
            "/api/triage/run", 
            json={"source": "dataset", "reset": True}
        )
        data = response.json()
        end_time = time.time()
        
        print(f"Benchmark completed successfully in {end_time - start_time:.2f} seconds.")
        print("Response payload:")
        print(data)
        
    except Exception as e:
        print(f"Error during benchmark: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
