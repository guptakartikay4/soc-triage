import httpx
import time
import json
import sys

BASE_URL = "http://localhost:8000"

def run_demo():
    print("==================================================")
    print("SOC Alert Triage and Incident Prioritization Demo")
    print("==================================================")
    
    print("\n1. Resetting database and running full triage pipeline on 3,000 synthetic alerts...")
    try:
        response = httpx.post(f"{BASE_URL}/api/triage/run", json={"source": "dataset", "reset": True}, timeout=120.0)
        response.raise_for_status()
        triage_result = response.json()
        print(f"Pipeline completed in {triage_result['total_seconds']} seconds.")
        print(f"Alerts processed: {triage_result['alerts_processed']}")
        print(f"Incidents created: {triage_result['incidents_created']}")
        print(f"Stage timings: {json.dumps(triage_result['timings'], indent=2)}")
    except Exception as e:
        print(f"Failed to run pipeline: {e}")
        sys.exit(1)
        
    print("\n2. Fetching dashboard metrics overview...")
    try:
        metrics = httpx.get(f"{BASE_URL}/api/metrics/overview").json()
        print(f"Total Incidents: {metrics['total_incidents']} (P1: {metrics['critical_incidents']}, P2: {metrics['high_incidents']})")
        print(f"Average Risk: {metrics['average_risk']}")
    except Exception as e:
        print(f"Failed to fetch metrics: {e}")

    print("\n3. Listing top 5 prioritized incidents...")
    try:
        incidents = httpx.get(f"{BASE_URL}/api/incidents?limit=5").json()
        for inc in incidents:
            print(f"- {inc['incident_id']} (Priority: {inc['priority']}, Risk: {inc['risk_score']}): {inc['alert_count']} alerts, {inc['affected_assets']}")
            print(f"  Explanation: {inc['risk_explanation']}")
    except Exception as e:
        print(f"Failed to list incidents: {e}")
        incidents = []

    if incidents:
        target_incident = incidents[0]['incident_id']
        print(f"\n4. Fetching AI Brief for the highest priority incident ({target_incident})...")
        try:
            brief = httpx.post(f"{BASE_URL}/api/incidents/{target_incident}/brief").json()
            print(f"Summary: {brief['summary']}")
            print(f"Confidence: {brief['confidence']} (Source: {brief['generation_source']})")
            print("Recommended Steps:")
            for step in brief['recommended_next_steps']:
                print(f"  - {step}")
        except Exception as e:
            print(f"Failed to fetch brief: {e}")

        print(f"\n5. Analyst taking action 'ESCALATE' on {target_incident} to simulate MTTT...")
        time.sleep(2) # Simulate analyst reading time
        try:
            action = httpx.post(
                f"{BASE_URL}/api/incidents/{target_incident}/action", 
                json={"action": "escalate", "note": "Looks critical, escalating to Tier 2."}
            ).json()
            print(f"Action recorded: {action['action']}")
        except Exception as e:
            print(f"Failed to record action: {e}")

        print("\n6. Fetching updated dashboard metrics overview for MTTT...")
        try:
            metrics = httpx.get(f"{BASE_URL}/api/metrics/overview").json()
            print(f"Triaged Count: {metrics['triaged_count']}")
            print(f"Average MTTT (seconds): {metrics['average_mttt_seconds']}")
        except Exception as e:
            print(f"Failed to fetch metrics: {e}")
            
    print("\nDemo completed.")

if __name__ == "__main__":
    run_demo()
