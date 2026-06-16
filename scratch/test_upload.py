import os
import requests
import sqlite3

def main():
    print("Testing PCAP Upload API and SQLite storage...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pcap_path = os.path.join(base_dir, "scratch", "traffic_test.pcap")
    db_path = os.path.join(base_dir, "data", "alerts.db")
    
    # 1. Clear database before test
    if os.path.exists(db_path):
        print("Clearing alerts table before test...")
        conn = sqlite3.connect(db_path)
        conn.cursor().execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        
    # 2. POST PCAP to /api/upload_pcap
    url = "http://127.0.0.1:5000/api/upload_pcap"
    print(f"Uploading {pcap_path} to {url}...")
    with open(pcap_path, 'rb') as f:
        files = {'file': f}
        r = requests.post(url, files=files)
        
    print("Response Status Code:", r.status_code)
    if r.status_code != 200:
        print("Error Response Body:", r.text)
    assert r.status_code == 200, f"Error: Status code is {r.status_code}, response: {r.text}"
    
    data = r.json()
    print("Response JSON Status:", data.get("status"))
    summary = data.get("summary", {})
    print("Summary:")
    print(f"  - Total Packets: {summary.get('total_packets')}")
    print(f"  - Total Flows:   {summary.get('total_flows')}")
    print(f"  - Threat Count:  {summary.get('threat_count')}")
    print(f"  - Max Risk:      {summary.get('max_risk')}")
    
    # 3. Check alerts saved in DB
    print("\nQuerying alerts table in database...")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts")
    rows = cursor.fetchall()
    print(f"Database contains {len(rows)} alerts.")
    
    # Verify we have threats
    assert len(rows) > 0, "Error: No threats inserted into database!"
    
    for idx, r in enumerate(rows[:5]):
        print(f"Threat {idx+1}: {r['source_ip']}:{r['src_port']} -> {r['dest_ip']}:{r['dest_port']} | {r['protocol']} | {r['prediction']} | Conf: {r['confidence']*100:.1f}% | Risk: {r['priority_score']} [{r['priority_level']}]")
        
    conn.close()
    
    # 4. Query /api/db_alerts
    db_alerts_url = "http://127.0.0.1:5000/api/db_alerts?limit=5"
    print(f"\nQuerying {db_alerts_url}...")
    r_db = requests.get(db_alerts_url)
    print("Response status:", r_db.status_code)
    assert r_db.status_code == 200
    db_data = r_db.json()
    print("Number of alerts returned from API:", len(db_data.get("alerts", [])))
    
    print("\nAll integration API tests passed successfully!")

if __name__ == '__main__':
    main()
