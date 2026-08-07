import requests

UBUNTU_IP = "172.20.10.3"
SURICATA_URL = f"http://{UBUNTU_IP}:8888/ids"

def get_ids_summary():
    try:
        res = requests.get(SURICATA_URL, timeout=5)
        return res.json()
    except Exception as ex:
        return {
            "status": "unavailable", "connected": False,
            "total_alerts": 0, "critical": 0,
            "high": 0, "medium": 0,
            "top_signature": "N/A", "alerts": [],
            "error": str(ex)
        }