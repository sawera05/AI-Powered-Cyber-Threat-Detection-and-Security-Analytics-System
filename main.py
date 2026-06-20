import pandas as pd

from analyzer import ThreatAnalyzer
from alerts import AlertSystem
from visualization import VisualizationManager
from prediction import PredictionEngine

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("data/cyber_logs.csv")

# =========================
# ANALYZER
# =========================
analyzer = ThreatAnalyzer(df)

print("\n===== FAILED LOGINS =====")
print(analyzer.failed_login_count())

print("\n===== MALWARE DETECTION =====")
print(analyzer.malware_detection_count())

print("\n===== SUSPICIOUS IPS =====")
print(analyzer.suspicious_ips())

print("\n===== TARGETED USERS =====")
print(analyzer.targeted_users())

# =========================
# VISUALIZATION
# =========================
visualizer = VisualizationManager()
visualizer.attack_graph(df)

# ========================= 
# ALERT SYSTEM
# =========================
alerts = AlertSystem()

failed = analyzer.failed_login_count()
malware = (df["Malware"] != "None").sum()
ips = df["IP_Address"].value_counts()

alerts.check_failed_logins(failed)
alerts.check_malware(malware)
alerts.check_ip_anomaly(ips)

alerts.show_alerts()

# =========================
# PREDICTION ENGINE
# =========================
predictor = PredictionEngine()
result = predictor.generate_alerts(df)

print("\n===== ALERTS =====")
print(result)