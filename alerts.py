from datetime import datetime

class AlertSystem:

    def __init__(self):
        self.alerts = []

    # --------------------------
    # Core alert handler
    # --------------------------
    def add_alert(self, message, severity="LOW", source=None):

        alert = {
            "timestamp": datetime.now(),
            "message": message,
            "severity": severity,
            "source": source
        }

        self.alerts.append(alert)

    # --------------------------
    # Failed login check
    # --------------------------
    def check_failed_logins(self, failed_count):

        if failed_count > 10:
            self.add_alert(
                "Critical Failed Login Attempts Detected",
                severity="CRITICAL"
            )
        elif failed_count > 3:
            self.add_alert(
                "High Failed Login Attempts Detected",
                severity="HIGH"
            )

    # --------------------------
    # IP anomaly check
    # --------------------------
    def check_ip_anomaly(self, ip_series):

        if ip_series.max() > 5:
            self.add_alert(
                "Severe IP Abnormal Activity Detected",
                severity="CRITICAL"
            )
        elif ip_series.max() > 2:
            self.add_alert(
                "Suspicious IP Activity Detected",
                severity="MEDIUM"
            )

    # --------------------------
    # Malware check
    # --------------------------
    def check_malware(self, malware_count):

        if malware_count > 5:
            self.add_alert(
                "Widespread Malware Infection Detected",
                severity="CRITICAL"
            )
        elif malware_count > 2:
            self.add_alert(
                "Multiple Malware Events Detected",
                severity="HIGH"
            )

    # --------------------------
    # Structured output for dashboard
    # --------------------------
    def show_alerts(self):

        return sorted(
            self.alerts,
            key=lambda x: x["severity"],
            reverse=True
        )