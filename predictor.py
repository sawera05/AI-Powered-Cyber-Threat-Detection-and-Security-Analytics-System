class PredictionEngine:

    def generate_alerts(self, df):

        alerts = []
        risk_score = 0

        # --------------------------
        # Failed login analysis
        # --------------------------
        failed_attempts = (df["Status"] == "Failed").sum()

        if failed_attempts > 3:
            alerts.append("High Failed Login Attempts Detected")
            risk_score += 2

        # --------------------------
        # IP anomaly detection
        # --------------------------
        ip_counts = df["IP_Address"].value_counts()

        suspicious_ips = ip_counts[ip_counts > 2]

        if not suspicious_ips.empty:
            alerts.append("Suspicious IP Activity Detected")
            risk_score += 2

        # --------------------------
        # Malware detection
        # --------------------------
        malware_count = (df["Malware"] != "None").sum()

        if malware_count > 2:
            alerts.append("Multiple Malware Events Detected")
            risk_score += 3

        # --------------------------
        # Final risk classification
        # --------------------------
        if risk_score >= 6:
            level = "CRITICAL"
        elif risk_score >= 3:
            level = "HIGH"
        else:
            level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "alerts": alerts
        }