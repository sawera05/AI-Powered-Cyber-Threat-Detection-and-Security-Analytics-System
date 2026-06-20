import pandas as pd

class ThreatAnalyzer:

    def __init__(self, dataframe):
        self.df = dataframe.copy()
        self.df.fillna("Unknown", inplace=True)

    # ---------------------------
    # Failed login analysis
    # ---------------------------
    def failed_login_count(self):
        return (self.df["Status"] == "Failed").sum()

    def failed_login_by_user(self):
        return self.df.loc[self.df["Status"] == "Failed", "Username"].value_counts()

    # ---------------------------
    # Malware detection
    # ---------------------------
    def malware_detection_count(self):
        malware_df = self.df[self.df["Malware"].notna()]
        malware_df = malware_df[malware_df["Malware"] != "None"]
        return malware_df["Malware"].value_counts()

    def infected_hosts(self):
        malware_df = self.df[self.df["Malware"] != "None"]
        return malware_df["IP_Address"].value_counts()

    # ---------------------------
    # IP behavioral risk (normalized)
    # ---------------------------
    def suspicious_ips(self, threshold=5):
        ip_counts = self.df["IP_Address"].value_counts()

        # Normalize instead of raw count
        normalized = ip_counts / len(self.df)

        return normalized[normalized > (threshold / len(self.df))]

    # ---------------------------
    # User activity profiling
    # ---------------------------
    def targeted_users(self, top_n=10):
        return self.df["Username"].value_counts().head(top_n)

    # ---------------------------
    # Improved anomaly scoring
    # ---------------------------
    def anomaly_score(self):

        ip_counts = self.df["IP_Address"].value_counts()
        user_counts = self.df["Username"].value_counts()

        self.df["ip_score"] = self.df["IP_Address"].map(ip_counts)
        self.df["user_score"] = self.df["Username"].map(user_counts)

        # weighted scoring (better than simple sum)
        self.df["risk_score"] = (
            (self.df["ip_score"] * 0.6) +
            (self.df["user_score"] * 0.4)
        )

        return self.df.sort_values("risk_score", ascending=False)