from sklearn.ensemble import IsolationForest
import pandas as pd

class AnomalyDetector:

    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)

    # --------------------------
    # Feature engineering
    # --------------------------
    def _prepare_features(self, df):

        df = df.copy()

        df["failed_flag"] = (df["Status"] == "Failed").astype(int)
        df["malware_flag"] = (df["Malware"] != "None").astype(int)

        ip_counts = df["IP_Address"].value_counts()
        user_counts = df["Username"].value_counts()

        df["ip_frequency"] = df["IP_Address"].map(ip_counts)
        df["user_frequency"] = df["Username"].map(user_counts)

        features = df[[
            "failed_flag",
            "malware_flag",
            "ip_frequency",
            "user_frequency"
        ]]

        return df, features

    # --------------------------
    # Train model
    # --------------------------
    def train_model(self, df):

        df, features = self._prepare_features(df)
        self.model.fit(features)

        df["anomaly"] = self.model.predict(features)

        # Convert output
        df["anomaly_label"] = df["anomaly"].map({1: "Normal", -1: "Suspicious"})

        return df

    # --------------------------
    # Predict on new data
    # --------------------------
    def predict(self, df):

        df, features = self._prepare_features(df)

        df["anomaly"] = self.model.predict(features)
        df["anomaly_label"] = df["anomaly"].map({1: "Normal", -1: "Suspicious"})

        return df