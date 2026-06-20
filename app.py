import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from analyzer import ThreatAnalyzer
from alerts import AlertSystem

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="Cyber SOC Dashboard",
    layout="wide"
)

st.title("🛡 Cyber Threat Detection SOC Dashboard")

# =========================
# LOAD DATA (SESSION SAFE)
# =========================
if "df" not in st.session_state:
    st.session_state.df = pd.read_csv("data/cyber_logs.csv")

df = st.session_state.df

# =========================
# OBJECTS
# =========================
analyzer = ThreatAnalyzer(df)
alerts = AlertSystem()

# =========================
# SIDEBAR
# =========================
st.sidebar.title("SOC PANEL")

menu = st.sidebar.selectbox(
    "Select Module",
    ["Analysis", "Visualization", "Alerts"]
)

# =========================
# ANALYSIS
# =========================
if menu == "Analysis":

    st.subheader("📊 Threat Analysis")

    st.write("Failed Logins:", analyzer.failed_login_count())
    st.write("Malware Events:", analyzer.malware_detection_count())
    st.write("Suspicious IPs:", analyzer.suspicious_ips())
    st.write("Top Users:", analyzer.targeted_users())

# =========================
# VISUALIZATION (ALL GRAPHS)
# =========================
elif menu == "Visualization":

    st.subheader("📈 Security Visualizations")

    # 1 Attack Types
    fig1, ax1 = plt.subplots()
    df["Event_Type"].value_counts().plot(kind="bar", ax=ax1)
    ax1.set_title("Attack Types")
    st.pyplot(fig1)

    # 2 Malware Pie
    fig2, ax2 = plt.subplots()
    df[df["Malware"] != "None"]["Malware"].value_counts().plot(
        kind="pie",
        autopct="%1.1f%%",
        ax=ax2
    )
    ax2.set_title("Malware Distribution")
    ax2.set_ylabel("")
    st.pyplot(fig2)

    # 3 IP Activity
    fig3, ax3 = plt.subplots()
    df["IP_Address"].value_counts().plot(kind="barh", ax=ax3)
    ax3.set_title("IP Activity")
    st.pyplot(fig3)

    # 4 User Activity
    fig4, ax4 = plt.subplots()
    df["Username"].value_counts().plot(kind="line", marker="o", ax=ax4)
    ax4.set_title("User Activity")
    st.pyplot(fig4)

    # 5 Status Distribution
    fig5, ax5 = plt.subplots()
    df["Status"].value_counts().plot(kind="bar", ax=ax5)
    ax5.set_title("Status Distribution")
    st.pyplot(fig5)

    # 6 Histogram
    fig6, ax6 = plt.subplots()
    df["Username"].value_counts().plot(kind="hist", bins=5, ax=ax6)
    ax6.set_title("Login Distribution")
    st.pyplot(fig6)

    # 7 Scatter Plot
    temp = df.copy()
    temp["failed"] = (temp["Status"] == "Failed").astype(int)
    temp["malware_flag"] = (temp["Malware"] != "None").astype(int)

    fig7, ax7 = plt.subplots()
    ax7.scatter(temp["failed"], temp["malware_flag"])
    ax7.set_title("Failed vs Malware")
    st.pyplot(fig7)

    # 8 Correlation Heatmap
    corr = temp[["failed", "malware_flag"]].corr()

    fig8, ax8 = plt.subplots()
    sns.heatmap(corr, annot=True, cmap="coolwarm", ax=ax8)
    ax8.set_title("Correlation Heatmap")
    st.pyplot(fig8)

# =========================
# ALERTS
# =========================
elif menu == "Alerts":

    st.subheader("🚨 Security Alerts")

    alerts.alerts = []

    failed = analyzer.failed_login_count()
    malware = (df["Malware"] != "None").sum()
    ips = df["IP_Address"].value_counts()

    alerts.check_failed_logins(failed)
    alerts.check_malware(malware)
    alerts.check_ip_anomaly(ips)

    if not alerts.alerts:
        st.success("No Threats Detected")

    for alert in alerts.alerts:
        if isinstance(alert, dict):
            st.error(alert["message"])
        else:
            st.error(alert)

# =========================
# FOOTER
# =========================
st.markdown("---")
st.markdown("### 🔐 Cyber Threat Detection System")