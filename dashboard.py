
import sqlite3
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Custom Log IDS",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Custom Log Intrusion Detection System")
st.caption("Security monitoring dashboard")

DB_FILE = "ids.db"


def load_alerts():
    connection = sqlite3.connect(DB_FILE)

    try:
        df = pd.read_sql_query(
            """
            SELECT
                id,
                source_ip,
                failed_attempts,
                window_start,
                window_end,
                severity,
                alert_message
            FROM alerts
            ORDER BY id DESC
            """,
            connection
        )
        return df
    finally:
        connection.close()


try:
    df = load_alerts()

    total_alerts = len(df)
    unique_ips = (
        df["source_ip"].nunique() if not df.empty else 0
    )
    high_alerts = (
        (df["severity"] == "HIGH").sum()
        if not df.empty else 0
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Alerts", total_alerts)
    col2.metric("Suspicious IPs", unique_ips)
    col3.metric("High Severity Alerts", int(high_alerts))

    st.subheader("Detected Security Alerts")

    if df.empty:
        st.info("No alerts found in the database.")
    else:
        st.dataframe(df, use_container_width=True)

        st.subheader("Alerts by Source IP")
        ip_counts = df["source_ip"].value_counts()
        st.bar_chart(ip_counts)

        st.subheader("Download Report")
        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download Alerts CSV",
            data=csv_data,
            file_name="security_alerts.csv",
            mime="text/csv"
        )

except sqlite3.Error as error:
    st.error(f"Database error: {error}")
