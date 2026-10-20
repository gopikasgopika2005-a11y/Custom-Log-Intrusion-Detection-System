\# Custom Log Intrusion Detection System (IDS)



\## Project Overview

A beginner-friendly, rule-based Intrusion Detection System built with Python. It analyzes custom security logs, detects repeated failed login attempts from the same IP address within a five-minute window, generates alerts, and displays results on a Streamlit dashboard.



\## Features

\- Custom log file analysis using Python

\- Time-based brute-force detection

\- HIGH severity alert generation

\- CSV alert report

\- SQLite database for storing detected alerts

\- Streamlit dashboard with alert metrics and charts

\- CSV report download from the dashboard



\## Technologies Used

\- Python

\- Regular Expressions

\- SQLite

\- Pandas

\- Streamlit

\- CSV



\## Project Files

\- `ids.py` — log analysis and intrusion detection

\- `sample\_logs.txt` — sample security logs for testing

\- `database\_setup.py` — creates the SQLite database and alerts table

\- `view\_alerts.py` — displays saved alerts

\- `dashboard.py` — interactive security dashboard

\- `requirements.txt` — Python dependencies



\## Detection Logic

The system flags a source IP when five or more failed login attempts occur within a five-minute window.



This is a rule-based prototype for educational purposes. It is not a production-grade security monitoring solution.



\## Setup and Usage



\### 1. Install dependencies

```bash

python -m pip install -r requirements.txt

```



\### 2. Create the database

```bash

python database\_setup.py

```



\### 3. Analyze the sample logs

```bash

python ids.py

```



\### 4. View saved alerts

```bash

python view\_alerts.py

```



\### 5. Launch the dashboard

```bash

python -m streamlit run dashboard.py

```



Open the local URL displayed in the terminal, usually `http://localhost:8501`.



\## Testing

Test the system using sample log entries with different timestamps. Verify both:

\- Five or more failed attempts within five minutes trigger an alert.

\- Attempts spread across a longer period do not trigger the same threshold alert.



\## Future Improvements

\- Prevent duplicate alert records

\- Add log filtering and date-range search

\- Improve alert severity classification

\- Add authentication and more robust log parsing

\- Expand test coverage



\## Disclaimer

This project is intended for educational and authorized defensive security testing only.



