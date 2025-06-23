# 🛡️ Threat Intelligence Aggregator

A dynamic Streamlit-based dashboard that fetches and analyzes the latest CVEs from the National Vulnerability Database (NVD). It provides keyword-based filtering, CVSS score selection, and real-time visual insights—making it ideal for analysts, security teams, and cyber threat researchers.

## 🚀 Features

- 🔄 Auto-refresh CVE feed every 24 hours
- 📥 Manual refresh with one click
- 🧠 Keyword-based filtering (e.g., "nigeria", "ecowas", "telecom")
- 🎯 CVSS score slider to prioritize high-severity threats
- 📊 Bar chart visualization for score distribution
- 💾 Download filtered CVEs as JSON
- 🖥️ Fully responsive Streamlit UI, deployable online

## 📂 Folder Structure

threat-intelligence-aggregator/
├── dashboard.py
├── data/ # CVE feed archive (auto-generated)
├── outputs/ # JSON output (auto-generated)
├── requirements.txt
└── README.md


## 📦 Installation

```bash
git clone https://github.com/admiralahmad/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
pip install -r requirements.txt
streamlit run dashboard.py

