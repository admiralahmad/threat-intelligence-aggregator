# dashboard.py

from datetime import datetime, timedelta
import os, time, gzip, json, platform
import requests, pandas as pd
import streamlit as st

DATA_DIR = "data"
OUTPUT_DIR = "outputs"
GZ_FILE = os.path.join(DATA_DIR, "nvdcve-modified.json.gz")
JSON_FILE = os.path.join(OUTPUT_DIR, "nvdcve-modified.json")
CACHE_FILE = os.path.join(DATA_DIR, "last_fetch.txt")
URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

def should_fetch_new_data():
    if not os.path.exists(CACHE_FILE):
        return True
    last_time = float(open(CACHE_FILE).read().strip())
    return time.time() - last_time > 86400  # 24 hours

def record_fetch_time():
    with open(CACHE_FILE, "w") as f:
        f.write(str(time.time()))

def fetch_feed():
    try:
        r = requests.get(URL, stream=True, timeout=60)
        r.raise_for_status()
        with open(GZ_FILE, "wb") as f:
            f.write(r.content)
        return True
    except Exception as e:
        st.error(f"❌ Error fetching CVE feed: {e}")
        return False

def extract_json():
    try:
        with gzip.open(GZ_FILE, "rb") as f_in:
            data = json.loads(f_in.read().decode("utf-8"))
        with open(JSON_FILE, "w") as f_out:
            json.dump(data, f_out)
        return data["CVE_Items"]
    except Exception as e:
        st.error(f"❌ Failed to extract JSON: {e}")
        return []

def filter_cves(items, keywords, days_back, min_score):
    recent_cut = datetime.utcnow() - timedelta(days=days_back)
    rows = []
    for i in items:
        desc = i["cve"]["description"]["description_data"][0]["value"].lower()
        pub = datetime.strptime(i["publishedDate"][:10], "%Y-%m-%d")
        try:
            score = i["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        except KeyError:
            score = i.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore", 0)
        if pub >= recent_cut and score >= min_score:
            rows.append({
                "CVE_ID": i["cve"]["CVE_data_meta"]["ID"],
                "Date": pub.date(),
                "Score": score,
                "Description": desc[:180] + ("..." if len(desc) > 180 else ""),
                "KeywordHit": any(k in desc for k in keywords)
            })
    return pd.DataFrame(rows)

def run_dashboard():
    st.set_page_config(page_title="CVE Intelligence Dashboard", layout="wide")
    st.title("🛡️ CVE Threat Intelligence Dashboard")
    st.caption(f"Running on **{platform.system()}** | Auto-refresh every 24 hours")

    # Sidebar filters
    with st.sidebar:
        st.header("🔍 Filter Settings")
        days_back = st.slider("Show CVEs from past days:", 1, 60, 30)
        min_score = st.slider("Minimum CVSS Score:", 0.0, 10.0, 8.0, 0.1)
        keyword_input = st.text_input("Keywords (comma-separated):", "Active Directory, Solarwinds, PHP, Entra, Windows, Apple, Apache, Linux")
        keywords = [k.strip().lower() for k in keyword_input.split(",") if k.strip()]

        if st.button("🔄 Refresh Feed Now"):
            if fetch_feed():
                record_fetch_time()
                st.success("✅ Feed refreshed successfully!")
                st.rerun()

    # Auto update check
    if should_fetch_new_data():
        if fetch_feed():
            record_fetch_time()
            st.toast("✅ Fetched latest CVE feed")

    # Show last update time
    if os.path.exists(CACHE_FILE):
        last_fetch = datetime.fromtimestamp(float(open(CACHE_FILE).read()))
        st.caption(f"🕒 Last updated: {last_fetch.strftime('%Y-%m-%d %H:%M:%S')}")

    if os.path.exists(GZ_FILE):
        items = extract_json()
        df = filter_cves(items, keywords, days_back, min_score)

        st.subheader(f"📝 Filtered CVEs ({len(df)} found)")
        st.dataframe(df, use_container_width=True)

        st.download_button("⬇️ Download JSON", df.to_json(orient="records", indent=2).encode(), "filtered_cves.json", "application/json")

        st.bar_chart(df["Score"].value_counts().sort_index())

run_dashboard()
