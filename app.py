import streamlit as st
import pandas as pd
import plotly.express as px
from models import engine, AccessLog
from sqlalchemy import select
from datetime import datetime, timedelta

st.set_page_config(page_title="Traefik Ultra Monitor", layout="wide", page_icon="🌎")

st.markdown("""
<style>
    [data-testid="stMetric"] { border: 1px solid rgba(255, 255, 255, 0.1); padding: 1rem; border-radius: 0.5rem; background: rgba(255, 255, 255, 0.05); }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] { border-radius: 6px 6px 0px 0px; padding: 10px 20px; background-color: rgba(255, 255, 255, 0.03); }
    .stTabs [aria-selected="true"] { color: #00CC96; border-bottom: 2px solid #00CC96; }
</style>
""", unsafe_allow_html=True)

st.title("🌎 Traefik Ultra Monitor")

@st.cache_data(ttl=10)
def fetch_data():
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc())
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except: return pd.DataFrame()

df_full = fetch_data()

if df_full.empty:
    st.warning("⚠️ No traffic data found.")
    if st.button("🔄 Refresh"): st.rerun()
else:
    # SIDEBAR
    st.sidebar.title("🔍 Time Filter")
    date_mode = st.sidebar.radio("Mode", ["Presets", "Custom Range"])
    
    now = datetime.now()
    df = df_full.copy()
    
    if date_mode == "Presets":
        preset = st.sidebar.selectbox("Range", ["1h", "24h", "7d", "30d", "All Time"], index=1)
        if preset == "1h": df = df[df['start_local'] > (now - timedelta(hours=1))]
        elif preset == "24h": df = df[df['start_local'] > (now - timedelta(days=1))]
        elif preset == "7d": df = df[df['start_local'] > (now - timedelta(days=7))]
        elif preset == "30d": df = df[df['start_local'] > (now - timedelta(days=30))]
    else:
        start_date = st.sidebar.date_input("Start Date", now - timedelta(days=7))
        end_date = st.sidebar.date_input("End Date", now)
        df = df[(df['start_local'].dt.date >= start_date) & (df['start_local'].dt.date <= end_date)]

    hosts = st.sidebar.multiselect("Hosts", options=sorted(df['request_host'].unique()), default=df['request_host'].unique())
    if hosts: df = df[df['request_host'].isin(hosts)]

    # TABS
    tabs = st.tabs(["📊 Overview", "🗺️ Global Map", "🛡️ Security Audit", "🚀 Performance", "🤖 Clients", "🕵️ Investigator"])

    with tabs[0]:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Requests", f"{len(df):,}")
        c2.metric("Attacks Prevented", f"{len(df[df['is_attack'] == True]):,}", delta_color="inverse")
        c3.metric("Avg Latency", f"{df['duration_ms'].mean():.2f} ms")
        c4.metric("Success Rate", f"{(df['status_code'] < 400).mean()*100:.1f}%")

        st.subheader("Traffic Activity")
        timeline = df.set_index('start_local').groupby([pd.Grouper(freq='1min'), 'status_group']).size().unstack(fill_value=0).reset_index()
        st.plotly_chart(px.area(timeline, x='start_local', y=timeline.columns[1:], template="plotly_dark"), use_container_width=True)

    with tabs[1]:
        st.subheader("Global Traffic Distribution")
        geo_counts = df.groupby(['country_name', 'country_code']).size().reset_index(name='Requests')
        fig_map = px.scatter_geo(geo_counts, locations="country_code", hover_name="country_name", size="Requests",
                                 projection="natural earth", template="plotly_dark", color="Requests",
                                 color_continuous_scale=px.colors.sequential.Viridis)
        st.plotly_chart(fig_map, use_container_width=True)

    with tabs[2]:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.subheader("Detected Attack Vectors")
            attacks = df[df['is_attack'] == True]
            if not attacks.empty:
                st.table(attacks['request_path'].value_counts().head(15))
            else: st.success("No attacks detected!")
        with col_s2:
            st.subheader("High-Risk IPs")
            risk_ips = df[df['is_attack'] == True]['client_addr'].value_counts().head(10).reset_index()
            st.dataframe(risk_ips, use_container_width=True)

    with tabs[3]:
        st.subheader("Slowest Host performance")
        slow_hosts = df.groupby('request_host')['duration_ms'].mean().sort_values(ascending=False).reset_index()
        st.plotly_chart(px.bar(slow_hosts, x='duration_ms', y='request_host', orientation='h', template="plotly_dark"), use_container_width=True)

    with tabs[4]:
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.subheader("Top Browsers")
            st.plotly_chart(px.pie(df, names='browser_family', hole=0.4, template="plotly_dark"), use_container_width=True)
        with col_c2:
            st.subheader("Top OS")
            st.plotly_chart(px.pie(df, names='os_family', hole=0.4, template="plotly_dark"), use_container_width=True)

    with tabs[5]:
        st.subheader("IP Investigator")
        ip_in = st.text_input("IP Address...").strip()
        if ip_in:
            res = df_full[df_full['client_addr'] == ip_in]
            if not res.empty:
                st.write(f"**Results for {ip_in} ({res.iloc[0]['country_name']} - {res.iloc[0]['asn']})**")
                st.dataframe(res[['start_local', 'request_method', 'request_host', 'request_path', 'status_code', 'is_attack']].head(50), use_container_width=True)
            else: st.warning("No data found.")

    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh Data"): st.rerun()
