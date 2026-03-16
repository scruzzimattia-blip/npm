import streamlit as st
import pandas as pd
import json
import plotly.express as px
from datetime import datetime

st.set_page_config(page_title="Traefik Stats", layout="wide")

st.title("📊 Traefik Access Log Dashboard")

LOG_FILE = "/app/logs/access.log"

@st.cache_data(ttl=10)
def load_data():
    data = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return pd.DataFrame()
    
    if not data:
        return pd.DataFrame()
    
    df = pd.DataFrame(data)
    # Convert StartLocal to datetime
    if 'StartLocal' in df.columns:
        df['StartLocal'] = pd.to_datetime(df['StartLocal'])
    return df

df = load_data()

if df.empty:
    st.warning("No data found in access.log yet. Please wait for Traefik to log some requests.")
    if st.button("Refresh"):
        st.rerun()
else:
    # Sidebar filters
    st.sidebar.header("Filters")
    if 'EntryPointName' in df.columns:
        entry_point = st.sidebar.multiselect("Entry Point", options=df['EntryPointName'].unique(), default=df['EntryPointName'].unique())
        df = df[df['EntryPointName'].isin(entry_point)]
    
    if 'RequestMethod' in df.columns:
        methods = st.sidebar.multiselect("Request Method", options=df['RequestMethod'].unique(), default=df['RequestMethod'].unique())
        df = df[df['RequestMethod'].isin(methods)]

    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", len(df))
    if 'DownstreamStatus' in df.columns:
        success_rate = (df['DownstreamStatus'].astype(int) < 400).mean() * 100
        col2.metric("Success Rate", f"{success_rate:.1f}%")
        col3.metric("Errors (4xx/5xx)", len(df[df['DownstreamStatus'].astype(int) >= 400]))
    if 'Duration' in df.columns:
        avg_duration = df['Duration'].mean() / 1_000_000 # Convert to ms if it's in ns
        col4.metric("Avg Duration", f"{avg_duration:.2f}ms")

    # Charts
    st.subheader("Requests over Time")
    if 'StartLocal' in df.columns:
        df_time = df.set_index('StartLocal').resample('1min').size().reset_index(name='count')
        fig_time = px.line(df_time, x='StartLocal', y='count', title="Requests per Minute")
        st.plotly_chart(fig_time, use_container_width=True)

    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Status Codes")
        if 'DownstreamStatus' in df.columns:
            fig_status = px.pie(df, names='DownstreamStatus', title="Response Status Distribution")
            st.plotly_chart(fig_status, use_container_width=True)

    with c2:
        st.subheader("Top Paths")
        if 'RequestPath' in df.columns:
            top_paths = df['RequestPath'].value_counts().head(10).reset_index()
            top_paths.columns = ['Path', 'Count']
            fig_paths = px.bar(top_paths, x='Count', y='Path', orientation='h', title="Top 10 Requested Paths")
            st.plotly_chart(fig_paths, use_container_width=True)

    st.subheader("Top Clients (IP)")
    if 'ClientAddr' in df.columns:
        top_ips = df['ClientAddr'].value_counts().head(10).reset_index()
        top_ips.columns = ['IP', 'Count']
        st.table(top_ips)

    if st.button("Refresh Data"):
        st.rerun()
