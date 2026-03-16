import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from models import engine, AccessLog
from sqlalchemy import select, func
from datetime import datetime, timedelta

st.set_page_config(page_title="Traefik Advanced Dashboard", layout="wide", page_icon="📈")

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    .stMetric { background-color: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    .stTabs [data-baseweb="tab-list"] { gap: 20px; }
    .stTabs [data-baseweb="tab"] { height: 50px; white-space: pre-wrap; background-color: #f0f2f6; border-radius: 5px 5px 0 0; padding: 10px 20px; }
    .stTabs [aria-selected="true"] { background-color: #e0e4eb; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Traefik Ultimate Monitor")

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

@st.cache_data(ttl=15)
def fetch_data():
    query = select(AccessLog).order_by(AccessLog.start_local.desc())
    df = pd.read_sql(query, engine)
    if not df.empty:
        df['start_local'] = pd.to_datetime(df['start_local'])
        df['duration_ms'] = df['duration'] / 1_000_000 # ns to ms
        df['hour'] = df['start_local'].dt.hour
        df['day_name'] = df['start_local'].dt.day_name()
    return df

df_full = fetch_data()

if df_full.empty:
    st.warning("No traffic data found in PostgreSQL. Please check if the worker is running.")
    if st.button("🔄 Refresh"):
        st.rerun()
else:
    # Sidebar Filters
    st.sidebar.header("🔍 Global Filters")
    time_range = st.sidebar.selectbox("Time Range", ["All", "Last 1h", "Last 24h", "Last 7d", "Last 30d"])
    
    now = datetime.now()
    df = df_full.copy()
    if time_range == "Last 1h":
        df = df[df['start_local'] > (now - timedelta(hours=1))]
    elif time_range == "Last 24h":
        df = df[df['start_local'] > (now - timedelta(days=1))]
    elif time_range == "Last 7d":
        df = df[df['start_local'] > (now - timedelta(days=7))]
    elif time_range == "Last 30d":
        df = df[df['start_local'] > (now - timedelta(days=30))]

    hosts = st.sidebar.multiselect("Filter Hosts", options=df['request_host'].unique(), default=df['request_host'].unique())
    df = df[df['request_host'].isin(hosts)]

    # Layout with Tabs
    tab_overview, tab_traffic, tab_security, tab_clients, tab_investigation = st.tabs([
        "📊 Overview", "📡 Traffic Analysis", "🛡️ Security", "💻 Clients & Bots", "🕵️ IP Investigator"
    ])

    with tab_overview:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Requests", f"{len(df):,}")
        total_bw = df['content_size'].sum()
        c2.metric("Total Bandwidth", format_bytes(total_bw))
        avg_dur = df['duration_ms'].mean()
        c3.metric("Avg Latency", f"{avg_dur:.2f} ms")
        success_rate = (df['status_code'] < 400).mean() * 100
        c4.metric("Success Rate", f"{success_rate:.1f}%")

        st.subheader("Traffic Heatmap (Day vs Hour)")
        heatmap_data = df.groupby(['day_name', 'hour']).size().reset_index(name='count')
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heatmap_pivot = heatmap_data.pivot(index='day_name', columns='hour', values='count').reindex(days_order)
        fig_heat = px.imshow(heatmap_pivot, labels=dict(x="Hour of Day", y="Day of Week", color="Requests"),
                             color_continuous_scale='Viridis', aspect="auto")
        st.plotly_chart(fig_heat, use_container_width=True)

    with tab_traffic:
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("Requests per Service")
            host_counts = df['request_host'].value_counts().reset_index()
            host_counts.columns = ['Host', 'Count']
            fig_hosts = px.bar(host_counts, x='Count', y='Host', orientation='h', color='Count', color_continuous_scale='Bluered')
            st.plotly_chart(fig_hosts, use_container_width=True)

        with col_right:
            st.subheader("Top Paths")
            path_counts = df['request_path'].value_counts().head(15).reset_index()
            path_counts.columns = ['Path', 'Count']
            fig_paths = px.bar(path_counts, x='Count', y='Path', orientation='h')
            st.plotly_chart(fig_paths, use_container_width=True)

        st.subheader("Latency vs Response Size")
        fig_scatter = px.scatter(df.sample(min(len(df), 2000)), x="content_size", y="duration_ms", 
                                 color="status_code", size_max=10, opacity=0.5,
                                 labels={"content_size": "Size (Bytes)", "duration_ms": "Latency (ms)"},
                                 title="Latency vs Content Size Correlation (Sampled)")
        st.plotly_chart(fig_scatter, use_container_width=True)

    with tab_security:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.subheader("HTTP Status Distribution")
            status_dist = df['status_code'].value_counts().reset_index()
            status_dist.columns = ['Status', 'Count']
            fig_status = px.pie(status_dist, names='Status', values='Count', hole=0.4)
            st.plotly_chart(fig_status, use_container_width=True)

        with col_s2:
            st.subheader("Top Error Paths (4xx/5xx)")
            errors_df = df[df['status_code'] >= 400]
            if not errors_df.empty:
                error_paths = errors_df['request_path'].value_counts().head(10).reset_index()
                error_paths.columns = ['Path', 'Count']
                st.table(error_paths)
            else:
                st.info("No errors detected.")

    with tab_clients:
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.subheader("Human vs Bot Traffic")
            bot_dist = df['is_bot'].map({True: 'Bot', False: 'Human'}).value_counts().reset_index()
            bot_dist.columns = ['Type', 'Count']
            fig_bot = px.pie(bot_dist, names='Type', values='Count', color='Type', color_discrete_map={'Bot': '#EF553B', 'Human': '#636EFA'})
            st.plotly_chart(fig_bot, use_container_width=True)

        with col_c2:
            st.subheader("Top Browser Families")
            browser_dist = df['browser_family'].value_counts().head(10).reset_index()
            browser_dist.columns = ['Browser', 'Count']
            st.dataframe(browser_dist, use_container_width=True)

        st.subheader("OS Distribution")
        os_dist = df['os_family'].value_counts().head(10).reset_index()
        os_dist.columns = ['OS', 'Count']
        fig_os = px.bar(os_dist, x='Count', y='OS', orientation='h', color='OS')
        st.plotly_chart(fig_os, use_container_width=True)

    with tab_investigation:
        st.subheader("🕵️ Detailed IP Investigation")
        ip_search = st.text_input("Enter IP Address to search")
        if ip_search:
            ip_df = df_full[df_full['client_addr'] == ip_search]
            if ip_df.empty:
                st.warning(f"No records found for IP {ip_search}")
            else:
                col_i1, col_i2, col_i3 = st.columns(3)
                col_i1.metric("Total Requests", len(ip_df))
                col_i2.metric("First Seen", ip_df['start_local'].min().strftime('%Y-%m-%d %H:%M'))
                col_i3.metric("Last Seen", ip_df['start_local'].max().strftime('%Y-%m-%d %H:%M'))
                
                st.write("**Top Domains Requested:**")
                st.table(ip_df['request_host'].value_counts().head(5))
                
                st.write("**Top Paths Requested:**")
                st.table(ip_df['request_path'].value_counts().head(10))
                
                st.write("**Latest 10 Requests:**")
                st.dataframe(ip_df[['start_local', 'request_method', 'request_host', 'request_path', 'status_code']].head(10))

    st.sidebar.markdown("---")
    st.sidebar.write(f"Last sync: {datetime.now().strftime('%H:%M:%S')}")
    if st.sidebar.button("🔄 Force Refresh"):
        st.rerun()
