import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from io import StringIO


# ---------------------------------------------------------
# 1. 核心解析函数 (合并 status 与 perf status)
# ---------------------------------------------------------
def parse_fortigate_logs(file_content):
    records = []
    current_record = {}

    # 默认后备时间，以防日志中完全没有找到 system time
    current_time = pd.Timestamp("2026-04-01 08:00:00")

    # --- 新增：提取 System time 的正则表达式 ---
    # 匹配例如 "System time: Tue Jan 11 18:30:30 2022"
    regex_time = re.compile(r"^System time:\s+(.+)")

    # 原有的性能提取正则
    regex_cpu = re.compile(r"^CPU states:\s+\d+% user\s+\d+% system.*?\s+(\d+)% idle")
    regex_mem = re.compile(r"^Memory:.*?([\d\.]+)%\)")
    regex_bw = re.compile(r"^Average network usage:\s+(\d+)\s+/\s+(\d+)\s+kbps in 1 minute")
    regex_sess = re.compile(r"^Average sessions:\s+(\d+)\s+sessions in 1 minute")
    regex_setup = re.compile(r"^Average session setup rate:\s+(\d+)\s+sessions per second")

    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()

        # --- 新增逻辑：检查是否包含系统时间 ---
        match_time = regex_time.search(line)
        if match_time:
            time_str = match_time.group(1)
            try:
                # pandas 可以自动解析 "Tue Jan 11 18:30:30 2022" 这种格式
                current_time = pd.to_datetime(time_str)
            except Exception as e:
                # 如果解析失败，仍然使用上一次的时间
                pass
            continue

        # 1. 检查 CPU 行 (作为新一次性能数据收集的起点)
        match_cpu = regex_cpu.search(line)
        if match_cpu:
            if current_record:
                records.append(current_record)
                # 如果遇到新的数据块，默认时间向后推移 1 分钟
                # 如果紧接着下一行又读取到了真实的 System time，这个推移会被覆盖纠正
                current_time += pd.Timedelta(minutes=1)

                # 使用获取到的真实时间（或推移后的时间）建立新记录
            current_record = {'Timestamp': current_time}
            idle_cpu = int(match_cpu.group(1))
            current_record['CPU_Usage'] = 100 - idle_cpu
            continue

        # 2. 检查 内存 行
        match_mem = regex_mem.search(line)
        if match_mem:
            current_record['Memory_Usage'] = float(match_mem.group(1))
            continue

        # 3. 检查 带宽 行
        match_bw = regex_bw.search(line)
        if match_bw:
            current_record['Bandwidth_Rx'] = int(match_bw.group(1))
            current_record['Bandwidth_Tx'] = int(match_bw.group(2))
            continue

        # 4. 检查 会话 行
        match_sess = regex_sess.search(line)
        if match_sess:
            current_record['Sessions'] = int(match_sess.group(1))
            continue

        # 5. 检查 新建速率 行
        match_setup = regex_setup.search(line)
        if match_setup:
            current_record['Setup_Rate'] = int(match_setup.group(1))
            continue

    # 保存最后一组数据
    if current_record:
        records.append(current_record)

    return pd.DataFrame(records)


# ---------------------------------------------------------
# 2. Web 界面与主逻辑 (UI)
# ---------------------------------------------------------
def main():
    st.set_page_config(page_title="Fortigate 性能报告", layout="wide")
    st.title("📈 性能数据可视化大屏")
    st.markdown("支持混合解析 `get system status` (提取时间) 与 `get sys perf status` (提取指标)。")

    uploaded_file = st.file_uploader("上传包含状态和性能的日志文件 (.txt 或 .log)", type=['txt', 'log'])

    if uploaded_file is not None:
        stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
        file_content = stringio.read()

        df = parse_fortigate_logs(file_content)

        if not df.empty:
            st.success(f"成功解析 {len(df)} 组数据记录！数据起始时间: **{df['Timestamp'].iloc[0]}**")

            # 布局 1：带宽、会话、新建速率
            col1, col2, col3 = st.columns(3)

            with col1:
                fig_bw = go.Figure()
                if 'Bandwidth_Rx' in df.columns and 'Bandwidth_Tx' in df.columns:
                    fig_bw.add_trace(go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Rx'], mode='lines', name='Rx (kbps)',
                                                line=dict(color='blue')))
                    fig_bw.add_trace(go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Tx'], mode='lines', name='Tx (kbps)',
                                                line=dict(color='red')))
                    fig_bw.update_layout(title="Bandwidth", margin=dict(l=0, r=0, t=30, b=0), height=300)
                    st.plotly_chart(fig_bw, use_container_width=True)

            with col2:
                if 'Sessions' in df.columns:
                    fig_sess = px.line(df, x='Timestamp', y='Sessions', title="Sessions")
                    fig_sess.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_sess.update_traces(line_color='#1f77b4')
                    st.plotly_chart(fig_sess, use_container_width=True)

            with col3:
                if 'Setup_Rate' in df.columns:
                    fig_setup = px.line(df, x='Timestamp', y='Setup_Rate', title="Setup Rate (cps)")
                    fig_setup.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
                    st.plotly_chart(fig_setup, use_container_width=True)

            # 布局 2：CPU 与 内存
            col4, col5, col6 = st.columns(3)

            with col4:
                if 'CPU_Usage' in df.columns:
                    fig_cpu = px.line(df, x='Timestamp', y='CPU_Usage', title="CPU Usage (%)")
                    fig_cpu.update_layout(yaxis_range=[0, 100], margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_cpu.update_traces(line_color='purple')
                    st.plotly_chart(fig_cpu, use_container_width=True)

            with col5:
                if 'Memory_Usage' in df.columns:
                    fig_mem = px.line(df, x='Timestamp', y='Memory_Usage', title="Memory Usage (%)")
                    fig_mem.update_layout(yaxis_range=[0, 100], margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_mem.update_traces(line_color='green')
                    st.plotly_chart(fig_mem, use_container_width=True)

            with st.expander("查看解析出的原始数据表 (带真实时间戳)"):
                st.dataframe(df)

        else:
            st.error("无法解析数据，请检查日志文件格式。")


if __name__ == "__main__":
    main()