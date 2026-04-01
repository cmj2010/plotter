import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from io import StringIO


# ---------------------------------------------------------
# 1. 核心解析函数 (基于 get sys perf status)
# ---------------------------------------------------------
def parse_perf_status(file_content):
    records = []
    current_record = {}

    # 预设一个起始时间（用于填补日志中没有时间戳的情况）
    mock_time = pd.Timestamp("2026-04-01 08:00:00")

    # 编译正则表达式，精确匹配每行数据的关键信息
    # 匹配总体 CPU: 提取 idle 值，使用率 = 100 - idle
    regex_cpu = re.compile(r"^CPU states:\s+\d+% user\s+\d+% system.*?\s+(\d+)% idle")
    # 匹配内存: 提取括号里的百分比数字，例如 (72.7%)
    regex_mem = re.compile(r"^Memory:.*?([\d\.]+)%\)")
    # 匹配带宽: 提取 1 分钟内的 Rx / Tx kbps
    regex_bw = re.compile(r"^Average network usage:\s+(\d+)\s+/\s+(\d+)\s+kbps in 1 minute")
    # 匹配会话数: 提取 1 分钟内的 sessions
    regex_sess = re.compile(r"^Average sessions:\s+(\d+)\s+sessions in 1 minute")
    # 匹配新建速率: 提取 1 分钟内的 setup rate
    regex_setup = re.compile(r"^Average session setup rate:\s+(\d+)\s+sessions per second")

    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()

        # 1. 检查 CPU 行 (通常作为新一次数据收集的起点)
        match_cpu = regex_cpu.search(line)
        if match_cpu:
            # 如果 current_record 里已经有数据，说明上一组数据收集完了，存入列表
            if current_record:
                records.append(current_record)
                mock_time += pd.Timedelta(minutes=1)  # 模拟时间推移 1 分钟

            # 开始新的一组数据
            current_record = {'Timestamp': mock_time}
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

    # 循环结束后，不要忘记把最后一组数据也加进去
    if current_record:
        records.append(current_record)

    return pd.DataFrame(records)


# ---------------------------------------------------------
# 2. Web 界面与主逻辑 (UI)
# ---------------------------------------------------------
def main():
    st.set_page_config(page_title="Fortigate 性能报告", layout="wide")
    st.title("📈 性能数据可视化大屏")
    st.markdown("解析 `get sys perf status` 日志，生成类似官方报告的趋势图。")

    uploaded_file = st.file_uploader("上传 perf status 日志文件 (.txt 或 .log)", type=['txt', 'log'])

    if uploaded_file is not None:
        stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
        file_content = stringio.read()

        df = parse_perf_status(file_content)

        if not df.empty:
            st.success(f"成功解析 {len(df)} 组数据记录！")

            # 使用 Streamlit 的列布局，一行放 3 个图，还原 PDF 上的紧凑感
            col1, col2, col3 = st.columns(3)

            # 【图表 1：带宽 Bandwidth】
            with col1:
                fig_bw = go.Figure()
                # 绘制 Rx (接收) 和 Tx (发送) 两条线
                if 'Bandwidth_Rx' in df.columns and 'Bandwidth_Tx' in df.columns:
                    fig_bw.add_trace(go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Rx'], mode='lines', name='Rx (kbps)',
                                                line=dict(color='blue')))
                    fig_bw.add_trace(go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Tx'], mode='lines', name='Tx (kbps)',
                                                line=dict(color='red')))
                    fig_bw.update_layout(title="Bandwidth", margin=dict(l=0, r=0, t=30, b=0), height=300)
                    st.plotly_chart(fig_bw, use_container_width=True)

            # 【图表 2：会话数 Sessions】
            with col2:
                if 'Sessions' in df.columns:
                    fig_sess = px.line(df, x='Timestamp', y='Sessions', title="Sessions")
                    fig_sess.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_sess.update_traces(line_color='#1f77b4')  # 官方蓝色
                    st.plotly_chart(fig_sess, use_container_width=True)

            # 【图表 3：新建速率 Setup Rate】
            with col3:
                if 'Setup_Rate' in df.columns:
                    fig_setup = px.line(df, x='Timestamp', y='Setup_Rate', title="Setup Rate (cps)")
                    fig_setup.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
                    st.plotly_chart(fig_setup, use_container_width=True)

            # 第二行布局
            col4, col5, col6 = st.columns(3)

            # 【图表 4：CPU】
            with col4:
                if 'CPU_Usage' in df.columns:
                    fig_cpu = px.line(df, x='Timestamp', y='CPU_Usage', title="CPU Usage (%)")
                    fig_cpu.update_layout(yaxis_range=[0, 100], margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_cpu.update_traces(line_color='purple')
                    st.plotly_chart(fig_cpu, use_container_width=True)

            # 【图表 5：内存 Memory】
            with col5:
                if 'Memory_Usage' in df.columns:
                    fig_mem = px.line(df, x='Timestamp', y='Memory_Usage', title="Memory Usage (%)")
                    fig_mem.update_layout(yaxis_range=[0, 100], margin=dict(l=0, r=0, t=30, b=0), height=300)
                    fig_mem.update_traces(line_color='green')
                    st.plotly_chart(fig_mem, use_container_width=True)

            # 原始数据查看器 (可选)
            with st.expander("查看解析出的原始数据表"):
                st.dataframe(df)

        else:
            st.error("文件中没有找到匹配 `get sys perf status` 格式的数据，请检查文件内容。")


if __name__ == "__main__":
    main()