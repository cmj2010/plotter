import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from io import StringIO


# =========================================================
# 1. 核心数据引擎 (提取更多维度)
# =========================================================
class FortiGateParser:
    def __init__(self):
        self.records = []
        self.current_time = pd.Timestamp("2026-04-01 08:00:00")
        self.current_record = {}

        self.regex_time = re.compile(r"^System time:\s+(.+)")

        # 匹配: CPU30 states: 2% user 2% system 0% nice 96% idle 0% iowait 0% irq 0% softirq
        self.regex_cpu = re.compile(
            r"^CPU(\d*)\s+states:\s+(\d+)%\s+user\s+(\d+)%\s+system\s+(\d+)%\s+nice\s+(\d+)%\s+idle.*?(\d+)%\s+softirq"
        )
        self.regex_mem = re.compile(r"^Memory:.*?([\d\.]+)%\)")
        self.regex_bw = re.compile(r"^Average network usage:\s+(\d+)\s+/\s+(\d+)\s+kbps")
        self.regex_sess = re.compile(r"^Average sessions:\s+(\d+)\s+sessions")
        self.regex_setup = re.compile(r"^Average session setup rate:\s+(\d+)\s+sessions")

    def parse_file(self, file_content):
        lines = file_content.splitlines()
        for line in lines:
            line = line.strip()
            if not line: continue
            if self._parse_system_status(line): continue
            if self._parse_perf_status(line): continue

    def _parse_system_status(self, line):
        match_time = self.regex_time.search(line)
        if match_time:
            try:
                self.current_time = pd.to_datetime(match_time.group(1))
            except Exception:
                pass
            return True
        return False

    def _parse_perf_status(self, line):
        # 1. 动态解析所有 CPU 核心的各项指标
        match_cpu = self.regex_cpu.search(line)
        if match_cpu:
            cpu_id = match_cpu.group(1)  # "" 代表整体 CPU
            user = int(match_cpu.group(2))
            system = int(match_cpu.group(3))
            nice = int(match_cpu.group(4))
            idle = int(match_cpu.group(5))
            softirq = int(match_cpu.group(6))
            total = 100 - idle

            prefix = "CPU_Overall" if cpu_id == "" else f"CPU_{cpu_id}"

            if cpu_id == "":
                if self.current_record:
                    self.records.append(self.current_record)
                    self.current_time += pd.Timedelta(minutes=1)
                self.current_record = {'Timestamp': self.current_time}

            self.current_record[f'{prefix}_user'] = user
            self.current_record[f'{prefix}_system'] = system
            self.current_record[f'{prefix}_nice'] = nice
            self.current_record[f'{prefix}_softirq'] = softirq
            self.current_record[f'{prefix}_total'] = total
            return True

        match_mem = self.regex_mem.search(line)
        if match_mem:
            self.current_record['Memory_Usage'] = float(match_mem.group(1))
            return True

        match_bw = self.regex_bw.search(line)
        if match_bw:
            self.current_record['Bandwidth_Rx'] = int(match_bw.group(1))
            self.current_record['Bandwidth_Tx'] = int(match_bw.group(2))
            return True

        match_sess = self.regex_sess.search(line)
        if match_sess:
            self.current_record['Sessions'] = int(match_sess.group(1))
            return True

        match_setup = self.regex_setup.search(line)
        if match_setup:
            self.current_record['Setup_Rate'] = int(match_setup.group(1))
            return True

        return False

    def get_dataframe(self):
        if self.current_record and self.current_record not in self.records:
            self.records.append(self.current_record)
        return pd.DataFrame(self.records)


# =========================================================
# 2. 前端展示层 (Streamlit UI)
# =========================================================
def main():
    st.set_page_config(page_title="Fortigate 性能报告", layout="wide")
    st.title("📈 模块化日志分析引擎")

    uploaded_file = st.file_uploader("上传诊断日志", type=['txt', 'log'])

    if uploaded_file is not None:
        stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
        file_content = stringio.read()

        parser = FortiGateParser()
        parser.parse_file(file_content)
        df = parser.get_dataframe()

        if not df.empty:
            st.success(f"解析完成！共 {len(df)} 组数据。")

            # ---------------------------------------------------------
            # 视图 1：整体 CPU 状态
            # ---------------------------------------------------------
            st.markdown("---")
            st.subheader("🖥️ 全局 CPU 状态分布 (Overall CPU states)")

            fig_overall_cpu = go.Figure()
            metrics = ['total', 'user', 'system', 'nice', 'softirq']
            colors = {'total': 'black', 'user': 'blue', 'system': 'red', 'nice': 'green', 'softirq': 'purple'}

            for metric in metrics:
                col_name = f"CPU_Overall_{metric}"
                if col_name in df.columns:
                    fig_overall_cpu.add_trace(go.Scatter(
                        x=df['Timestamp'], y=df[col_name],
                        mode='lines', name=metric.capitalize(),
                        line=dict(color=colors.get(metric))
                    ))

            fig_overall_cpu.update_layout(yaxis_title="Usage (%)", yaxis_range=[0, 100], height=350,
                                          hovermode="x unified")
            st.plotly_chart(fig_overall_cpu, use_container_width=True)

            # ---------------------------------------------------------
            # 视图 2：子 CPU 分组图表 (按 15 个一组)
            # ---------------------------------------------------------
            st.markdown("---")
            st.subheader("🧬 核心 CPU 分组详情 (Per-Core grouped by 15)")

            cpu_cols = [col for col in df.columns if re.match(r"^CPU_\d+_total$", col)]
            cpu_ids = sorted([int(re.search(r"^CPU_(\d+)_total$", col).group(1)) for col in cpu_cols])

            if cpu_ids:
                chunk_size = 15
                for i in range(0, len(cpu_ids), chunk_size):
                    chunk_ids = cpu_ids[i:i + chunk_size]
                    group_title = f"CPU {chunk_ids[0]} - {chunk_ids[-1]}"

                    st.markdown(f"#### 组别: {group_title}")

                    col1, col2, col3 = st.columns(3)
                    col4, col5, _ = st.columns(3)
                    columns_layout = [col1, col2, col3, col4, col5]

                    for idx, metric in enumerate(metrics):
                        with columns_layout[idx]:
                            fig_group = go.Figure()
                            for cid in chunk_ids:
                                col_name = f"CPU_{cid}_{metric}"
                                if col_name in df.columns:
                                    fig_group.add_trace(go.Scatter(
                                        x=df['Timestamp'], y=df[col_name],
                                        mode='lines', name=f"CPU {cid}", line=dict(width=1)
                                    ))

                            fig_group.update_layout(
                                title=f"{group_title} ({metric.capitalize()})",
                                yaxis_range=[0, 100],
                                margin=dict(l=0, r=0, t=30, b=0),
                                height=250,
                                hovermode="x unified"
                            )
                            st.plotly_chart(fig_group, use_container_width=True)

                    st.write("")

            # ---------------------------------------------------------
            # 视图 3：其他全局指标 (带宽、会话、新建速率、内存)
            # ---------------------------------------------------------
            st.markdown("---")
            st.subheader("🌐 其他关键指标")

            # 采用 2x2 网格布局
            col_o1, col_o2 = st.columns(2)
            col_o3, col_o4 = st.columns(2)

            with col_o1:
                if 'Bandwidth_Rx' in df.columns:
                    fig_bw = go.Figure()
                    fig_bw.add_trace(
                        go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Rx'], mode='lines', name='Rx (kbps)'))
                    fig_bw.add_trace(
                        go.Scatter(x=df['Timestamp'], y=df['Bandwidth_Tx'], mode='lines', name='Tx (kbps)'))
                    fig_bw.update_layout(title="Bandwidth", height=250, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_bw, use_container_width=True)

            with col_o2:
                if 'Sessions' in df.columns:
                    fig_sess = px.line(df, x='Timestamp', y='Sessions', title="Sessions")
                    fig_sess.update_layout(height=250, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_sess, use_container_width=True)

            with col_o3:
                # [新增] 恢复 Setup Rate 图表展示
                if 'Setup_Rate' in df.columns:
                    fig_setup = px.line(df, x='Timestamp', y='Setup_Rate', title="Session Setup Rate (cps)")
                    fig_setup.update_traces(line_color='orange')  # 给它一个专属的橙色
                    fig_setup.update_layout(height=250, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_setup, use_container_width=True)

            with col_o4:
                if 'Memory_Usage' in df.columns:
                    fig_mem = px.line(df, x='Timestamp', y='Memory_Usage', title="Memory Usage (%)")
                    fig_mem.update_layout(yaxis_range=[0, 100], height=250, margin=dict(l=0, r=0, t=30, b=0))
                    fig_mem.update_traces(line_color='green')
                    st.plotly_chart(fig_mem, use_container_width=True)

            # 原始数据查看
            with st.expander("查看详细宽表数据"):
                st.dataframe(df)


if __name__ == "__main__":
    main()