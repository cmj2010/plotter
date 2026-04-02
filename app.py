import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
import collections
from io import StringIO


# =========================================================
# 1. 核心数据引擎 (模块化解析器)
# =========================================================
class FortiGateParser:
    def __init__(self):
        self.records = []
        self.current_time = pd.Timestamp("2026-04-01 08:00:00")
        self.current_record = {}
        self.temp_exec_date = None
        self.current_ips_pid = None  # [新增] 用于追踪当前的 IPS PID 状态

        # --- 模块 A: 时间触发器正则 ---
        self.regex_sys_time = re.compile(r"^System time:\s+(.+)")
        self.regex_fnsysctl_date = re.compile(
            r"^([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+[A-Z]+\s+(\d{4})")
        self.regex_exec_date = re.compile(r"^current date is:\s+(\d{4}-\d{2}-\d{2})")
        self.regex_exec_time = re.compile(r"^current time is:\s+(\d{2}:\d{2}:\d{2})")

        # --- 模块 B: CPU 及常规性能正则 ---
        self.regex_cpu = re.compile(
            r"^CPU(\d*)\s+states:\s+(\d+)%\s+user\s+(\d+)%\s+system\s+(\d+)%\s+nice\s+(\d+)%\s+idle.*?(\d+)%\s+softirq")
        self.regex_mem = re.compile(r"^Memory:.*?([\d\.]+)%\)")
        self.regex_bw = re.compile(r"^Average network usage:\s+(\d+)\s+/\s+(\d+)\s+kbps")
        self.regex_sess = re.compile(r"^Average sessions:\s+(\d+)\s+sessions")
        self.regex_setup = re.compile(r"^Average session setup rate:\s+(\d+)\s+sessions")

        # --- 模块 C: 硬件内存 (Hardware Sysinfo Memory) 正则 ---
        self.regex_hw_mem_trigger = re.compile(r"^MemTotal:\s+(\d+)\s+kB")
        self.regex_hw_mem_metrics = re.compile(
            r"^(Cached|AnonPages|Shmem|Buffers|MemFree|MemAvailable|Slab|SReclaimable|SUnreclaim|Active|Inactive|Active\(anon\)|Inactive\(anon\)|Active\(file\)|Inactive\(file\)):\s+(\d+)\s+kB"
        )

        # --- 模块 D: 进程内存 (Top Mem) 正则 ---
        self.regex_topmem_cmd = re.compile(r"diag sys top-mem")
        self.regex_topmem_line = re.compile(r"^([\w\.\-]+)\s+\((\d+)\):\s+(\d+)kB")

        # --- 模块 E: IPS Session Status 正则 [新增] ---
        # 基于用户提供的 XML Parser 定制
        self.regex_ips_cmd = re.compile(r"diagnose ips session status")
        self.regex_ips_pid = re.compile(r"^PID:\s+(\d+)")
        self.regex_ips_mem = re.compile(r"^memory (capacity|used)\s+(\d+)[A-Za-z]?")
        self.regex_ips_pps = re.compile(r"^recent pps\\bps\s+(\d+)\\")
        self.regex_ips_inuse = re.compile(r"^(TCP|UDP|ICMP|IP):\s*in-use\\active\\total\s+(\d+)\\")
        self.regex_ips_reass = re.compile(r"^(TCP) reassemble:\s+(\d+)")

    def parse_file(self, file_content):
        lines = file_content.splitlines()
        for line in lines:
            line = line.strip()
            if not line: continue

            # --- 路由逻辑 ---
            if self._parse_time_triggers(line): continue
            if self._parse_perf_status(line): continue
            if self._parse_hw_sysinfo_memory(line): continue
            if self._parse_topmem(line): continue
            if self._parse_ips_session(line): continue  # 挂载 IPS 解析模块

    def _parse_time_triggers(self, line):
        match_sys = self.regex_sys_time.search(line)
        if match_sys:
            try:
                self.current_time = pd.to_datetime(match_sys.group(1))
            except Exception:
                pass
            return True

        match_fn = self.regex_fnsysctl_date.search(line)
        if match_fn:
            safe_time_str = f"{match_fn.group(1)} {match_fn.group(2)}"
            try:
                self.current_time = pd.to_datetime(safe_time_str)
            except Exception:
                pass
            return True

        match_exec_d = self.regex_exec_date.search(line)
        if match_exec_d:
            self.temp_exec_date = match_exec_d.group(1)
            return True

        match_exec_t = self.regex_exec_time.search(line)
        if match_exec_t:
            if self.temp_exec_date:
                combined_time_str = f"{self.temp_exec_date} {match_exec_t.group(1)}"
                try:
                    self.current_time = pd.to_datetime(combined_time_str)
                    self.temp_exec_date = None
                except Exception:
                    pass
            return True

        return False

    def _parse_perf_status(self, line):
        match_cpu = self.regex_cpu.search(line)
        if match_cpu:
            cpu_id = match_cpu.group(1)
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

    def _parse_hw_sysinfo_memory(self, line):
        match_trigger = self.regex_hw_mem_trigger.search(line)
        if match_trigger:
            if 'HW_Mem_Total' in self.current_record:
                if self.current_record not in self.records:
                    self.records.append(self.current_record)
                self.current_time += pd.Timedelta(minutes=1)
                self.current_record = {'Timestamp': self.current_time}

            self.current_record['HW_Mem_Total'] = int(match_trigger.group(1))
            return True

        match_metrics = self.regex_hw_mem_metrics.search(line)
        if match_metrics:
            key = match_metrics.group(1)
            safe_key = key.replace('(', '_').replace(')', '')
            value = int(match_metrics.group(2))
            self.current_record[f'HW_Mem_{safe_key}'] = value
            return True

        return False

    def _parse_topmem(self, line):
        match_cmd = self.regex_topmem_cmd.search(line)
        if match_cmd:
            if any(k.startswith('TopMem_') for k in self.current_record.keys()):
                if self.current_record not in self.records:
                    self.records.append(self.current_record)
                self.current_time += pd.Timedelta(minutes=1)
                self.current_record = {'Timestamp': self.current_time}
            return True

        match_line = self.regex_topmem_line.search(line)
        if match_line:
            proc_name = match_line.group(1)
            pid = match_line.group(2)
            mem_kb = int(match_line.group(3))
            col_name = f"TopMem_{proc_name} ({pid})"
            self.current_record[col_name] = mem_kb
            return True

        return False

    def _parse_ips_session(self, line):
        """ 新增模块：处理 IPS Session Status 输出 """
        # 1. 识别命令触发，推移时间
        match_cmd = self.regex_ips_cmd.search(line)
        if match_cmd:
            # 检查当前是否已经记录过 IPS，如果是，推移时间
            if any(k.startswith('IPS_') for k in self.current_record.keys()):
                if self.current_record not in self.records:
                    self.records.append(self.current_record)
                self.current_time += pd.Timedelta(minutes=1)
                self.current_record = {'Timestamp': self.current_time}
            self.current_ips_pid = None  # 新循环，重置 PID
            return True

        # 2. 识别 PID 块的开始
        match_pid = self.regex_ips_pid.search(line)
        if match_pid:
            self.current_ips_pid = match_pid.group(1)
            return True

        # 3. 只有在获取到 PID 的前提下，才开始抓取各维度的指标
        if self.current_ips_pid:
            match_mem = self.regex_ips_mem.search(line)
            if match_mem:
                self.current_record[f'IPS_{self.current_ips_pid}_Mem_{match_mem.group(1)}'] = int(match_mem.group(2))
                return True

            match_pps = self.regex_ips_pps.search(line)
            if match_pps:
                self.current_record[f'IPS_{self.current_ips_pid}_pps'] = int(match_pps.group(1))
                return True

            match_inuse = self.regex_ips_inuse.search(line)
            if match_inuse:
                self.current_record[f'IPS_{self.current_ips_pid}_{match_inuse.group(1)}_inuse'] = int(
                    match_inuse.group(2))
                return True

            match_reass = self.regex_ips_reass.search(line)
            if match_reass:
                self.current_record[f'IPS_{self.current_ips_pid}_{match_reass.group(1)}_reassemble'] = int(
                    match_reass.group(2))
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
            start_time = df['Timestamp'].iloc[0].strftime('%Y-%m-%d %H:%M:%S')
            end_time = df['Timestamp'].iloc[-1].strftime('%Y-%m-%d %H:%M:%S')
            st.success(f"解析完成！共 {len(df)} 组数据记录。数据时间范围：**{start_time}** 至 **{end_time}**")

            # --- 视图 1：整体 CPU 状态 ---
            st.markdown("---")
            st.subheader("🖥️ 全局 CPU 状态分布 (Overall CPU states)")
            fig_overall_cpu = go.Figure()
            metrics = ['total', 'user', 'system', 'nice', 'softirq']
            colors = {'total': 'black', 'user': 'blue', 'system': 'red', 'nice': 'green', 'softirq': 'purple'}
            for metric in metrics:
                col_name = f"CPU_Overall_{metric}"
                if col_name in df.columns:
                    fig_overall_cpu.add_trace(
                        go.Scatter(x=df['Timestamp'], y=df[col_name], mode='lines', name=metric.capitalize(),
                                   line=dict(color=colors.get(metric))))
            fig_overall_cpu.update_layout(yaxis_title="Usage (%)", yaxis_range=[0, 100], height=350,
                                          hovermode="x unified")
            st.plotly_chart(fig_overall_cpu, use_container_width=True)

            # --- 视图 2：子 CPU 分组图表 ---
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
                                    fig_group.add_trace(
                                        go.Scatter(x=df['Timestamp'], y=df[col_name], mode='lines', name=f"CPU {cid}",
                                                   line=dict(width=1)))
                            fig_group.update_layout(title=f"{group_title} ({metric.capitalize()})",
                                                    yaxis_range=[0, 100], margin=dict(l=0, r=0, t=30, b=0), height=250,
                                                    hovermode="x unified")
                            st.plotly_chart(fig_group, use_container_width=True)
                    st.write("")

            # --- 视图 3：其他全局指标 ---
            st.markdown("---")
            st.subheader("🌐 其他关键指标")
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
                if 'Setup_Rate' in df.columns:
                    fig_setup = px.line(df, x='Timestamp', y='Setup_Rate', title="Session Setup Rate (cps)")
                    fig_setup.update_traces(line_color='orange')
                    fig_setup.update_layout(height=250, margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_setup, use_container_width=True)
            with col_o4:
                if 'Memory_Usage' in df.columns:
                    fig_mem = px.line(df, x='Timestamp', y='Memory_Usage', title="Memory Usage (%)")
                    fig_mem.update_layout(yaxis_range=[0, 100], height=250, margin=dict(l=0, r=0, t=30, b=0))
                    fig_mem.update_traces(line_color='green')
                    st.plotly_chart(fig_mem, use_container_width=True)

            # --- 视图 4：底层硬件内存详情 ---
            st.markdown("---")
            st.subheader("🗄️ 底层硬件内存详情 (Hardware Memory Details)")
            col_hw1, col_hw2 = st.columns(2)
            col_hw3, col_hw4 = st.columns(2)
            with col_hw1:
                target_mem_cols = ['HW_Mem_Cached', 'HW_Mem_AnonPages', 'HW_Mem_Shmem', 'HW_Mem_Buffers']
                if any(col in df.columns for col in target_mem_cols):
                    fig_hw_mem = go.Figure()
                    for col in target_mem_cols:
                        if col in df.columns:
                            fig_hw_mem.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[col], mode='lines', name=col.replace('HW_Mem_', '')))
                    fig_hw_mem.update_layout(title="Used memory (kB)", height=350, hovermode="x unified",
                                             margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_hw_mem, use_container_width=True)
            with col_hw2:
                target_ratio_cols = ['HW_Mem_Total', 'HW_Mem_MemFree', 'HW_Mem_MemAvailable']
                if any(col in df.columns for col in target_ratio_cols):
                    fig_hw_ratio = go.Figure()
                    for col in target_ratio_cols:
                        if col in df.columns:
                            display_name = col.replace('HW_Mem_', '')
                            if display_name == 'Total': display_name = 'MemTotal'
                            fig_hw_ratio.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[col], mode='lines', name=display_name))
                    fig_hw_ratio.update_layout(title="Memory ratio (kB)", height=350, hovermode="x unified",
                                               margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_hw_ratio, use_container_width=True)
            with col_hw3:
                target_slab_cols = ['HW_Mem_Slab', 'HW_Mem_SReclaimable', 'HW_Mem_SUnreclaim']
                if any(col in df.columns for col in target_slab_cols):
                    fig_hw_slab = go.Figure()
                    for col in target_slab_cols:
                        if col in df.columns:
                            fig_hw_slab.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[col], mode='lines', name=col.replace('HW_Mem_', '')))
                    fig_hw_slab.update_layout(title="Slab (kB)", height=350, hovermode="x unified",
                                              margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_hw_slab, use_container_width=True)
            with col_hw4:
                target_cache_cols = [
                    'HW_Mem_Active', 'HW_Mem_Inactive',
                    'HW_Mem_Active_anon', 'HW_Mem_Inactive_anon',
                    'HW_Mem_Active_file', 'HW_Mem_Inactive_file'
                ]
                if any(col in df.columns for col in target_cache_cols):
                    fig_hw_cache = go.Figure()
                    for col in target_cache_cols:
                        if col in df.columns:
                            display_name = col.replace('HW_Mem_', '').replace('_anon', '(anon)').replace('_file',
                                                                                                         '(file)')
                            fig_hw_cache.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[col], mode='lines', name=display_name))
                    fig_hw_cache.update_layout(title="Cache memory (kB)", height=350, hovermode="x unified",
                                               margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_hw_cache, use_container_width=True)

            # --- 视图 5：进程级内存消耗排行 ---
            topmem_cols = [col for col in df.columns if col.startswith('TopMem_')]
            if topmem_cols:
                st.markdown("---")
                st.subheader("📊 子进程内存消耗排行 (Top 10 Processes)")

                process_groups = collections.defaultdict(list)
                for col in topmem_cols:
                    match = re.search(r"^TopMem_(.*?)\s+\(\d+\)$", col)
                    if match:
                        proc_name = match.group(1)
                        process_groups[proc_name].append(col)
                    else:
                        process_groups[col].append(col)

                group_max_mem = {}
                for proc_name, cols in process_groups.items():
                    group_max_mem[proc_name] = df[cols].max().sum()

                top_10_procs = sorted(group_max_mem.keys(), key=lambda k: group_max_mem[k], reverse=True)[:10]

                col_t1, col_t2 = st.columns(2)
                cols_layout_top = [col_t1, col_t2]

                for idx, proc_name in enumerate(top_10_procs):
                    proc_cols = process_groups[proc_name]
                    with cols_layout_top[idx % 2]:
                        fig_topmem = go.Figure()
                        for col in proc_cols:
                            pid_match = re.search(r"\((\d+)\)", col)
                            pid_str = f"PID: {pid_match.group(1)}" if pid_match else col
                            fig_topmem.add_trace(go.Scatter(x=df['Timestamp'], y=df[col], mode='lines', name=pid_str))

                        fig_topmem.update_layout(title=f"Process: {proc_name}", yaxis_title="Memory (kB)", height=350,
                                                 hovermode="x unified", margin=dict(l=0, r=0, t=30, b=0))
                        st.plotly_chart(fig_topmem, use_container_width=True)

            # ---------------------------------------------------------
            # [新增] 视图 6：IPS Session Status (引擎会话状态)
            # ---------------------------------------------------------
            ips_cols = [col for col in df.columns if col.startswith('IPS_')]
            if ips_cols:
                st.markdown("---")
                st.subheader("🛡️ IPS 引擎状态 (IPS Session Status)")
                st.markdown("根据指定的 `diag ips session status` 解析规则，提取各实例 (PID) 的核心运转性能数据。")

                # 提取所有存在的 IPS PID
                ips_pids = set()
                for col in ips_cols:
                    match = re.search(r"^IPS_(\d+)_", col)
                    if match:
                        ips_pids.add(match.group(1))
                ips_pids = sorted(list(ips_pids))

                col_ips1, col_ips2 = st.columns(2)
                col_ips3, col_ips4 = st.columns(2)

                # [表 1: IPS Memory]
                with col_ips1:
                    fig_ips_mem = go.Figure()
                    for pid in ips_pids:
                        used_col = f"IPS_{pid}_Mem_used"
                        if used_col in df.columns:
                            fig_ips_mem.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[used_col], mode='lines', name=f"PID {pid}"))
                    fig_ips_mem.update_layout(title="IPS Memory Used (MB)", height=350, hovermode="x unified",
                                              margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_ips_mem, use_container_width=True)

                # [表 2: IPS pps]
                with col_ips2:
                    fig_ips_pps = go.Figure()
                    for pid in ips_pids:
                        pps_col = f"IPS_{pid}_pps"
                        if pps_col in df.columns:
                            fig_ips_pps.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[pps_col], mode='lines', name=f"PID {pid}"))
                    fig_ips_pps.update_layout(title="IPS PPS (packets/sec)", height=350, hovermode="x unified",
                                              margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_ips_pps, use_container_width=True)

                # [表 3: IPS in-use]
                with col_ips3:
                    fig_ips_inuse = go.Figure()
                    for pid in ips_pids:
                        tcp_col = f"IPS_{pid}_TCP_inuse"
                        udp_col = f"IPS_{pid}_UDP_inuse"
                        if tcp_col in df.columns:
                            fig_ips_inuse.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[tcp_col], mode='lines', name=f"PID {pid} TCP"))
                        if udp_col in df.columns:
                            # UDP 线型设为虚线(dash)，方便与同图的 TCP 进行区分
                            fig_ips_inuse.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[udp_col], mode='lines', line=dict(dash='dot'),
                                           name=f"PID {pid} UDP"))
                    fig_ips_inuse.update_layout(title="IPS Sessions In-Use", yaxis_title="sessions", height=350,
                                                hovermode="x unified", margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_ips_inuse, use_container_width=True)

                # [表 4: IPS TCP reassemble]
                with col_ips4:
                    fig_ips_reass = go.Figure()
                    for pid in ips_pids:
                        reass_col = f"IPS_{pid}_TCP_reassemble"
                        if reass_col in df.columns:
                            fig_ips_reass.add_trace(
                                go.Scatter(x=df['Timestamp'], y=df[reass_col], mode='lines', name=f"PID {pid}"))
                    fig_ips_reass.update_layout(title="IPS TCP Reassemble (pps)", height=350, hovermode="x unified",
                                                margin=dict(l=0, r=0, t=30, b=0))
                    st.plotly_chart(fig_ips_reass, use_container_width=True)

            # 原始数据查看
            with st.expander("查看详细宽表数据"):
                st.dataframe(df)


if __name__ == "__main__":
    main()