# 📈 FortiGate 日志分析引擎使用说明书

## 1. 工具简介

**FortiGate 日志分析引擎** 是一个基于 Python 和 Streamlit 构建的轻量级、交互式数据可视化工具。它专门用于解析 FortiGate 防火墙的底层诊断日志，提取时间戳及各项性能指标，并自动生成动态的可视化图表。

本工具能够帮助网络工程师和运维人员直观地观察系统资源（如 CPU、内存、进程、IPS 引擎等）的长期增长趋势，快速定位内存泄漏、CPU 异常飙升或会话拥堵等潜在问题。

---

## 2. 数据收集指南

本工具依赖于特定 FortiOS CLI 命令的输出数据。为了生成具有时间序列的图表，**你需要在一段时间内（如数小时或数天）定期、循环地在 FortiGate 上执行以下命令，并将所有的输出结果保存为单个文本文件（`.txt` 或 `.log`）。**

你可以使用终端工具（如 SecureCRT 的自动脚本、TeraTerm 宏 或 Python `netmiko` 脚本）来定期记录以下命令的输出：

```text
fnsysctl date
get system status
get sys performance status
diag hardware sysinfo memory
diag sys top-mem 50
diag ips session status
diag test application ipsmonitor 24
```
> **💡 核心提示：** > * `fnsysctl date` 或 `get system status` 中的时间信息极其重要，分析引擎依赖它们来锚定后续数据的时间戳。
> * 建议的数据收集间隔为 **1 分钟** 或 **5 分钟** 采集一轮。