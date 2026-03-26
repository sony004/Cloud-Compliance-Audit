# Alibaba Cloud Automated Compliance Audit (Powered by Prowler)

本项目基于 Prowler 的 Alibaba Cloud 检测能力，提供一个可独立运行的合规检测工作流，并新增了 **NIST SP 800-53 Rev.5 控制项映射**能力。

当前定位：
- 检测层：复用 Prowler checks 执行云配置与安全检测
- 合规层：输出 CIS 等基线报告
- 控制层：将检测结果映射为 NIST 800-53 控制项证据（不做评分）

## Project Structure

- `src/aliyun_project/cli.py`: 主 CLI（`scan` / `summary` / `nist-map`）
- `src/aliyun_project/sync_rules.py`: 从 Prowler 同步 checks/compliance 规则
- `src/aliyun_project/nist_mapping.py`: NIST 控制项映射与聚合逻辑
- `rules/compliance/alibabacloud/*.json`: 本地合规基线规则
- `rules/checks/*.json`: 本地检查项集合
- `rules/mappings/nist_800_53_rev5_alibabacloud.json`: NIST 映射规则库
- `run_scan_docker.ps1`: Docker 方式扫描
- `run_scan.ps1`: Poetry 本地环境扫描
- `run_sync.ps1`: 同步本地规则
- `output/`: 扫描与报告输出目录

## 1) Prepare Credentials

首次运行前准备 `.env`：

```powershell
Copy-Item .env.example .env
```

填写以下内容：

```env
ALIBABA_CLOUD_ACCESS_KEY_ID=<your_access_key_id>
ALIBABA_CLOUD_ACCESS_KEY_SECRET=<your_access_key_secret>
# Optional (STS)
# ALIBABA_CLOUD_SECURITY_TOKEN=<your_security_token>
```

## 2) Run Scan

### Option A: Docker (Recommended for quick start)

```powershell
.\run_scan_docker.ps1
```

`run_scan_docker.ps1` now performs two steps by default:
- Run Prowler scan
- Run `nist-map` automatically and write mapped reports to `output/nist/`

常用参数：

```powershell
# 指定区域
.\run_scan_docker.ps1 -Region cn-beijing,cn-shanghai

# 指定合规基线
.\run_scan_docker.ps1 -Compliance cis_2.0_alibabacloud

# 使用本地 checks 文件
.\run_scan_docker.ps1 -UseLocalChecks

# 忽略 Prowler finding 退出码 3
.\run_scan_docker.ps1 -IgnoreExitCode3

# 指定镜像
.\run_scan_docker.ps1 -Image toniblyx/prowler:stable

# 仅扫描，跳过 NIST 映射
.\run_scan_docker.ps1 -SkipNistMap
```

### Option B: Poetry Local Environment

```powershell
py -m poetry install
.\run_scan.ps1
```

## 3) Summarize Compliance Report

```powershell
aliyun-audit summary
```

指定文件：

```powershell
aliyun-audit summary --file output/compliance/<your_file>.csv --top 10
```

## 4) Map Findings to NIST SP 800-53 (Rev.5)

新增命令：`nist-map`

如果你使用 `.\run_scan_docker.ps1`，该命令会在扫描后自动执行；本节命令适用于手动单独执行映射。

功能：
- 读取扫描 CSV（优先最新 `output/prowler-output-*.csv`）
- 按 `CHECK_ID/CHECKID` 匹配映射规则
- 生成控制项视角报告（摘要 + 明细 + JSON）

直接运行：

```powershell
aliyun-audit nist-map
```

指定输入文件：

```powershell
aliyun-audit nist-map --file output/prowler-output-<account>-<time>.csv
```

指定映射规则文件和输出目录：

```powershell
aliyun-audit nist-map `
  --mapping-file rules/mappings/nist_800_53_rev5_alibabacloud.json `
  --report-dir output/nist
```

输出文件：
- `output/nist/*_nist80053_control_summary.csv`
- `output/nist/*_nist80053_control_details.csv`
- `output/nist/*_nist80053_control_summary.json`

说明：
- 当前仅实现控制项映射与证据聚合，不包含风险评分模型
- 映射规则可在 `rules/mappings/nist_800_53_rev5_alibabacloud.json` 持续扩展

## 5) Sync Local Rules from Prowler

```powershell
.\run_sync.ps1
```

指定本地 Prowler 源码目录：

```powershell
.\run_sync.ps1 -SourceRoot "E:\path\to\prowler"
```

同步后将更新：
- `rules/compliance/alibabacloud/*.json`
- `rules/checks/alibabacloud_all_checks.json`
- `rules/checks/cis_2.0_alibabacloud_checks.json`

## 6) Typical Output Files

- `output/prowler-output-<account>-<time>.csv`
- `output/prowler-output-<account>-<time>.html`
- `output/prowler-output-<account>-<time>.ocsf.json`
- `output/compliance/*_cis_2.0_alibabacloud.csv`
- `output/nist/*_nist80053_control_summary.csv`
- `output/nist/*_nist80053_control_details.csv`

## Notes

- 若 `scan` 报缺少凭据，请先检查 `.env` 是否存在且变量名正确
- 若使用 Poetry，请确认 `py -m poetry` 可用
- 若使用 Docker，请确认 `docker version` 正常
