# Alibaba Cloud 合规审计与 NIST 800-53 映射项目

本项目基于 **Prowler** 对 Alibaba Cloud 进行自动化安全检查，并扩展了以下能力：

- 扫描结果映射到 **NIST SP 800-53 Rev.5** 控制项
- 生成控制项级汇总、明细、HTML、OSCAL 报告
- 生成证据索引与证据哈希链清单
- 连续合规快照、差异分析与趋势图
- 证据完整性校验与篡改实验（FAIL -> PASS，自动回滚）

## 1. 项目结构

- `src/aliyun_project/cli.py`：主 CLI 入口（`scan` / `summary` / `nist-map` / `verify-evidence` / `tamper-evidence`）
- `src/aliyun_project/nist_mapping.py`：检查项到 NIST 控制项映射与报告生成
- `src/aliyun_project/continuous_compliance.py`：连续合规快照、差异、趋势图生成
- `src/aliyun_project/verify_evidence_chain.py`：证据哈希链校验
- `src/aliyun_project/evidence_tamper_experiment.py`：篡改实验与自动回滚
- `src/aliyun_project/sync_rules.py`：从 Prowler 同步 checks/compliance 规则
- `rules/mappings/nist_800_53_rev5_alibabacloud.json`：NIST 映射规则
- `run_scan_docker.ps1`：Docker 一键扫描 + 自动 NIST 映射
- `run_scan.ps1`：Poetry 本地扫描脚本
- `run_sync.ps1`：规则同步脚本
- `Dockerfile.prowler-patched`：项目定制镜像（含补丁与绘图依赖）

## 2. 环境要求

- Windows + PowerShell
- Docker（推荐）
- 或 Python 3.10 ~ 3.12 + Poetry

## 3. 凭据配置

首次运行前创建 `.env`：

```powershell
Copy-Item .env.example .env
```

填写以下变量：

```env
ALIBABA_CLOUD_ACCESS_KEY_ID=<your_access_key_id>
ALIBABA_CLOUD_ACCESS_KEY_SECRET=<your_access_key_secret>
# 可选（STS）
# ALIBABA_CLOUD_SECURITY_TOKEN=<your_security_token>
```

## 4. 快速开始（Docker，推荐）

```powershell
.\run_scan_docker.ps1
```

默认流程：

1. 使用 `aliyun-prowler-patched:latest` 镜像（不存在时自动构建）
2. 执行 Prowler 扫描
3. 自动执行 `nist-map`
4. 更新连续合规输出（快照、差异、趋势图）

常用参数：

```powershell
# 指定区域
.\run_scan_docker.ps1 -Region cn-beijing,cn-shanghai

# 指定 compliance
.\run_scan_docker.ps1 -Compliance cis_2.0_alibabacloud

# 使用本地 checks 列表
.\run_scan_docker.ps1 -UseLocalChecks

# 忽略 Prowler 发现项返回码 3
.\run_scan_docker.ps1 -IgnoreExitCode3

# 强制重建镜像
.\run_scan_docker.ps1 -BuildImage

# 仅扫描，不做 NIST 映射
.\run_scan_docker.ps1 -SkipNistMap

# 仅映射指定实例相关记录
.\run_scan_docker.ps1 -TargetInstanceId i-xxxxxx

# 使用自定义镜像
.\run_scan_docker.ps1 -Image toniblyx/prowler:stable
```

## 5. 本地运行（Poetry）

```powershell
py -m poetry install
.\run_scan.ps1
```

## 6. CLI 用法

### 6.1 扫描

```powershell
poetry run aliyun-audit scan --region cn-beijing --compliance cis_2.0_alibabacloud
```

### 6.2 汇总

```powershell
poetry run aliyun-audit summary
poetry run aliyun-audit summary --file output/compliance/<file>.csv --top 10
```

### 6.3 NIST 映射

```powershell
poetry run aliyun-audit nist-map
```

指定输入与输出目录：

```powershell
poetry run aliyun-audit nist-map `
  --file output/prowler-output-<account>-<time>.csv `
  --mapping-file rules/mappings/nist_800_53_rev5_alibabacloud.json `
  --report-dir output/nist `
  --continuous-dir output/continuous
```

跳过连续合规：

```powershell
poetry run aliyun-audit nist-map --skip-continuous
```

### 6.4 证据链校验

```powershell
poetry run aliyun-audit verify-evidence
poetry run aliyun-audit verify-evidence --file output/nist/<manifest>.json
```

### 6.5 篡改实验

```powershell
poetry run aliyun-audit tamper-evidence
poetry run aliyun-audit tamper-evidence --file output/nist/<manifest>.json
```

## 7. 主要输出说明

### 7.1 原始扫描输出（`output/`）

- `prowler-output-<account>-<time>.csv`
- `prowler-output-<account>-<time>.html`
- `prowler-output-<account>-<time>.ocsf.json`

### 7.2 NIST 映射输出（`output/nist/`）

- `*_nist80053_control_summary.csv`
- `*_nist80053_control_details.csv`
- `*_nist80053_control_report.html`
- `*_nist80053_control_summary.json`
- `*_nist80053_assessment-results.oscal.json`
- `*_nist80053_evidence_manifest.json`
- `*_nist80053_control_evidence_index.csv`

### 7.3 连续合规输出（`output/continuous/`）

- `snapshots/*_control_snapshot.json`
- `*_control_diff.csv`
- `*_control_diff.json`
- `control_trend.csv`
- `control_trend_trajectory.png`（有 `pandas/matplotlib` 时）
- `control_trend_trajectory.svg`（依赖缺失时自动回退）

## 8. 规则同步

```powershell
.\run_sync.ps1
```

指定 Prowler 源目录：

```powershell
.\run_sync.ps1 -SourceRoot "E:\path\to\prowler"
```

同步结果：

- `rules/compliance/alibabacloud/*.json`
- `rules/checks/alibabacloud_all_checks.json`
- `rules/checks/cis_2.0_alibabacloud_checks.json`

## 9. 常见问题

### 9.1 扫描后没有生成趋势图 PNG

通常是运行环境缺少 `pandas/matplotlib`。项目会自动回退生成：

- `output/continuous/control_trend_trajectory.svg`

### 9.2 Docker 构建失败

请检查：

- Docker Desktop 是否启动
- 网络是否可拉取基础镜像
- `.env` 凭据是否存在且有效

### 9.3 `verify-evidence` 返回非 0

表示证据 payload 或哈希链不一致。请结合最新 manifest 与 tamper 报告定位问题。
