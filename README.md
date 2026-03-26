# 阿里云安全审计项目（独立版）

这是一个可独立运行的阿里云审计项目，基于 Prowler。
你可以直接在本仓库中完成扫描、规则管理与报告导出，不依赖外层目录。

## 这个项目现在能做什么

1. 按合规基线执行阿里云扫描（默认 `cis_2.0_alibabacloud`）。
2. 使用本地可编辑检查清单执行扫描（`rules/checks/*.json`）。
3. 导出扫描结果到本地 `output/`（CSV、HTML、JSON-OCSF）。
4. 维护本地规则文件（`rules/compliance/alibabacloud/*.json` 与 `rules/checks/*.json`）。
5. 通过脚本快速发起扫描（推荐 Docker 方式，避免本机 Python 依赖问题）。

## 目录说明

- 合规规则：`rules/compliance/alibabacloud/*.json`
- 检查清单：`rules/checks/alibabacloud_all_checks.json`
- CIS 检查清单：`rules/checks/cis_2.0_alibabacloud_checks.json`
- 扫描输出：`output/`
- Docker 扫描脚本：`run_scan_docker.ps1`
- Poetry 扫描脚本：`run_scan.ps1`
- 规则同步脚本：`run_sync.ps1`

## 快速开始（推荐：Docker）

### 1) 准备凭证

在项目根目录执行：

```powershell
Copy-Item .env.example .env
```

编辑 `.env`，填入：

```env
ALIBABA_CLOUD_ACCESS_KEY_ID=你的AccessKeyId
ALIBABA_CLOUD_ACCESS_KEY_SECRET=你的AccessKeySecret
# 若使用 STS 临时凭证，取消注释并填写：
# ALIBABA_CLOUD_SECURITY_TOKEN=你的SecurityToken
```

### 2) 执行默认 CIS 扫描

```powershell
.\run_scan_docker.ps1
```

### 3) 查看结果

结果会写到本地 `output/`，常见文件：

- `output/prowler-output-<account>-<time>.csv`
- `output/prowler-output-<account>-<time>.html`
- `output/prowler-output-<account>-<time>.ocsf.json`
- `output/compliance/*_cis_2.0_alibabacloud.csv`

## 常用操作（Docker）

### 指定区域

```powershell
.\run_scan_docker.ps1 -Region cn-beijing,cn-shanghai
```

### 指定合规基线

```powershell
.\run_scan_docker.ps1 -Compliance cis_2.0_alibabacloud
```

### 使用本地 checks 文件扫描

```powershell
.\run_scan_docker.ps1 -UseLocalChecks
```

### 忽略退出码 3（有失败项但流程不中断）

```powershell
.\run_scan_docker.ps1 -IgnoreExitCode3
```

### 指定镜像

```powershell
.\run_scan_docker.ps1 -Image toniblyx/prowler:stable
```

## Poetry 方式（可选）

如果你希望在本机 Python 环境运行，可用：

```powershell
py -m poetry install
.\run_scan.ps1
```

说明：Windows 下可能因依赖路径过长导致安装失败，因此优先建议 Docker 方式。

## 规则维护与同步

项目内规则可直接编辑：

- `rules/checks/alibabacloud_all_checks.json`
- `rules/checks/cis_2.0_alibabacloud_checks.json`
- `rules/compliance/alibabacloud/*.json`

同步规则（Poetry）：

```powershell
.\run_sync.ps1
```

可选：从本地 Prowler 源码目录同步：

```powershell
.\run_sync.ps1 -SourceRoot "E:\path\to\prowler"
```

## 输出解读建议

1. 优先处理 `Critical` 和 `High`。
2. 再按服务维度集中处理（例如 ActionTrail、SLS、Security Center）。
3. 以 `output/compliance/*_cis_2.0_alibabacloud.csv` 作为整改跟踪主表。

## 注意事项

1. `.env` 仅用于本地，不应提交到仓库。
2. 建议使用 RAM 子账号最小权限访问，不建议长期使用主账号密钥。
3. Docker 需先确保 `docker version` 正常，且 Docker Desktop 已运行。
