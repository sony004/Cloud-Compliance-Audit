# Alibaba Cloud 閸氬牐顫夌€孤ゎ吀娑?NIST 閺勭姴鐨犳い鍦窗

閺堫剟銆嶉惄顔肩唨娴?**Prowler** 鐎?Alibaba Cloud 鏉╂稖顢戦懛顏勫З閸栨牗顥呴弻銉礉楠炶埖澧跨仦鏇氱啊娴犮儰绗呴懗钘夊閿?
- 濡偓閺屻儳绮ㄩ弸婊勬Ё鐏忓嫬鍩?**NIST SP 800-53 Rev.5** 閹貉冨煑妞?- 閻㈢喐鍨氶幒褍鍩楁い鍦獓濮瑰洦鈧眹鈧焦妲戠紒鍡愨偓涓燭ML閵嗕副SCAL 娑撳氦鐦夐幑顔界閸?- 鏉╃偟鐢婚崥鍫ｎ潐韫囶偆鍙庢稉搴℃▕瀵倸鍨庨弸鎰剁礄閺傛澘顤冩径杈Е閵嗕椒鎱ㄦ径宥冣偓浣哄Ц閹礁褰夐崠鏍电礆
- 閼奉亜濮╅悽鐔稿灇閹貉冨煑妞ょ绉奸崝鍨禈閿涘牅绱崗?PNG閿涘瞼宸辨笟婵婄閺冭泛娲栭柅鈧?SVG閿?- 鐠囦焦宓侀柧鎯х暚閺佸瓨鈧勭墡妤犲奔绗岀弧鈩冩暭鐎圭偤鐛欓敍鍦楢IL -> PASS閿涘矁鍤滈崝銊ユ礀濠婃熬绱?- 閺勭姴鐨犻弫鍫熺亯閸掑棙鐎介敍鍫ｎ洬閻╂牜宸奸妴浣恒仛娓氬鈧焦甯堕崚璺虹厵閸掑棗绔烽崶鎾呯礆

## 1. 妞ゅ湱娲扮紒鎾寸€?
- `src/aliyun_project/cli.py`閿涙氨绮烘稉鈧?CLI 閸忋儱褰涢敍鍧剆can` / `summary` / `nist-map` / `verify-evidence` / `tamper-evidence`閿?- `src/aliyun_project/nist_mapping.py`閿涙瓊IST 閹貉冨煑閺勭姴鐨犳稉搴㈠Г閸涘﹦鏁撻幋?- `src/aliyun_project/continuous_compliance.py`閿涙俺绻涚紒顓炴値鐟欏嫬鎻╅悡褋鈧礁妯婂鍌樷偓浣界Ъ閸斿灝娴?- `src/aliyun_project/verify_evidence_chain.py`閿涙俺鐦夐幑顕€鎽奸弽锟犵崣
- `src/aliyun_project/evidence_tamper_experiment.py`閿涙氨顕栭弨鐟扮杽妤犲奔绗岄崶鐐寸泊
- `rules/mappings/nist_800_53_rev5_alibabacloud.json`閿涙瓊IST 閺勭姴鐨犵憴鍕灟
- `run_scan_docker.ps1`閿涙ocker 娑撯偓闁款喗澹傞幓?+ 閼奉亜濮?NIST 閺勭姴鐨?- `run_scan.ps1`閿涙瓍oetry 閺堫剙婀撮幍顐ｅ伎
- `run_sync.ps1`閿涙艾鎮撳銉潐閸?- `Dockerfile.prowler-patched`閿涙岸銆嶉惄顔肩暰閸掑爼鏆呴崓蹇ョ礄閸氼偉藟娑撲焦顥呴弻銉┿€嶆稉搴ｇ帛閸ュ彞绶风挧鏍电礆

## 2. 閻滎垰顣ㄧ憰浣圭湴

- Windows + PowerShell
- Docker閿涘牊甯归懡鎰剁礆
- 閹?Python 3.10~3.12 + Poetry

## 3. 閸戭厽宓侀柊宥囩枂

妫ｆ牗顐兼潻鎰攽閸撳秴鍣径?`.env`閿?
```powershell
Copy-Item .env.example .env
```

婵夘偄鍟撻敍?
```env
ALIBABA_CLOUD_ACCESS_KEY_ID=<your_access_key_id>
ALIBABA_CLOUD_ACCESS_KEY_SECRET=<your_access_key_secret>
# Optional (STS)
# ALIBABA_CLOUD_SECURITY_TOKEN=<your_security_token>
```

## 4. 韫囶偊鈧喎绱戞慨瀣剁礄Docker閿涘本甯归懡鎰剁礆

```powershell
.\run_scan_docker.ps1
```

姒涙顓荤悰灞艰礋閿?
1. 娴ｈ法鏁ら梹婊冨剼 `aliyun-prowler-patched:latest` 鏉╂劘顢戦幍顐ｅ伎
2. 閼汇儵鏆呴崓蹇庣瑝鐎涙ê婀崚娆掑殰閸斻劍鐗撮幑?`Dockerfile.prowler-patched` 閺嬪嫬缂?3. 閹殿偅寮跨紒鎾存将閼奉亜濮╅幍褑顢?`nist-map`
4. 閼奉亜濮╅弴瀛樻煀鏉╃偟鐢婚崥鍫ｎ潐閿涘牆鎻╅悡褋鈧礁妯婂鍌樷偓浣界Ъ閸斿灝娴橀敍?
鐢摜鏁ら崣鍌涙殶閿?
```powershell
# 閹稿洤鐣鹃崠鍝勭厵
.\run_scan_docker.ps1 -Region cn-beijing,cn-shanghai

# 閹稿洤鐣?compliance
.\run_scan_docker.ps1 -Compliance cis_2.0_alibabacloud

# 娴ｈ法鏁ら張顒€婀?checks 閸掓銆?.\run_scan_docker.ps1 -UseLocalChecks

# 韫囩晫鏆?Prowler 閸欐垹骞囨い纭呯箲閸ョ偟鐖?3
.\run_scan_docker.ps1 -IgnoreExitCode3

# 瀵搫鍩楅柌宥呯紦闂€婊冨剼
.\run_scan_docker.ps1 -BuildImage

# 娴犲懏澹傞幓蹇庣瑝閸?NIST 閺勭姴鐨?.\run_scan_docker.ps1 -SkipNistMap

# 娴犲懏妲х亸鍕瘹鐎规艾鐤勬笟瀣祲閸忓疇顔囪ぐ?.\run_scan_docker.ps1 -TargetInstanceId i-xxxxxx

# 娴ｈ法鏁ら懛顏勭暰娑斿鏆呴崓?.\run_scan_docker.ps1 -Image toniblyx/prowler:stable
```

## 5. 閺堫剙婀存潻鎰攽閿涘湧oetry閿?
```powershell
py -m poetry install
.\run_scan.ps1
```

> `run_scan.ps1` 娴兼艾鍘涢幍褑顢?`poetry install`閿涘瞼鍔ч崥搴ょ殶閻?`aliyun-audit scan`閵?
## 6. CLI 閻劍纭?
### 6.1 閹殿偅寮?
```powershell
poetry run aliyun-audit scan --region cn-beijing --compliance cis_2.0_alibabacloud
```

### 6.2 濮瑰洦鈧?
```powershell
poetry run aliyun-audit summary
poetry run aliyun-audit summary --file output/compliance/<file>.csv --top 10
```

### 6.3 NIST 閺勭姴鐨?
```powershell
poetry run aliyun-audit nist-map
```

閸欘垶鈧绱?
```powershell
poetry run aliyun-audit nist-map `
  --file output/prowler-output-<account>-<time>.csv `
  --mapping-file rules/mappings/nist_800_53_rev5_alibabacloud.json `
  --report-dir output/nist `
  --continuous-dir output/continuous
```

婵″倿娓剁捄瀹犵箖鏉╃偟鐢婚崥鍫ｎ潐閿?
```powershell
poetry run aliyun-audit nist-map --skip-continuous
```

### 6.4 鐠囦焦宓侀柧鐐墡妤?
```powershell
poetry run aliyun-audit verify-evidence
poetry run aliyun-audit verify-evidence --file output/nist/<manifest>.json
```

### 6.5 缁♀剝鏁肩€圭偤鐛欓敍鍫ｅ殰閸斻劌娲栧姘剧礆

```powershell
poetry run aliyun-audit tamper-evidence
poetry run aliyun-audit tamper-evidence --file output/nist/<manifest>.json
```

## 7. 閺勭姴鐨犻弫鍫熺亯閸掑棙鐎?
鏉╂劘顢戦敍?
```powershell
```

## 8. 娑撴槒顩︽潏鎾冲毉鐠囧瓨妲?
### 8.1 閸樼喎顫愰幍顐ｅ伎鏉堟挸鍤敍鍧刼utput/`閿?
- `prowler-output-<account>-<time>.csv`
- `prowler-output-<account>-<time>.html`
- `prowler-output-<account>-<time>.ocsf.json`

### 8.2 NIST 閺勭姴鐨犳潏鎾冲毉閿涘潉output/nist/`閿?
- `*_nist80053_control_summary.csv`
- `*_nist80053_control_details.csv`
- `*_nist80053_control_report.html`
- `*_nist80053_control_summary.json`
- `*_nist80053_assessment-results.oscal.json`
- `*_nist80053_evidence_manifest.json`
- `*_nist80053_control_evidence_index.csv`

### 8.3 鏉╃偟鐢婚崥鍫ｎ潐鏉堟挸鍤敍鍧刼utput/continuous/`閿?
- `snapshots/*_control_snapshot.json`
- `*_control_diff.csv`
- `*_control_diff.json`
- `control_trend.csv`
- `control_trend_trajectory.png`閿涘牐瀚?`pandas/matplotlib` 閸欘垳鏁ら敍?- `control_trend_trajectory.svg`閿涘牅绶风挧鏍繁婢惰鲸妞傞懛顏勫З閸ョ偤鈧偓閿?
## 9. 鐟欏嫬鍨崥灞绢劄

```powershell
.\run_sync.ps1
```

閹存牗瀵氱€?Prowler 濠ф劗鐖滈惄顔肩秿閿?
```powershell
.\run_sync.ps1 -SourceRoot "E:\path\to\prowler"
```

閸氬本顒為崘鍛啇閿?
- `rules/compliance/alibabacloud/*.json`
- `rules/checks/alibabacloud_all_checks.json`
- `rules/checks/cis_2.0_alibabacloud_checks.json`

## 10. 鐢瓕顫嗛梻顕€顣?
### 10.1 閹殿偅寮块崥搴㈢梾閻鍩岀搾瀣◢閸?
- 閼汇儴绻涚紒顓炴値鐟欏嫭顒滅敮闀愮稻濞屸剝婀?PNG閿涘矂鈧艾鐖堕弰顖濈箥鐞涘瞼骞嗘晶鍐繁鐏?`pandas/matplotlib`
- 妞ゅ湱娲板鍙夋暜閹镐礁娲栭柅鈧悽鐔稿灇 SVG閿涙瓪output/continuous/control_trend_trajectory.svg`
- Docker 閹恒劏宕樻担璺ㄦ暏姒涙顓婚梹婊冨剼 `aliyun-prowler-patched:latest`閿涘牆鍑￠崠鍛儓缂佹ê娴樻笟婵婄閿?
### 10.2 `run_scan_docker.ps1` 閺嬪嫬缂撴径杈Е

濡偓閺屻儻绱?
- Docker Desktop 閺勵垰鎯侀崥顖氬З
- 缂冩垹绮堕弰顖氭儊閸欘垱濯洪崣鏍х唨绾偓闂€婊冨剼 `toniblyx/prowler:stable`
- 閸戭厽宓侀弬鍥︽ `.env` 閺勵垰鎯佺€涙ê婀稉鏃€婀侀弫?
### 10.3 `verify-evidence` 鏉╂柨娲栭棃?0

鐞涖劎銇氱拠浣瑰祦闁剧偓鍨?payload 閺嶏繝鐛欐稉宥勭閼锋番鈧倸褰茬紒鎾虫値閿?
- `*_nist80053_evidence_manifest.json`
- `tamper-evidence` 閻㈢喐鍨氶惃鍕杽妤犲本濮ら崨?
鐎规矮缍呴梻顕€顣介弶銉︾爱閵