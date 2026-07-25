# 企业内网安全日志监控与告警响应平台

本项目使用 Wazuh 收集企业内网安全日志，并通过标准库 Python 程序对
`alerts.json` 进行二次处理，输出适合安全运营人员阅读的中文 HTML、CSV
和 JSON 报告。

报告生成器不仅统计单条告警，还会在明确时间窗口内把同一来源、同一资产和
同一安全场景的记录关联为“安全事件”。例如，同一来源连续认证失败后又成功
登录，会被升级为需要优先核查的疑似账户失陷事件。

## 核心能力

- 流式读取 Wazuh JSONL，以及轮转后的 `.json.gz` 文件。
- 统计有效记录、损坏 JSON、重复事件、无效时间戳和各类过滤数量。
- 归一化 Agent、来源 IP、资产 IP、操作账户、目标账户、命令、规则和 MITRE 字段。
- 来源地址缺失时保持 `Unknown`，不会把 Agent IP 错当作攻击源。
- 精确识别 SSH 失败/成功、暴力破解、sudo、Agent 启停、端口变化、FIM 和系统时间变化。
- 按来源、资产、事件类别和时间窗关联告警，并识别“认证失败后成功登录”。
- 输出优先处置队列、事件时间线、身份与特权审计、Agent 健康、资产画像和 MITRE 覆盖。
- 对 HTML 内容转义，对 CSV 单元格进行 Excel 公式注入防护。
- 使用临时文件和原子替换发布报告，降低输出中断导致新旧文件混合的风险。
- 仅依赖 Python 标准库，适合直接部署到 Wazuh Manager。

## 项目结构

```text
.
├── examples/
│   └── alerts.json                  真实 Wazuh JSONL 测试数据
├── reports/
│   └── latest/                      默认报告输出目录
├── rules/
│   └── local_rules.xml              Wazuh 自定义检测规则
├── scripts/
│   ├── soc_report.py                兼容的命令行入口
│   └── soc_reporting/
│       ├── cli.py                   参数校验和流程编排
│       ├── models.py                告警、事件和质量统计模型
│       ├── pipeline.py              解析、归一化、评分、关联和聚合
│       └── reporting.py             安全 CSV/JSON 输出和 HTML 渲染
└── tests/
    └── test_soc_reporting.py        标准库 unittest 回归测试
```

## 快速生成报告

在 Windows PowerShell 中：

```powershell
.\.venv\Scripts\python.exe .\scripts\soc_report.py `
  --input .\examples\alerts.json `
  --output-dir .\reports\latest `
  --timezone Asia/Shanghai
```

如果没有项目虚拟环境，也可以使用系统 Python：

```powershell
python .\scripts\soc_report.py `
  --input .\examples\alerts.json `
  --output-dir .\reports\latest
```

在 Wazuh Manager 上处理活动告警文件：

```bash
python3 scripts/soc_report.py \
  --input /var/ossec/logs/alerts/alerts.json \
  --output-dir reports/latest \
  --since 2026-07-26T00:00:00+08:00 \
  --incident-window-minutes 10
```

建议先制作只读快照，再以普通用户运行报告程序，避免长期使用 root 权限：

```bash
sudo install -o "$USER" -g "$(id -gn)" -m 600 \
  /var/ossec/logs/alerts/alerts.json /tmp/alerts-snapshot.json

python3 scripts/soc_report.py \
  --input /tmp/alerts-snapshot.json \
  --output-dir reports/latest
```

## 常用筛选

只报告等级 5 及以上：

```bash
python3 scripts/soc_report.py \
  --input alerts.json \
  --output-dir reports/high \
  --min-level 5
```

只保留安全运营场景，排除普通会话和未分类噪声：

```bash
python3 scripts/soc_report.py \
  --input alerts.json \
  --output-dir reports/soc-only \
  --soc-only
```

处理轮转压缩文件：

```bash
python3 scripts/soc_report.py \
  --input ossec-alerts-25.json.gz \
  --output-dir reports/2026-07-25
```

严格模式会在发现损坏 JSON 或非对象 JSON 时停止：

```bash
python3 scripts/soc_report.py \
  --input alerts.json \
  --output-dir reports/strict \
  --strict
```

完整参数：

```bash
python3 scripts/soc_report.py --help
```

## 输出文件

```text
security_operations_report.html   中文安全运营主报告
report_summary.json               指标、质量统计和前十优先事件
cleaned_alerts.csv                归一化告警明细
incidents.csv                     时间窗关联后的安全事件
summary_by_source_ip.csv          已知来源 IP 汇总
summary_by_alert_type.csv         告警类型汇总
summary_by_asset.csv              资产汇总
summary_by_rule.csv               Wazuh 规则汇总
mitre_attack_summary.csv          MITRE 战术与技术映射
response_recommendations.csv      按事件生成的响应建议
alert_timeline.csv                报告周期时间桶趋势
```

## 风险与关联口径

- 单条告警风险综合 Wazuh `rule.level`、事件类型、来源属性和自定义规则。
- `rule.firedtimes` 是 Wazuh 规则累计触发信息，不作为单事件频次直接加分。
- 事件频次按来源 IP、受影响资产、事件类别和 `--incident-window-minutes`
  重新计算。
- 默认风险等级：

```text
Critical / 严重：85-100
High     / 高危：65-84
Medium   / 中危：40-64
Low      / 低危：0-39
```

- 同一来源在认证失败链后于关联窗口内成功登录时，事件会升级为
  `Suspected Compromise / 疑似账户失陷`。
- 风险评分用于调查排序，不替代人工定性；封禁、隔离和账户变更必须经过授权。

## 运行测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

回归测试覆盖来源 IP 误归因、规则 `2502` 分类、sudo 用户角色、脏用户名、
失败后成功登录关联、损坏 JSON、重复事件、CSV 公式注入和 HTML 转义。

## 自定义 Wazuh 规则

`rules/local_rules.xml` 包含以下实验规则：

```text
100010  SSH 暴力破解
100011  SSH 无效用户名
100012  SSH 用户名枚举
100020  Web 扫描器活动
100021  Web 目录爆破
```

安装前应先使用 Wazuh 规则测试工具验证，并根据实际网络基线调整频率与时间窗。
