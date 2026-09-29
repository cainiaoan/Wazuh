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
- 关联同一 Agent 上的防火墙丢弃事件，识别同源、多目标端口探测候选（规则 `100030`）。
- 按来源、资产、事件类别和时间窗关联告警，并识别“认证失败后成功登录”。
- 输出优先处置队列、事件时间线、身份与特权审计、Agent 健康、资产画像和 MITRE 覆盖。
- 对 HTML 内容转义，对 CSV 单元格进行 Excel 公式注入防护。
- 默认限制读取 25 万行、解压后 256 MiB、单行 1 MiB；拒绝非法 UTF-8，
  并中和换行伪造与双向文本控制符。
- HTML 报告启用严格 CSP；新建报告目录为 `0700`、报告文件为 `0600`（POSIX）。
- 使用临时文件和原子替换发布报告，降低输出中断导致新旧文件混合的风险。
- 报告生成器运行时仅依赖 Python 标准库，适合直接部署到 Wazuh Manager。

## 项目结构

```text
.
├── examples/
│   └── alerts.json                  真实 Wazuh JSONL 测试数据
├── reports/
│   └── latest/                      默认报告输出目录
├── rules/
│   └── local_rules.xml              Wazuh 自定义检测规则
├── pytest.ini                       pytest 测试发现和源码路径配置
├── requirements-dev.txt             测试开发依赖
├── scripts/
│   ├── soc_report.py                兼容的命令行入口
│   └── soc_reporting/
│       ├── cli.py                   参数校验和流程编排
│       ├── models.py                告警、事件和质量统计模型
│       ├── pipeline.py              解析、归一化、评分、关联和聚合
│       └── reporting.py             安全 CSV/JSON 输出和 HTML 渲染
└── tests/
    └── test_soc_reporting.py        pytest 回归测试
```

## 快速生成报告

在 Windows PowerShell 中：

```powershell
.\.venv\Scripts\python.exe .\scripts\soc_report.py `
  --input .\examples\alerts.json `
  --output-dir .\reports\latest `
  --timezone Asia/Shanghai
```

在 macOS 中：

```bash
python scripts/soc_report.py \
  --input examples/alerts.json \
  --output-dir reports/latest \
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

严格模式会在发现损坏/非对象 JSON、超长行或非法 UTF-8 时停止：

```bash
python3 scripts/soc_report.py \
  --input alerts.json \
  --output-dir reports/strict \
  --strict
```

默认最多读取 250,000 行、256 MiB 解压后内容，并拒绝超过 1 MiB 的单条 JSONL
记录，防止异常日志或压缩炸弹消耗过多内存。可按已验证的数据源调整；对应参数设为
`0` 表示关闭该项限制：

```bash
python3 scripts/soc_report.py \
  --input alerts.json \
  --output-dir reports/latest \
  --limit 500000 \
  --max-input-bytes 536870912 \
  --max-line-bytes 2097152
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

- 单条告警风险综合 Wazuh `rule.level`、事件类型、来源属性和自定义规则：
  `min(rule.level × 6, 75) + 类型加分 + 公网来源 7 分 + 自定义规则 5 分`，
  最终封顶 100 分。
- Wazuh 自身严重度是评分下限：level 4/8/12 及以上至少分别为
  Medium（40）、High（65）、Critical（85），避免新规则因尚未配置类型加分而被降级。
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

- 普通单次失败不会直接升级。至少 3 条失败，或 Wazuh 已明确判定为暴力破解/用户名枚举，
  才构成“失败链”；随后必须在窗口内出现同 Manager、同 Agent、同资产、同来源且账户匹配的
  成功登录，事件才升级为 `Suspected Compromise / 疑似账户失陷`（最低 95 分）。
- 已作为失陷证据的成功登录不会再生成一个重复的独立事件；事件 ID 由首条证据稳定哈希生成，
  不随风险排名变化。
- 风险评分用于调查排序，不替代人工定性；封禁、隔离和账户变更必须经过授权。

## 安全分析流程

1. **输入隔离与质量检查**：以二进制方式逐行读取 JSONL/`.gz`，先执行单行大小、
   UTF-8、JSON 对象和时间戳检查；记录损坏、超长、编码错误、重复与过滤统计。
2. **字段归一化**：从 Wazuh 结构化 `data` 优先提取来源/目标 IP、账户和命令；
   只有 SSH/PAM 认证上下文才允许从原始文本回退提取来源，防止 Web 请求内容伪造来源 IP。
3. **规则分类**：精确 `rule.id` 优先，其次使用可信规则组与限定上下文，最后才进入低置信度
   fallback。Web 文本中的 `invalid user` 不会被误分成 SSH 攻击。
4. **单告警评分**：应用 Wazuh 等级、场景加分、来源属性、自定义规则及严重度下限，
   映射为 Low/Medium/High/Critical。
5. **事件关联**：按 Manager、Agent、资产、来源、事件类别和身份维度聚合时间相邻告警；
   未知来源的认证记录不会无条件合并，失败后成功关联还要求来源、资产和账户一致。
6. **聚合与响应**：生成来源、资产、规则、MITRE、身份/特权、Agent 健康和时间趋势，
   再输出人工确认、封禁候选、账户核查、ACL/WAF 调整等建议，不自动执行破坏性动作。
7. **安全发布**：阻止输入文件与固定报告文件碰撞，CSV 公式中和、HTML 全量转义并启用 CSP，
   使用私有临时文件和原子替换发布每个结果文件。

## 运行测试

先安装测试依赖：

```bash
python3 -m pip install -r requirements-dev.txt
```

然后运行完整测试：

```bash
python3 -m pytest
```

回归测试覆盖来源 IP/分类欺骗、规则 `2502` 与端口扫描分类、sudo 用户角色、脏用户名、
失败后成功登录的正反例、极端时间戳、损坏/超长/非法编码 JSON、跨 Agent 重复 ID、
输入覆盖保护、CSV 公式注入、HTML 转义/CSP、完整报告文件清单及规则表一致性。

## 自定义 Wazuh 规则

`rules/local_rules.xml` 包含以下实验规则：

```text
100010  SSH 暴力破解
100011  SSH 无效用户名
100012  SSH 用户名枚举
100020  Web 扫描器活动
100021  Web 目录爆破
100030  防火墙丢弃事件关联的疑似多端口探测
```

安装前应先使用 Wazuh 规则测试工具验证，并根据实际网络基线调整频率与时间窗。
规则 `100030` 依赖上游防火墙 decoder 提供 `srcip`/`dstport` 且基础规则属于
`firewall_drop` 组；不满足该条件时不会触发。Wazuh 的 `different_dstport` 表示端口发生变化，
并不保证 12 次命中对应 12 个唯一端口，因此该规则是需要调优和人工确认的候选信号，
也不覆盖“同一端口、多个目标 IP”的水平扫描。

## 当前边界

- 本项目是 Wazuh 告警文件的**离线二次分析与静态报告器**，不负责 Agent/Manager 部署、
  持续 tail、任务调度、通知或主动响应。
- 单次运行只分析一个文件，跨轮转文件和跨运行周期的事件不会自动关联。
- “异常登录”当前指有充分失败证据后的成功认证，不包含异地登录、非工作时段、
  新设备或不可能旅行等需要身份基线的数据模型。
- 报告包含账户、命令、内网地址和原始证据，虽使用私有文件权限，分享前仍应按组织策略脱敏。
- 输出文件分别原子替换，但整套报告尚不是一次事务提交；超大规模输入仍建议先分时段快照，
  并在验证资源容量后调整 `--limit`、`--max-input-bytes` 和 `--max-line-bytes`。
