# ISCP fork 中的 SparkClaw 基线

[English](../../docs/sparkclaw-baseline.md)

本 fork 以 ISCP `47f1f6c231c56c92eff6b6c5d398e037ebcf9602` 为起点，导入
SparkClaw `cf9b81dec39b8872efc43650080bb8facaa58511` 的传输实现。来源是
[Infinimesh-ai/SparkClaw](https://github.com/Infinimesh-ai/SparkClaw)，后续开发位置是
[此 fork](https://github.com/ZZZZJJJ0928/ISCP)。这是开发基线，不代表上游协议发布。
源 SparkClaw 依赖 `github.com/Infinimesh-ai/ISCP v0.2.0-rc.1`。

## 包含范围

| 位置 | 职责 |
| --- | --- |
| `pkg/server/relay` | 当前 Relay：持续接收、独立心跳、持久队列领取、写失败回滚、撤销、持久签名密钥及托管授权钩子 |
| `pkg/iscp/appstream` | 可选通用应用帧、订阅标识、序号校验、取消及结束解码 |
| `schemas/candidates/application-stream.v1.json` | 原样保留的应用流候选 Schema，保留原 ID 和候选状态 |
| `extensions/sparkclaw/iscpauth` | 长期授权、scope 和 Grant 策略 |
| `extensions/sparkclaw/iscpbridge` | 可独立使用的配置、注册、凭据恢复、Relay 客户端、身份与 Grant 验证 |
| `extensions/sparkclaw/iscplocalenroll`、`iscplocalissuer` | 本地注册与签发，包含续期、重新授权、删除 |
| `extensions/sparkclaw/iscpnodeclient`、`iscpnodeissuer`、`iscpnodecontrol` | 节点注册、持久加密授权状态、绑定设备证明的控制 peer 与恢复 |
| `extensions/sparkclaw/iscprelayadapter` | PostgreSQL 授权事务、服务身份恢复、设备隔离及多授权方路由 |
| `extensions/sparkclaw/iscpworkbench` | 桌面 helper RPC、加密应用流、权限检查及取消 |
| `extensions/sparkclaw/protocol` | SparkClaw bridge/execution Schema、fixtures 及桌面操作投影 |
| `cmd/iscp-*` | 下表所列七个独立命令 |

原有 `services/relay-reference/cmd/relayd` 已使用 `pkg/server/relay`。被替代的私有
参考实现已经移除，原测试保留在导入的 Relay 测试中。为使迁移可核对，Go package
名称、wire 名称、环境变量名称保持原样。

## 当前行为

信封仍通过 HTTP `POST /v2/relay/envelopes` 提交；设备完成原有 challenge/READY
交换后，通过 `GET /v2/relay/connect` 持续接收。固定 55 秒接收窗口已经取消，空闲
心跳不阻塞队列数据。导入的测试覆盖连接替换、撤销、关闭及写失败。接收连接与应用
订阅的生命周期分开：应用结束、续订、ACK 仍按原语义处理。

授权仍分为 Relay access、设备持有证明、端到端 Grant 和应用 scope。导入保留注册、
续期、撤销、永久授权修订、恢复回执、加密 issuer 存储及原有凭据到期检查。本次未
增加 WebSocket 提交、改变密码格式或增加投递保证；全双工传输是后续设计变更。

可选的 `POST /api/sparkclaw/iscp-control/v1/service-recover` 是 SparkClaw 扩展。
它要求配置托管适配器，并且服务身份已获批准；不能注册或复活设备。未配置该适配器
的普通参考部署返回 404。

## 构建与运行

使用 Go 1.25 系列的 1.25.5 或更高版本，无需 SparkClaw checkout、外部 Go workspace
或本地模块替换：

```sh
GOWORK=off go build ./...
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go run ./services/relay-reference/cmd/relayd
```

参考命令沿用 local-lab 默认配置，可通过 `ISCP_RELAY_SIGNER_FILE` 启用导入的签名
密钥持久化。生产 `iscp-public-relay` 沿用 SparkClaw 的 `ISCP_SIGNER_FILE` 名称，
要求持久 PostgreSQL 及原有生产配置。运行前明确配置 domain、Relay URL、身份、
授权方及私有路径；命令中保留的历史部署默认值不代表本次部署。

| 命令 | 用途 |
| --- | --- |
| `go build ./cmd/iscp-public-relay` | 生产 Relay 与托管事务 socket |
| `go build ./cmd/iscp-control-forwarder` | 加密 issuer/control peer 转发 |
| `go build ./cmd/iscp-node-issuer` | 节点授权方与邀请管理 |
| `go build ./cmd/iscp-node-provision` | 设备初始化及运维配给 |
| `go build ./cmd/iscp-local-issuer` | 私有本地测试 issuer |
| `go build ./cmd/iscp-local-enroll` | 本地注册及已固定凭据刷新 |
| `go build ./cmd/iscp-workbench` | 保留 stdin/stdout 协议的桌面 helper |

仓库不包含生产配置或凭据。基线已在 macOS arm64 构建，并交叉构建 Linux amd64。
原生 keyring 行为和部署环境仍需各自的集成验收。

## 核验与来源

`extensions/sparkclaw/baseline-manifest.json` 记录 159 个源/目标文件、3 处抽取、
源及目标 SHA-256、固定提交、排除的业务文件以及 import/fixture 路径调整。
抽取 helper 保留原函数体和常量；混合的 bridge 契约测试仅移除了两个被排除的
Gateway 业务适配器测试。

```sh
python3 scripts/verify-sparkclaw-baseline.py
# 可选：对固定源提交独立重放迁移：
python3 scripts/verify-sparkclaw-baseline.py --source /path/to/SparkClaw
node scripts/sync-iscp-operations.mjs --check
```

清单描述本次历史导入，后续有意修改会报告基线偏移，不应重写摘要来隐藏变更。
操作注册表继续生成 Go 常量和桌面投影；修改注册表后运行
`node scripts/sync-iscp-operations.mjs`。

使用一次性 PostgreSQL 数据库验证：

```sh
SC_RELAY_TEST_DSN="$TEST_DATABASE_URL" SC_RELAY_LONG_TEST=1 \
  GOWORK=off go test -race -count=1 ./...
SC_ISCP_NODE_TEST_DSN="$TEST_DATABASE_URL" \
  GOWORK=off go test -p 1 -race -count=1 \
  ./extensions/sparkclaw/iscpnodeclient ./extensions/sparkclaw/iscpnodeissuer
```

数据库角色需要创建临时数据库的权限，测试不能指向部署中的状态。节点 fixture
包共用 Schema，须通过 `-p 1` 串行运行，避免初始化 DDL 竞争。CI 包含两组 PostgreSQL
测试以及跨越原 55 秒边界的接收测试。本次结果记录于
`extensions/sparkclaw/baseline-validation.json`。

功能检查通过不代表发布安全验收。导入时 `govulncheck` 在源版本固定的
`golang.org/x/text v0.38.0` 中报告可达通告 GO-2026-6629、GO-2026-5970；gosec
报告 28 项待复核告警。本次为保留基线，未改这些依赖版本和函数体，原发布门禁也
保持启用且未压制告警。声称 fork 可发布之前，需要独立的安全更新与复核。

## 归属与后续开发

SparkClaw 的 Agent runtime、UI、业务存储、Gateway handlers 和原 phone bridge
业务服务留在原仓库。本轮未切换 SparkClaw 模块版本，也未改变运行中的 Relay、
数据库或已安装客户端。在独立的消费方迁移完成版本固定和 import 替换前，框架中
仍保留原传输副本。

后续传输、Relay、授权变更在此开发；SparkClaw 专用绑定留在 `extensions/sparkclaw`，
通用候选经协议决策流程后再升级。保留上游 Go 模块名以维持兼容，消费方采用时明确
固定 fork 的版本。`origin` 指向个人 fork，`upstream` 指向 `Infinimesh-ai/ISCP`。

原 ISCP MIT 和导入 SparkClaw Apache-2.0 许可证均保留，详见
[NOTICE](../../NOTICE) 与 `extensions/sparkclaw/SPARKCLAW_LICENSE.txt`；导入不改变许可。
