# 连接认证与操作恢复 v2 冻结候选

语言：简体中文 | [English](../../spec/authentication-operation-recovery-v2.md)

状态：2026-10-19，**InfiniCenter 0041 评审候选**。本文、
[封闭 schema](../../schemas/candidates/operation-recovery.v2.json)、
[测试向量](../../conformance/fixtures/operation-recovery.v2.json)及测试专用 API
仅供冻结评审，不表示已接受、对外公布或实现。服务与客户端独立构建发布。

## 1 范围与操作类型

协议名为 `iscp.operation.recovery.v2`。issuer 使用
`control.credentials.v2`，Relay 使用 `control.relay-credentials.v2`。
此次新控制协议仅冻结以下四类。既有业务保留原严格 schema、任务授权及契约；
SparkClaw 的完整业务恢复清单另行记录真实入口、待补能力和验收要求。
不能把已有处理器自动升级为 find-or-admit；不导入旧 pending、不迁移源码或模块。

| kind | 命名空间 / 目标 | 精确 payload | 成功结果 body |
| --- | --- | --- | --- |
| `credential.renew` | `control.credentials.v2` / issuer | 排序去重的 `requested_scopes` | `grant` |
| `credential.recover` | `control.credentials.v2` / issuer | 排序去重的 `requested_scopes` | `grant`、完整签名 `relay_result` |
| `relay.refresh` | `control.relay-credentials.v2` / Relay | 排序去重的 `requested_scopes` | `relay_credentials` |
| `relay.recover` | `control.relay-credentials.v2` / Relay | 排序去重的 `requested_scopes` | `relay_credentials` |

控制意图使用 standing 授权、null 业务期限和原绑定；授权 scopes 与 payload 一致，
且为当前长期授权子集。前置条件为目标持久资源版本、目标凭据 generation 和授权
revision。已有操作先查账本再比较当前 generation，不能因轮换而丢失旧结果。
这些控制 CAS 字段不能混入普通业务意图。可选 parent/predecessor 也属于不可变意图。
失败/取消 body 只含 schema 的 code。Grant/凭据对象封闭，仍校验签名、目标、
confirmation、权限和时效；renew 不得附带 Relay 凭据，recover 不得缺少子结果。

父结果 generation 属于 issuer；受限、不可递归的 `relay_result` 保留 Relay 签名、
目标服务、绑定、独立 generation 与授权 revision。客户端除验证 issuer 外签，
还验证原 pinned Relay 签名及 actor/subject/target/generation 链接。
issuer generation 9 和 Relay generation 22 分别执行 CAS；两部分持久安装后才
确认父结果。崩溃后逐项对账，不能拿父代数安装 Relay 凭据。

## 2 HTTPS 入口及结果

以下均为原 pinned authority 的 HTTPS POST，禁止重定向；挑战与长期身份恢复
不依赖已认证 WSS，也不要求旧 access/refresh 仍有效。

| 路径 | 输入 / 输出 |
| --- | --- |
| `/v2/control/challenge` | challenge_request / challenge，不泄露账户状态或授予权限 |
| `/v2/control/operations/submit` | request_submit / 签名状态或密封不可变结果 |
| `/v2/control/operations/lookup` | request_lookup / 签名状态或结果，永不执行 |
| `/v2/control/operations/recover` | request_recover / 四类控制操作原子查找或受理 |
| `/v2/control/operations/ack` | request_ack / 签名不可变处置回执 |

action 必须匹配真实路径。上下文 domain/device 是认证 actor，必须等于操作键主体；
意图 namespace/operation_id 与键一致，target.service_id 等于 audience。
直接请求 actor=subject，仅第 6 节允许委托例外；不能用自报 header 声称身份。
转发保留原路径和正文，由最终 issuer 验证。

公共 HTTPS ingress 的 challenge_request.audience 只能选预配置可信路由。
authority 发出的 challenge_id 在 ingress 保存为十秒有效的不透明路由映射；
后续 submit/lookup/recover/ack 均按映射转发。最终验证器独立检查 audience/path。
该通路为独立受保护 HTTPS/服务通道，不能依赖过期 WSS peer。不能接受调用方 URL
或未签路由 header。映射未知或 ingress 重启后重新挑战，操作编号不变。
未到达目标签名者的失败只表示传输不明，不能证明撤销。

HTTP 200 为状态/结果/处置；400 格式错误、401 认证失败、403 权限拒绝、409 意图
或 generation 冲突、410 命名空间关闭、503 暂不可用。控制错误为签名类型对象；
仅 HTTP 状态不能证明撤销、未受理或回滚。请求/结果上限 128 KiB，不能截断结果。

状态包含 admitted/running/succeeded/failed/cancelled/absent/unknown/conflict/
namespace_closed。admitted/running 的历史完整、code=none、结果摘要为 null；
终态保留结果摘要，code 为 none 或 result_expired。absent 还要求 record_version=0。
history_unavailable 只能是 unknown 且历史不完整；commit_unknown/effect_unknown
对应历史完整但本次结果不明；conflict 不披露结果；关闭命名空间返回相应 code 和
历史不完整。absence 需持同键锁完成准入屏障，只是某个时点的观察，只有 recover
事务才能原子受理；JingSi not_started 继续永久禁止该键受理。

错误 retryable 仅在 challenge_expired/authorization_unavailable/resource_exhausted
为 true。无可信关联的错误用 null attempt_id/key/revision，不回显非法字段。
revoked/ended 必须绑定合法本次 attempt、actor 操作键和授权 revision；普通拒绝
不等于撤销。签名也须匹配原 authority 和本次请求。

## 3 规范编码与认证字节

使用 ISCP 严格编码：合法 UTF-8，无重复键、孤立 surrogate、尾随数据、浮点/指数、
未知字段或非规范 base64url。计数器为 uint64 范围的无前导零十进制字符串，既有
Grant revision 为安全 JSON 整数。时间必须是有效公历 UTC 秒精度 RFC3339。
scope 数组按 UTF-8 排序且唯一；base64url 解码再编码必须逐字相同。schema 匹配
不替代这些语义检查。

令 C 为规范字节，H 为 SHA256 后无填充 base64url，`\0` 为一个 NUL：

```text
semantic_digest = H("ISCP-OPERATION-INTENT-V2\0" || C(intent))
request_digest = H("ISCP-CONTROL-REQUEST-V2\0" || C(request without authentication))
signature_input = "ISCP-V2-SIGNATURE\0iscp.control.authentication.v2\0" || C(context)
```

context 按 schema 包含协议、purpose、真实 method/path、配置 audience、已验证
actor、服务挑战及编号、nonce、issued_at、request_digest 和 credential_sha256。
最后一项为精确 bearer token UTF-8 字节的 SHA256，没提供 token 时为 null。
不能把无效 token 静默当作未提供；长期身份恢复可显式省略过期 token。
认证签署该上下文，不重用旧 DeviceProof，不递归签署自身。换 wrap key、attempt、
路径、audience、token 或意图都会改变认证绑定，不改变原操作身份。

challenge/challenge_id 分别为 32 字节随机数，有效十秒，绑定 authority/actor/
purpose，并与认证动作原子消费。nonce 为 16–64 字节随机数；issued_at 可落后
服务器 60 秒或领先 30 秒，但不延长挑战。丢响应后重新挑战。Ed25519 KID 与登记
身份一致；服务在认证、准入与披露边界按第 7 节检查当前权限，签名不复活撤销权限。

## 4 不可变结果、重密封与处置

```text
result_digest = H("ISCP-OPERATION-RESULT-V2\0" || C(result.payload))
result signature = SignatureInput("iscp.operation.result.v2", result without signature)
disposition_digest = H("ISCP-OPERATION-DISPOSITION-V2\0" || C(disposition without
                       signature, disposition_digest, accepted_at))
```

版本、键、意图摘要、终态、完成时间、签发 generation 和 body 不可变；重取结果
字节及签名一致。status/disposition 分别用其 type 作为 SignatureInput 类型。
按原可信 issuer/Relay 公钥验证。

重密封采用 X25519/HKDF-SHA256/ChaCha20Poly1305。delivery_context 精确包含
protocol、actor 操作键、semantic_digest、result_digest、delivery_id、接收方及
服务端 X25519 公钥。delivery_id 为 32 随机字节，nonce 为 12 随机字节，每次
密封使用新服务端私钥，拒绝无效或低阶共享密钥。

```text
salt = SHA256("ISCP-CONTROL-RESULT-SALT-V2\0" || C(delivery_context))
key = HKDF-SHA256(X25519(server_private, recipient_public), salt,
                 "ISCP-CONTROL-RESULT-KEY-V2\0" || C(delivery_context), 32)
aad = "ISCP-CONTROL-RESULT-AAD-V2\0" || C(delivery_context)
plaintext = C(the same signed result)
```

新请求认证保护接收密钥，当前 actor 必须仍有结果读取权限。委托子结果先交给
issuer，再作为完整签名子结果进入原用户父结果，不直接披露给其他设备。
秘密在存储和传输中加密，不写日志或明文 journal。

ACK 精确绑定结果摘要及 generation。installed 表示原凭据在有效期内已通过本地
身份/代数 CAS 持久安装；acknowledged_expired 明确关闭过期结果；
acknowledged_superseded 明确关闭已被更高持久代数隔离的结果。applied 仅用于
非凭据结果，不能冒充安装。服务按不可变结果和当前代数校验处置。

仅登记 issuer actor 能以 delegated 确认自己的委托 Relay 子结果，且必须提供
parent_result_digest。先冻结并持久保存包含子结果的签名父结果，再取得并保存
Relay delegated 回执，最后重查当前父权限并发布完成。delegated 表示进入该
不可变父结果，不虚称终端安装；丢 ACK 只重试相同处置。其他处置该字段必须 null。
终端设备不能使用 delegated。首个有效 ACK 原子建立不可变回执；精确重复返回
原回执，不同处置/结果冲突。后继绑定前驱键/结果/处置摘要和当前期望代数；只有
前驱持久关闭后可创建，不能删除未知 pending 或伪造 installed。

## 5 控制状态与凭据 CAS

持久保存意图/键/摘要、准入授权快照、状态和版本、预留目标代数、子步骤/outbox、
签名结果、处置和时间，再使对应效果对外可见。admitted→running→终态；不确定性
保留在原步骤/效果状态，不另造操作。准入通过持久 CAS 预留下一代数，同目标同代
只有一个变更；相同键/摘要复用原预留，其他键竞争已消费代数得到冲突。
同库签发凭据与回执原子提交，外部步骤先记 dispatch intent。worker 按存储版本
接管，旧 worker 不能覆盖新状态。COMMIT 断连是 unknown，不能推断回滚。失败
操作也不能静默重用已消费代数；对账和披露仍须当前权限。

## 6 issuer 到 Relay 的子操作权限

issuer 先持久父准入和子意图，再以自己的服务身份取得新 Relay challenge/PoP。
子键归服务 actor，subject_binding 是原目标设备。Relay 从受保护存储检查服务
活跃、domain/device/binding 的登记 issuer owner、目标长期授权活跃、当前精确
授权/资源 revision、允许的目标 scopes 和目标凭据 generation。actor/subject/
parent 同 domain，parent key 是原目标的 issuer 操作键及原摘要/步骤。
无关 issuer、普通设备、错误目标、已撤销主体、过期 revision 或扩大 scope 均拒绝。
这些是存储事实，不是调用者声明。

不要求父终态回执，否则循环依赖。受保护服务请求与已登记 issuer ownership 授权
受限子操作；parent 引用只作稳定关联和审计，不独立授予权限或证明父完成。

```text
child_context = {parent_key, parent_semantic_digest, target_service_id, step,
                 child_index, predecessor_disposition_digest}
child_operation_id = "child-" + H("ISCP-CHILD-OPERATION-V2\0" || C(child_context))
```

恢复步骤名为 relay.credentials.recover。初次 child_index="0"、前驱处置摘要为
null；已提交子结果只能取回，不能再次轮换。未知子结果阻止父完成/后继。
子结果签名关闭为 expired/superseded 后才增加持久 child_index，绑定前驱处置
摘要和当前目标代数，持久新子键后发送。父结果冻结前可这样建立子后继；父结果
冻结后嵌入凭据过期只能关闭父结果并创建关联父后继，不能修改旧父结果。
稳定意图不携旧 RelayProof。

## 7 共同权限锁与保留期

与双工线共用锁序：**writer epoch/scope → domain → device（按 ID 排序）→
owner → 唯一键（control operation/message 统一按 namespace、ID 排序）**。
缺层跳过，禁止先操作键再权限。权限读取可共享锁，rotate/revoke/takeover 独占
相同行；认证提交、准入、披露、双工发送/投递/查询与所有权切换全部参与。
双工线维护共同 helper/migration，认证线不能另造 advisory lock。
issuer 独立存储用同逻辑顺序与持久 CAS，不宣称跨服务单事务；网络调用在事务外。

跨服务撤销先在 issuer 持久 closing/新 revision，阻止父准入、完成和披露；稳定
原撤销操作/outbox 驱动 Relay。在共同锁内 Relay 持久 revoked/新 revision，
撤销所有 generation（包括刚先提交的子结果）、隔离 owner 并保留不可变撤销记录。
受保护成功响应或认证后精确查询该记录是持久 ACK。issuer 保存 ACK 后才标记
全局 effective/revoked。丢响应保持 closing 并重试原操作，失败不恢复权限。
子操作可先于 Relay 撤销提交，但父 closing 禁止披露，Relay 撤销使其失效；
晚到子操作在新 revision/status 下拒绝。缩权同样 fail-closed，所需执行点均确认
后才开放剩余权限，pending 不冒充全局撤销已完成。

结果正文至少保留完成后七天，且任何内含凭据仍可用时必须保留。未解决操作和
对账证据不清理。正文过期后保留终态、键/摘要、结果摘要、代数/有效期界限及
处置或待 ACK 元数据，返回 terminal/result_expired，不重执行生成结果。
命名空间仍准入时墓碑永久保留；删除去重历史前永久关闭 actor 命名空间、隔离
所有 writer 并保留关闭标记。恢复出不完整历史返回 unknown/closed，不从空表或
新 history_id 推断完整。

## 8 共同客户端 API 与代次

测试专用编译契约定义未来 iscpbridge 的 CredentialProvider/Binding/Lease/Event
及 Invalidate 类型。provider 管理加密持久化、安装 CAS 和原身份/domain/目标的
单飞；binding 包含 issuer/Relay/TLS pins。双工 owner 管理 WSS PoP、读写、
Relay owner generation 和本地 connection epoch。构造先验身份/pins，允许
access/refresh 均过期进入独立 HTTPS 恢复，但不得发布 data READY。

CredentialGeneration 是服务端凭据 CAS，RelayOwnerGeneration 是服务器 READY
所有权，ConnectionEpoch 是进程内旧回调围栏；三者强类型分离。Lease.ExpiresAt
为 access 和该传输所需权限的最早截止，不是 bundle 缓存有效期，也不延长任务。

Invalidate(binding,expected_generation,reason) 比较并标记指定租约无效，尚未到
TTL 也须使下次 EnsureAccess 对账/刷新，不能反复返回拒绝的 token。旧代数失效
事件忽略。原因仅 authentication_required/access_rejected/rotation_required，
不能断言撤销。经过验证的 provider 事件有 rotated/recovered/revoked/
identity_changed/scope_changed，携带 binding、凭据代数、授权 revision 与有序
StateVersion。旧 binding/状态版本不能覆盖撤销；只有权限未变的轮换允许原地
reauth，身份/范围变动隔离旧会话。

调用者 context 只取消自身等待。共享 flight 使用 provider 关闭 context 和 30 秒
有界尝试，写入检查当前 binding/generation/state CAS。无已验证状态时 Subscribe
等待第一份已验证租约/权限事件，不把普通恢复中报告成 revoked。订阅不阻塞恢复，
合并状态保留终态/失效优先级；使用租约时重新校验，旧对象本身不是权限。

## 9 评审与实现门槛

运行 Node 向量生成器及 `go test ./conformance -run AuthenticationRecoveryCandidate`。
Node 独立生成编码、Ed25519 和密封固定向量，Go 验证字节、摘要、签名、两次结果
重密封、格式负例、schema、委托主体及后继。另用 Draft2020-12 验证器检查 schema。
通过只证明候选资产一致，不证明服务恢复已实现。

发布前针对真实存储注入准入、子发送、签发提交、结果保存、安装、ACK 崩溃；
竞争轮换/撤销/接管，验证长断线、COMMIT 不明、历史缺口、独立构建和原生 UI。
业务清单必须实际验证未发送原意图、执行中附着、结果持久应用/ACK、未知副作用
及流快照恢复，不能只凭 recovery 标签宣布完成。

已接受勘误 0042：签名 `kid` 允许以 `-` 或 `_` 开头，因为现有 ISCP SHA-256 base64url 指纹可能使用这两种首字符。其他标识符规则不变。
