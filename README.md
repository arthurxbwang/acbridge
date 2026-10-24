# acbridge

acbridge 将 AllinSSL 的雷池 WAF 面板证书部署请求转换为 Caddy Admin API 配置更新。证书先保存到本地缓存，再热加载至 Caddy，无需 SSH 或重启 Caddy。缓存包含私钥，并非“零磁盘写入”。

## 兼容范围

- 已核对 [AllinSSL 1.1.4 的 safelinewaf.go](https://github.com/allinssl/allinssl/blob/1.1.4/backend/internal/cert/deploy/safelinewaf.go)，支持授权 API 的连接测试及 **雷池 WAF 面板**部署（上传证书后绑定 `cert_id`）。
- 不模拟 WAF 站点、应用或认证中心；AllinSSL 的“站点部署”和“认证中心部署”需要 `/api/open/site`、`/api/open/portal` 等接口，目前不支持。不要按旧说明随意填写网站占位符。
- 已以 **Caddy 2.10.2** 的真实进程验证。其他版本需提供相同的 JSON 配置、证书 `tags`、ETag/If-Match 条件写入语义，并运行集成测试；未宣称所有 Caddy 2.x 版本兼容。
- Go 模块要求 Go 1.20+；本次验证使用 Go 1.27.3。没有第三方 Go 依赖。

## 编译和启动

```bash
go build -o acbridge .
go vet ./...
go test ./...
```

Caddy 默认 Admin 地址为 `http://127.0.0.1:2019`。桥接程序需要读取 `/config/` 并更新 TLS 证书配置的权限。Admin API 应仅在受信任网络可达。

通过部署平台安全注入 `ACBRIDGE_TOKEN`，然后启动：

```bash
# 先安全设置 ACBRIDGE_TOKEN；不要将真实凭据写进命令历史、文档或日志。
./acbridge -addr 127.0.0.1:9443 \
  -caddy http://127.0.0.1:2019 \
  -cert-dir /var/lib/acbridge/certs -sync-interval 30
```

`ACBRIDGE_TOKEN` 优先于 `-token`。为兼容旧版本仍保留默认 Token；实际部署必须提供自己的强 Token。程序不输出 Token、私钥或 Caddy 错误响应原文。`-sync-interval` 必须为正整数秒。

服务监听 **HTTPS**，启动时生成的自签证书没有主机名 SAN，且每次重启更换。建议在前面配置有受信任证书的 HTTPS 入口；AllinSSL 的 URL 必须使用可访问的 HTTPS 地址。直接连接自签入口时，AllinSSL 1.1.4 需显式配置其 `ignore_ssl` 选项，这仅影响客户端到桥接入口的认证，不代表 Caddy 上的业务证书已经部署成功。开发集成测试则使用测试 CA 完整验证业务 TLS 握手。

使用 systemd 模板时，将二进制放在 `/opt/acbridge/acbridge`，在 `/opt/acbridge/acbridge.env` 中安全写入 `ACBRIDGE_TOKEN` 的值并设置权限 `0600`。模板现在使用 `EnvironmentFile`，不再将 Token 放进 `ExecStart` 参数。升级已有服务也需更新 unit，执行 `systemctl daemon-reload` 后重启。安装脚本隐藏 Token 输入及输出，随机生成的值保存在该环境文件中，请通过安全渠道填写至 AllinSSL。

## API 协议

除健康页 `/` 外，下列接口均校验 `X-SLCE-API-TOKEN`。成功必须包含空字符串 `err` 和 `msg`，因为 AllinSSL 1.1.4 将任何非空 `msg` 视为错误，即使 HTTP 状态为 200。

| 请求 | 含义 | 成功的 `data` |
| --- | --- | --- |
| `GET /api/open/site/group` | 测试鉴权及 API 可达性；没有 WAF 分组 | `[]` |
| `GET /api/open/cert` | 列出缓存的证书元数据 | `{"nodes":[],"total":0}` |
| `POST /api/open/cert` | 校验、持久化并同步完整证书链 | 可精确往返的数字 ID |
| `PUT /api/open/system` | 校验 `cert_id` 存在，并再次确认 Caddy 同步成功 | `{"cert_id":123}` |
| `DELETE /api/open/cert/{id}` | 持久化删除并同步 | `null` |

证书接口保留 `/open/cert` 及带尾斜线的旧路径。连接测试与绑定接口不接受其他 HTTP 方法，返回 405 JSON；缺失或错误 Token 返回 401 JSON。

上传请求：

```json
{"type":2,"manual":{"crt":"<叶子证书 PEM + 按顺序排列的中间证书 PEM>","key":"<对应私钥 PEM>"}}
```

成功示例：`{"data":123,"err":"","msg":""}`。随后绑定 `{"cert_id":123}`。ID 必须为正的整数 JSON 数字；缺失、字符串、零、负数、小数、超范围请求返回 400，不存在或歧义 ID 返回 404。上传可携带已有 `id` 作为更新提示；未知提示返回 404，返回值始终是证书内容导出的新 ID，不承诺续期后保持原 ID。

连接测试只验证该 API 和 Token；它不会绕过 Caddy 同步，也不能证明证书已部署。POST 和 PUT 都只有同步成功才返回成功。Caddy 失败返回 502、`caddy_sync_failed` 和不包含凭据的操作路径/HTTP 状态说明。

## Caddy 配置及并发

同步仅管理 `apps.tls.certificates.load_pem` 中带 `acbridge` 标签的条目；该标签由桥接程序保留。已有无标签且证书内容完全相同的旧条目会被接管。其他有标签条目及不同证书条目保留。未知的旧无标签条目不会自动删除，升级时应检查是否存在已经脱离缓存的旧证书，避免同域名重复证书影响选择。

存在的 `load_pem` 使用 **PATCH** 替换；缺失节点使用 **PUT** 创建最近的缺失子树，不覆盖已存在的父对象。HTTP 路由、TLS automation、其他加载器及其他应用保持不变。

每次先 GET `/config/` 取得 ETag，再用 If-Match 条件写入。412/409 会重新读取并有限重试，持续冲突返回失败；服务内部的上传、删除、绑定及周期同步串行执行。缺少 ETag 时拒绝不受保护的写入。一个缓存目录只应由一个 acbridge 实例写入。

Caddy 错误原文可能包含输入 PEM，程序不会透传；保留方法、路径、HTTP 状态并要求在受控环境中检查 Caddy 诊断信息。

## 缓存、ID 和升级

上传和恢复均先解析全部证书、校验链顺序和中间签名，再以 `tls.X509KeyPair` 校验叶子证书与私钥。元数据来自第一张叶子证书，PEM 规范化时保留链顺序。此校验不替代客户端的信任根、域名和有效期验证。

数字 ID 为规范化完整证书链的 SHA-256 截断值，范围为 `1..2^53-1`（零映射为 1）。同一证书链的换行格式变化和重启不改变 ID；续期或证书链变化会改变 ID。截断哈希存在理论碰撞，若与已缓存的不同证书冲突，返回 409，保留原缓存，不静默覆盖。

没有新快照时，会读取旧的 `*.pem` 组合缓存，完整保留各个 CERTIFICATE 块及私钥；损坏缓存会导致启动明确失败，避免把空状态同步到 Caddy。首次持久化上传或删除后，整个期望缓存通过临时文件、文件同步和原子重命名保存到 `-cert-dir/.acbridge-cache.json`（0600），此后仅以该快照为准。旧 `.pem/.crt/.key` 不删除、不再更新，也不会在删除或续期后复活。它们可能含旧私钥，确认迁移并备份后应按部署策略清理。不要删除权威快照来“刷新”缓存。旧程序不读取新快照，不能直接回退并复用旧 PEM 目录；回退前应将当前完整证书链和私钥安全导出到干净目录，或重新部署证书，避免恢复过期缓存。

可识别缓存中证书的旧 FNV 63 位 ID，以及唯一匹配的 float64 舍入形式；有歧义返回失败。旧原始 PEM 格式信息若已丢失，旧 ID 不一定能重建；接近 int64 上界、舍入后越界的旧 ID 也不能保证兼容。升级后建议重新上传，并用本次返回的新 ID 绑定，不要继续保存旧数字配置。

无效上传在写盘和修改内存之前被拒绝；磁盘写入失败也不修改内存。有效上传先持久化期望状态，再更新内存并尝试同步：若 Caddy 拒绝，返回失败，但保留新期望状态，周期同步、重复上传或再次 PUT 绑定均可重试。因此 POST 失败不等于缓存没有变化；Caddy 中最后成功的配置可能仍在生效。本地快照与远端 Caddy 不是跨服务原子事务，必须以 API 成功及真实 TLS 握手确认效果。任何与新证书域名重叠的旧缓存证书会整体被替换，包括它原先覆盖的其他域名。

## 端到端验证

```bash
# 普通回归测试，不需要外部服务
go test -race -count=1 ./...

# 必须明确提供真实 Caddy，避免集成用例被跳过
CADDY_BIN=/absolute/path/to/caddy go test -race -count=1 -v ./...
```

集成测试自行生成测试 CA、叶子证书和中间证书，在临时端口启动真实 Caddy，执行上传→JSON float64 往返→PUT 绑定，验证握手链、叶子证书 DER、续期后证书、缓存恢复，以及 HTTP 路由和其他 TLS 配置。还对每一级缺失配置节点进行真实初始化。Token 错误、无效请求、私钥不匹配、碰撞、磁盘失败、并发 ETag 冲突及 Caddy 拒绝配置由回归测试覆盖；无 CADDY_BIN 时真实 Caddy 用例明确标记为 skipped。

部署后的人工验收：

1. 用相同 Token 执行 AllinSSL“测试连接”，再选择“雷池 WAF 面板”部署。
2. 确认 POST 与 PUT 都没有非空 `msg`，不要只看连接测试结果。
3. 从目标客户端用业务域名作 SNI 握手并核对叶子证书指纹，例如：

```bash
# 必要时以 -CAfile 指定受信任的内部 CA。不要将私钥内容用于诊断输出。
openssl s_client -connect server.example:443 -servername app.example \
  -verify_hostname app.example -verify_return_error </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
openssl x509 -in fullchain.pem -noout -fingerprint -sha256
```

4. 重启 acbridge、重新握手，再重启测试 Caddy 验证周期恢复。Caddy 没有证书的启动窗口可能导致握手失败，应等待桥接同步成功后重试。

历史问题及引入证据见 [兼容性排查记录](docs/compatibility.md)。防火墙来源配置错误及配置里误存字面量 `[REDACTED]` 属于部署问题，与代码修复分开处理。
