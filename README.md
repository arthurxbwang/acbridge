# acbridge

acbridge 将 AllinSSL 的雷池 WAF 面板证书部署请求转换为 Caddy Admin API 配置更新。证书先保存到本地缓存，再热加载至 Caddy，无需 SSH 或重启 Caddy。缓存包含私钥，并非“零磁盘写入”。

## 兼容范围

- 已核对 [AllinSSL 1.1.4 的 safelinewaf.go](https://github.com/allinssl/allinssl/blob/1.1.4/backend/internal/cert/deploy/safelinewaf.go)，支持授权 API 的连接测试及 **雷池 WAF 面板**部署（上传证书后绑定 `cert_id`）。
- 不模拟 WAF 站点、应用或认证中心；AllinSSL 的“站点部署”和“认证中心部署”需要 `/api/open/site`、`/api/open/portal` 等接口，目前不支持。不要按旧说明随意填写网站占位符。
- 已以 **Caddy 2.10.2** 的真实进程验证。其他版本需提供相同的 JSON 配置、证书 `tags`、ETag/If-Match 条件写入语义，并运行集成测试；未宣称所有 Caddy 2.x 版本兼容。
- Go 模块要求 Go 1.20+；本次验证使用 Go 1.27.3。没有第三方 Go 依赖。

## 安装、接入与升级

推荐拓扑：AllinSSL → 可信 HTTPS 域名 → Caddy 反向代理 → 本机 acbridge HTTP → Caddy Admin API。这里借用 AllinSSL 的“雷池 WAF 面板”部署通道，实际证书仍供 Caddy 的业务域名使用。

前提：Linux + systemd，已有 Caddy 2.10.2 且开启 Admin API。源代码安装需要 Git、Go 1.20+；安装器也需要 curl、Python 3。先从希望部署的分支或版本取得本仓库，在仓库目录执行：

```bash
# 开发分支验收；分支须已推送到 GitHub 才能远端拉取
sudo bash install.sh --ref feat/deployment-hardening
# 正式使用时指定已发布版本；校验 SHA256SUMS 后安装
# sudo bash install.sh --version vX.Y.Z
```

安装器默认使用 `127.0.0.1:9443` 的 HTTP 代理模式，以独立 `acbridge` 用户运行。首次生成随机 Token；升级沿用已有 Token、端口、Caddy 地址和缓存目录。需要无人值守时加 `--yes`；所有选项见 `bash install.sh --help`。实际 Token 保存在安装目录的 `acbridge.env` 中，权限 `0600`，请通过安全渠道填写至 AllinSSL。明确加 `--rotate-token` 才会轮换 Token，并需同步更新 AllinSSL。

安装目录和证书缓存目录应使用 `/opt/acbridge`、`/var/lib/acbridge/certs` 等专用路径；systemd 沙箱隐藏 `/home`、`/root`、`/run/user`、`/tmp`、`/var/tmp`，安装器会拒绝这些目录及解析符号链接后落入其中的路径。

安装器验证 Caddy Admin API 和带鉴权的 `/readyz`，服务启动或就绪检查失败会回滚程序及配置并返回非零状态。证书缓存不会作为程序回滚的一部分被覆盖。旧版端口、Token 和缓存目录可以迁移，但原自签 HTTPS 入口需要明确选择 `--mode proxy` 或提供可信证书的 `--mode tls`，不会静默切换传输方式。首次迁移须同步核对 AllinSSL 中的 HTTPS 地址。

为桥接入口配置独立域名，例如在已有 Caddyfile 中添加：

```caddy
bridge.example.com {
    reverse_proxy 127.0.0.1:9443
}
```

替换为自己的域名，正确设置 DNS 并允许 Caddy 完成 HTTPS 签发。用 `caddy validate --config /etc/caddy/Caddyfile` 检查，然后通过原有服务方式 reload。入口证书建议交给 Caddy 独立管理，避免入口首次签发依赖尚未接通的 AllinSSL。安装器不会自动覆盖已有 Caddyfile。代理模式只适合同一网络命名空间；容器部署需另行配置可信网络及 HTTPS。

在 AllinSSL 的授权 API 中选择雷池，地址填 `https://bridge.example.com`，填入 Token 后测试连接。证书自动部署目标选择 **雷池 WAF 面板**。先完成一次真实部署，并从业务域名验证返回证书；连接测试仅证明入口和鉴权正常。

如果已有可信证书，也可以让 acbridge 直接监听 HTTPS：

```bash
sudo bash install.sh --mode tls --bind 0.0.0.0 --port 9443 \
  --tls-cert /absolute/path/fullchain.pem --tls-key /absolute/path/privkey.pem \
  --tls-server-name bridge.example.com \
  --ref feat/deployment-hardening
```

安装器把证书复制到受限目录供服务用户读取；使用私有 CA 时还需 `--tls-ca /absolute/path/ca.pem`，让本机就绪检查验证信任链。入口证书更新后需重新提供新文件运行安装器，再重启 acbridge；业务证书更新仍通过 Caddy 热加载。

## 手工启动与开发

```bash
go build -o acbridge .
go vet ./...
go test ./...
# 先通过安全方式注入 ACBRIDGE_TOKEN
./acbridge -http -addr 127.0.0.1:9443 \
  -caddy http://127.0.0.1:2019 -cert-dir ./certs -sync-interval 30
./acbridge -version
```

没有 Token 或使用旧公开默认 Token 会拒绝启动。`ACBRIDGE_TOKEN` 优先于兼容参数 `-token`；不要把实际凭据放入命令行。HTTP 只允许监听明确的 loopback IP。直接 HTTPS 必须同时提供 `-tls-cert` 和 `-tls-key`；只有本地开发可明确使用 `-dev-self-signed`，不能作为可信生产入口。

默认同步周期为 30 秒，可设为 1～86400 秒。Caddy Admin API 默认 `http://127.0.0.1:2019`，必须只对受信任客户端开放。服务收到 SIGTERM/SIGINT 后会等待在途请求退出。

## 运行状态与排障

- `/`：公开存活检查，仅返回最小状态，不公开域名或证书信息。
- `/readyz`：需要 `X-SLCE-API-TOKEN`；最近同步成功且未过期返回 200，未同步或同步失败返回 503。
- `/status`：同样需要鉴权，返回就绪状态、最近尝试/成功时间、同步错误及缓存数量。适合定时监控；同步成功表示 Admin 配置已同步，业务路由仍需真实 TLS 握手验收。
- `journalctl -u acbridge -n 100 --no-pager`：检查服务日志；不输出 Token、私钥或 Caddy 原始错误正文。

常见失败：401 检查 Token；503 检查 Caddy 地址与日志；证书验证失败检查入口域名、完整链和信任根；上传 409 检查是否会减少原证书的域名覆盖范围。备份整个证书缓存目录及环境文件，备份含私钥，须限制访问。卸载服务前先停止并禁用 `acbridge.service`，按需保留备份和缓存，不要通过删除快照来“刷新”证书。

## API 协议

除健康页 `/` 外，下列接口均校验 `X-SLCE-API-TOKEN`。成功必须包含空字符串 `err` 和 `msg`，因为 AllinSSL 1.1.4 将任何非空 `msg` 视为错误，即使 HTTP 状态为 200。

| 请求 | 含义 | 成功的 `data` |
| --- | --- | --- |
| `GET /api/open/site/group` | 测试鉴权及 API 可达性；没有 WAF 分组 | `[]` |
| `GET /api/open/cert` | 列出缓存的证书元数据 | `{"nodes":[],"total":0}` |
| `POST /api/open/cert` | 校验、持久化并同步完整证书链 | 可精确往返的数字 ID |
| `PUT /api/open/system` | 校验 `cert_id` 存在，并再次确认 Caddy 同步成功 | `{"cert_id":123}` |
| `DELETE /api/open/cert/{id}` | 持久化删除并同步 | `null` |

列表的 `trusted:false` 与 `trust_status:"not_verified"` 表示桥接未执行客户端信任验证；`self_signature` 根据叶子签名判断。

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

每次先 GET `/config/` 取得 ETag，再用 If-Match 条件写入。412/409 会重新读取并有限重试，持续冲突返回失败；服务内部的上传、删除、绑定及周期同步串行执行。缺少 ETag 时拒绝不受保护的写入。一个缓存目录只应由一个 acbridge 实例写入；同一个 Caddy 也只能连接一个 acbridge 实例，因为托管标签固定为 `acbridge`。

Caddy 错误原文可能包含输入 PEM，程序不会透传；保留方法、路径、HTTP 状态并要求在受控环境中检查 Caddy 诊断信息。

## 缓存、ID 和升级

上传和恢复均先解析全部证书、校验链顺序和中间签名，再以 `tls.X509KeyPair` 校验叶子证书与私钥。元数据来自第一张叶子证书，PEM 规范化时保留链顺序。新上传还检查叶子及中间证书的有效期，过期或尚未生效时拒绝写入。恢复已有缓存允许过期证书，以便服务能够启动并接收续期。以上检查不替代客户端信任根和域名验证。

数字 ID 为规范化完整证书链的 SHA-256 截断值，范围为 `1..2^53-1`（零映射为 1）。同一证书链的换行格式变化和重启不改变 ID；续期或证书链变化会改变 ID。截断哈希存在理论碰撞，若与已缓存的不同证书冲突，返回 409，保留原缓存，不静默覆盖。

没有新快照时，会读取旧的 `*.pem` 组合缓存，完整保留各个 CERTIFICATE 块及私钥；损坏缓存会导致启动明确失败，避免把空状态同步到 Caddy。首次持久化上传或删除后，整个期望缓存通过临时文件、文件同步和原子重命名保存到 `-cert-dir/.acbridge-cache.json`（0600），此后仅以该快照为准。旧 `.pem/.crt/.key` 不删除、不再更新，也不会在删除或续期后复活。它们可能含旧私钥，确认迁移并备份后应按部署策略清理。不要删除权威快照来“刷新”缓存。旧程序不读取新快照，不能直接回退并复用旧 PEM 目录；回退前应将当前完整证书链和私钥安全导出到干净目录，或重新部署证书，避免恢复过期缓存。

可识别缓存中证书的旧 FNV 63 位 ID，以及唯一匹配的 float64 舍入形式；有歧义返回失败。旧原始 PEM 格式信息若已丢失，旧 ID 不一定能重建；接近 int64 上界、舍入后越界的旧 ID 也不能保证兼容。升级后建议重新上传，并用本次返回的新 ID 绑定，不要继续保存旧数字配置。

无效上传在写盘和修改内存之前被拒绝；磁盘写入失败也不修改内存。有效上传先持久化期望状态，再更新内存并尝试同步：若 Caddy 拒绝，返回失败，但保留新期望状态，周期同步、重复上传或再次 PUT 绑定均可重试。因此 POST 失败不等于缓存没有变化；Caddy 中最后成功的配置可能仍在生效。本地快照与远端 Caddy 不是跨服务原子事务，必须以 API 成功及真实 TLS 握手确认效果。新上传若与旧证书域名重叠，必须完整覆盖被替换旧证书的域名，否则返回 409 并保留原状态。例如旧证书覆盖 A、B，新证书只覆盖 A 时会被拒绝；应签发包含 A、B 的证书。确需拆分域名时，请规划维护窗口及完整迁移顺序，避免直接删除旧证书造成覆盖缺口。

## 测试与发布

CI 覆盖最低 Go 版本和稳定版，运行竞态、真实 Caddy TLS、程序启动与安装器模拟测试。推送版本标签可构建 Linux amd64/arm64 压缩包和 SHA256SUMS；发布本身需要维护者操作。安装器模拟测试不会改动宿主机 systemd。

### 端到端验证

```bash
# 普通回归测试，不需要外部服务
go test -race -count=1 ./...

# 必须明确提供真实 Caddy，避免集成用例被跳过
CADDY_BIN=/absolute/path/to/caddy go test -race -count=1 -v ./...
bash scripts/test-install.sh
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
