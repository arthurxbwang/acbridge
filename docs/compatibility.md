# 兼容性排查记录

本次修复前，本地 HEAD 为 `cd21a2ec67209ae7fc030e6be3e75e14a75c1bf8`；通过 `git ls-remote origin refs/heads/main` 确认当时远端 main 也是该提交。检查了仓库内全部六条历史提交，没有证据将本次问题归因于 AllinSSL 升级。

## 修复前证据和历史

| 确认的问题 | 修复前实现/观测 | 历史定位 |
| --- | --- | --- |
| 连接测试 404 | main 只注册 `/` 及四个 cert 路径，未知路径由 `handleHome` 返回纯文本 404 | 首次包含服务代码的 `875c905` 已缺失，不是后续删除 |
| 面板绑定缺失 | 没有 `/api/open/system` 路由或 cert_id 处理 | `875c905` 已缺失 |
| 配置更新失败及父对象覆盖风险 | `initializeCaddyCerts` 对现有 load_pem、certificates、tls、apps 均使用 PUT；真实 Caddy 2.10.2 对四级都返回 409 | `875c905` 已包含该实现 |
| 证书链覆盖 | `loadCertsFromDisk` 每遇到 CERTIFICATE 都对 certPEM 重新赋值，只留下最后一张 | `875c905` 已包含 |
| 63 位数字精度 | `getCertID` 返回 `FNV-1a & 0x7fffffffffffffff` | `466e8ed` 增加函数；`875c905` 仅存在调用，缺失定义，本身不能正常编译 |
| 不匹配证书先写缓存 | 上传只解析第一张证书元数据，随后写盘、修改缓存、调用 Caddy；没有 `tls.X509KeyPair` | `875c905` 已包含 |
| 成功被调用方误判 | POST 成功的 `msg` 为 `Certificate deployed and applied successfully` | `875c905` 已包含；与已核对的 AllinSSL 1.1.4 非空 msg 判错逻辑不兼容 |
| Token 输出 | 启动日志直接打印 Token，安装脚本也显示输入/生成值 | 本次同时移除；模板和安装脚本改用 0600 环境文件，避免 Token 放入启动参数 |

`cd21a2e` 的主要行为变更是从 HTTP 改为内存自签 HTTPS；上述缺陷已存在于更早实现。仓库历史不能证明用户过去部署使用的是哪个二进制、缓存内容或本地补丁，因此不能据此认定一次特定部署回归的完整来源。

## 核对的调用方协议

参考 [AllinSSL 1.1.4 safelinewaf.go](https://github.com/allinssl/allinssl/blob/1.1.4/backend/internal/cert/deploy/safelinewaf.go)：

- `SafeLineAPITest` GET `api/open/site/group`；返回对象经 `RequestSafeLineWaf` 解析，仅检查 `msg` 是否为空，不读取分组 data 的结构。因此返回合法空数组用于这个版本的连接测试，不宣称模拟完整 SafeLine 分组 API。
- `RequestSafeLineWaf` 将 JSON 解码为 `map[string]any`，直接断言 `msg` 为字符串；非空即失败。
- `uploadSafeLineCert` 要求 `data` 为 float64 数字。
- `DeploySafeLineWaf` POST `api/open/cert` 后以 `cert_id` PUT `api/open/system`。
- 同文件中的站点、认证中心部署还需其他 API；本桥接不支持，README 已修正原来的宽泛说明。

不以固定成功响应掩盖部署失败：连接测试的范围仅限 API 可达性和鉴权；上传和绑定均检查真实同步结果。

## 验证与边界

`bridge_test.go` 包含协议、缓存迁移、失败状态、精度往返、完整链及 Caddy 集成用例。真实 Caddy 2.10.2 用例验证条件写入可用、每级缺失节点初始化、已有空列表、续期替换、恢复后完整 TLS 链和预期叶子 DER，以及原 HTTP 路由和其他 TLS 配置。

ETag 冲突、Caddy HTTP 拒绝和不泄露错误正文通过受控 Admin 模拟服务验证；没有声称对用户服务器、AllinSSL 控制台或其生产域名进行远程操作。外部防火墙及实际凭据配置不在这些回归测试中。旧 ID 与缓存的迁移限制、单实例缓存目录约束和失败后的期望状态重试语义见 README。
