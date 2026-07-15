这是一个极简且优雅的 API 桥接服务。它巧妙地对外伪装成“长亭雷池 (SafeLine) WAF”，拦截来自 AllinSSL 的证书推送请求，并将其无缝转化为 Caddy 原生 Admin API 的内存级配置注入。

借助本方案，你可以让 AllinSSL 走现成的雷池部署通道，在不暴露服务器 SSH 密码、不修改文件权限、不重启 Caddy 服务的前提下，实现 Caddy SSL 证书的纯内存自动热更新。

✨ 核心痛点与解决思路
在传统的自动化部署中，第三方证书管理平台（如 AllinSSL）为 Caddy 部署证书通常面临两难：

给 SSH 权限？ 安全风险极高，且频繁的磁盘读写和覆盖操作不够优雅。

写定制化插件？ 侵入性太强，需要重新编译 Caddy，维护成本极高。

我们的解法：移花接木
AllinSSL 已经原生支持推送证书给“雷池 WAF”。我们只需编写一个轻量级的中间层，模拟雷池的 API 鉴权与报文格式。AllinSSL 以为自己把证书推给了雷池，实际上桥接服务在接收到证书后，转身通过 HTTP PUT 直接打入了 Caddy 的配置树（Config Tree）中。

🚀 核心优势
🛡️ 绝对的安全隔离 (Zero SSH & Passwordless)
无需在 AllinSSL 中填写服务器的 Root 账号密码，也无需开放 SSH 端口。一切交互均通过携带自定义 Token 的 HTTP API 完成，权限被死死限制在“仅能更新证书”。

⚡ 纯内存注入 (Zero Disk I/O)
告别传统的 .crt 和 .key 实体文件替换。证书数据以 JSON 格式直接写入 Caddy 内存，不在磁盘留下任何冗余文件，极致干净。

🔄 无感热更新 (Zero Downtime)
得益于 Caddy 强大的 Admin API，证书配置在注入瞬间即刻生效。整个过程完全不需要 systemctl restart caddy，旧连接不断开，新连接直接握手新证书。

🔌 零侵入性 (Zero Intrusion)
不需要为 Caddy 挂载任何第三方模块，也不需要修改当前的 Caddyfile 核心代理逻辑。只需 Caddy 开放默认的 :2019 本地管理端口即可。

⚙️ 它是如何工作的？
触发推送：AllinSSL 自动完成域名验证与证书签发。

伪装接收：AllinSSL 按照“雷池 WAF”的格式发起 POST 请求，桥接服务验证 X-SLCE-API-TOKEN。

格式转换：桥接服务剥离雷池格式外壳，提取 cert 和 key 纯文本。

内存重载：桥接服务向 Caddy 本地 Admin API (/config/apps/tls/...) 发起请求，Caddy 即刻接管并应用新证书。

💡 适用场景
极其适合对服务器权限管理严格、追求基础设施干净整洁，且希望完全自动化 SSL 续签周期的现代化运维架构。

---

## 🛠️ 快速上手与部署指南

### 1. 编译 `acbridge`
由于目标服务器通常是 Linux，你可以在本地（需要 Go 环境）交叉编译出适用于目标服务器的无依赖二进制文件：

```bash
# 编译为 Linux 64位 (常见 VPS/服务器)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o acbridge

# 编译为 Linux ARM64位 (如甲骨文 ARM、树莓派等)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o acbridge
```

### 2. 服务器部署
将编译好的 `acbridge` 二进制文件上传到目标服务器的 `/opt/acbridge/` 目录中：

```bash
# 创建部署目录并拷贝二进制
mkdir -p /opt/acbridge
mv acbridge /opt/acbridge/
chmod +x /opt/acbridge/acbridge

# 创建证书磁盘缓存目录（用于持久化备份，防 Caddy 重启丢失）
mkdir -p /var/lib/acbridge/certs
```

### 3. 配置 Systemd 自定启服务
使用项目中的 `acbridge.service` 模板进行部署：

1. 将 `acbridge.service` 拷贝到服务器的 `/etc/systemd/system/acbridge.service`。
2. 编辑该文件，修改 `-token YOUR_SECRET_TOKEN` 为你的自定义强口令 Token。
3. 启动并启用服务：

```bash
systemctl daemon-reload
systemctl enable --now acbridge
```

### 4. 检查服务状态
```bash
# 查看服务是否正常运行
systemctl status acbridge

# 访问本地健康检查接口（若在服务器上）
curl http://127.0.0.1:9443/
```

---

## ⚙️ Caddy 配置说明

由于本方案采用**纯内存级注入**，你的 `Caddyfile` 保持最标准的反代配置即可，**不需要**在 Caddyfile 中指定 `tls /path/to/cert` 等指令：

```caddy
# Caddyfile 示例
example.com {
    # 你的核心反代或静态服务逻辑
    reverse_proxy localhost:8080
}
```

*当客户端通过 HTTPS 请求 `example.com` 时，Caddy 的 SSL 握手引擎会优先在内存配置树中检索已加载的证书，检索到 `acbridge` 注入的证书后即可成功握手，从而避免了向 Let's Encrypt 申请证书的动作。*

> [!IMPORTANT]
> **关于 Caddy Admin API**
> `acbridge` 依赖 Caddy 的本地 Admin API（默认监听 `http://127.0.0.1:2019`）。请确保你的 Caddy 开启了此接口（默认是开启的）。如果 Caddy 运行在 Docker 容器中，请确保 `acbridge` 可以通过网络访问到 Caddy 的管理端口，并在启动 `acbridge` 时通过 `-caddy` 参数指定正确的 URL。

---

## 🔗 AllinSSL 联动配置步骤

在 AllinSSL 控制台中，你只需将本服务添加为 **“雷池 WAF”** 即可，不需要做任何定制开发：

1. **进入 AllinSSL 仪表盘**：选择“授权 API 管理” -> “添加授权 API”。
2. **选择类型**：下拉菜单选择 **“雷池”** (SafeLine)。
3. **WAF 访问地址**：填入部署了 `acbridge` 的服务器地址，例如 `http://<服务器IP>:9443`。
4. **API Token**：填入你在 `acbridge.service` 中配置的 Token。
5. **部署任务配置**：
   * 在 AllinSSL 中创建证书自动申请任务。
   * 添加“自动部署”步骤，部署目标选择上面创建的“雷池 WAF”实例。
   * “应用名称”或“网站”随便填一个占位符即可（`acbridge` 会直接解析证书内的域名并注入，不依赖 AllinSSL 传递的关联网站字段）。
6. **测试与运行**：点击 AllinSSL 的“测试连接”或“立即部署”，即可在 `acbridge` 日志中看到证书接收、解析、持久化备份并完美注入 Caddy 内存的日志！

