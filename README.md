# acbridge
这是一个极简且优雅的 API 桥接服务。它巧妙地对外伪装成“长亭雷池 (SafeLine) WAF”，拦截来自 AllinSSL 的证书推送请求，并将其无缝转化为 Caddy 原生 Admin API 的内存级配置注入。  借助本方案，你可以让 AllinSSL 走现成的雷池部署通道，在不暴露服务器 SSH 密码、不修改文件权限、不重启 Caddy 服务的前提下，实现 Caddy SSL 证书的纯内存自动热更新。
