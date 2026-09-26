# rgate 需求文档

> 本文档由项目演进过程中的用户需求归纳整理而成，描述 rgate（Rust 实现的轻量级反向代理 / 静态文件网关）的完整需求。

## 1. 项目概述

rgate 是一个单二进制的 HTTP/HTTPS 网关，功能包括：

- 静态文件服务（按虚拟主机区分 webroot）
- 按路径前缀的反向代理（支持 WebSocket 升级）
- 多虚拟主机（vhost）路由，按 Host 头 / SNI 匹配
- HTTPS 支持，含按 SNI 选择每主机证书
- 明文 HTTP 请求自动重定向到 HTTPS

## 2. 需求演进

### 需求 R1：全量英文化

**需求内容**：项目中所有文字（注释、日志、错误信息、页面内容）改为英文。

**验收标准**：
- 所有源码注释、`eprintln!`/`println!` 日志、`anyhow` 错误信息均为英文
- `www/index.html` 页面文字为英文，`lang` 属性为 `en`
- 编译通过，功能不受影响

### 需求 R2：双端口配置与 HTTP→HTTPS 自动跳转

**需求内容**：配置文件使用两个端口号：
- `httpPort`：HTTP 服务器监听端口（必填）
- `httpsPort`：HTTPS 服务器监听端口（可选）
  - **未配置**：不启用 HTTPS 服务器，HTTP 上正常提供静态文件与代理服务
  - **已配置**：启用 HTTPS 服务器，并将**所有** HTTP 请求自动转发（301 重定向）到 HTTPS 服务器

**验收标准**：
- 无 `httpsPort` 时：仅启动 HTTP 监听，请求正常处理，无重定向
- 有 `httpsPort` 时：
  - HTTP 请求一律返回 `301 Moved Permanently`，`Location` 指向对应的 `https://<host>[:port]<path+query>`
  - 端口为 443 时 Location 中省略端口；主机名支持 IPv6 字面量；无 Host 头返回 400
- `httpsPort` 已配置但缺少证书配置时，启动报错

### 需求 R3：配置改为 XML 并支持多虚拟主机

**需求内容**：配置文件由 `config.json` 改为 `config.xml`，配置项结构重构为多站点方案：

```xml
<web>
    <ports http="80" https="443"/>
    <host>
        <name value="test.yunp.top"/>
        <ssl cert="certs/test.yunp.top.pem" key="certs/test.yunp.top.key"/>
        <webroot value="www"/>
        <proxy path="/web" target="http://127.0.0.1:9081/web"/>
    </host>
    <host>
        <name value="yunp.top"/>
        <name value="www.yunp.top"/>
        <ssl cert="certs/yunp.top.pem" key="certs/yunp.top.key"/>
        <webroot value="www"/>
        <proxy path="/web" target="http://127.0.0.1:9082/web"/>
    </host>
</web>
```

**功能要求**：
- **全局端口**：`<ports>` 的 `http` 属性必填；`https` 属性可选，语义同 R2
- **虚拟主机**：每个 `<host>` 支持多个 `<name>`（域名）、独立 `<ssl>`（证书 + 私钥）、`<webroot>`（缺省 `www`）、多条 `<proxy>` 规则
- **请求路由**：按请求的 `Host` 头（去端口、忽略大小写）匹配虚拟主机，使用该 host 的 webroot 与代理规则；无匹配时回落到第一个 host
- **证书选择**：TLS 握手按 SNI 为每个虚拟主机选择对应证书，同一 host 的多个域名共用其证书；未知 SNI 名称在握手阶段拒绝
- 代理语义（前缀匹配、最长前缀优先、WebSocket 升级、逐跳头剥离、`x-forwarded-for`/`x-forwarded-proto` 注入等）保持不变

**验收标准**：
- 解析 config.xml 并通过校验：必须存在 `<host>`、每个 host 至少一个 `<name>`、启用 https 时每个 host 必须有 `<ssl>`
- 不同 Host 头的请求路由到各自的 webroot 与上游
- 不同 SNI 名称在握手中出示各自 host 的证书
- R2 的 HTTP→HTTPS 重定向行为在多 host 下继续生效

## 3. 既有基础功能（需求演进过程中保持不变）

以下功能在历次重构中均要求保持：

| 功能 | 说明 |
| --- | --- |
| 静态文件服务 | URL 路径百分号解码、按扩展名推断 MIME、目录请求回落 `index.html`、仅允许 GET/HEAD、HEAD 返回空 body |
| 目录穿越防护 | 丢弃空段与 `.`，拒绝 `..`（403） |
| 前缀代理 | `/web` 命中 `/web` 与 `/web/**`，不命中 `/webfoo`；最长前缀优先 |
| 上游目标 | 支持 `http://` 与 `https://`（上游 TLS 含内置根证书）；上游路径前缀拼接 |
| WebSocket | 透传 `Connection`/`Upgrade` 头，101 响应后双向转发字节流 |
| 转发头处理 | 剥离逐跳头；注入 `x-forwarded-for`、`x-forwarded-proto`；Host 改写为上游 authority |
| 错误处理 | 上游不可达等错误返回 502；文件不存在 404；方法不允许 405 |

## 4. 非功能需求

- **技术栈**：Rust + tokio + hyper（HTTP/1.1）+ rustls（ring 后端，ALPN 限定 http/1.1）
- **运行方式**：`rgate [config.xml]`，缺省读取当前目录 `config.xml`；Ctrl-C 优雅退出
- **可观测性**：启动时打印监听地址、每个虚拟主机（域名、webroot、代理规则数）；每条请求打印一行访问日志；错误输出到 stderr
- **国际化**：全部输出与注释为英文（R1）
