# anno

内网穿透 / 端口转发。包含 Rust 服务端、Rust 客户端和 React 管理 Web UI。

## 组件


| 组件          | 说明                            |
| ----------- | ----------------------------- |
| `anno-server` | 控制面 + 公网监听 + HTTP 管理 API      |
| `anno-client` | 连接服务端，TCP/UDP 转发，可选本地 HTTP 代理 |
| `common`    | 二进制帧协议                        |
| `frontend`  | React + Ant Design 管理界面（Vite） |


---

## 快速启动

### 1. 准备服务端配置

在服务端工作目录创建 `.env` 文件，配置管理后台登录密码（bcrypt hash）：

```bash
# 生成 bcrypt hash（需要安装 apache2-utils）
htpasswd -bnBC 10 "" yourpassword | tr -d ':\n' | sed 's/$2y/$2b/'
```

`.env` 文件示例：

```env
ADMIN_PASSWORD_HASH=$2b$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2. 启动服务端

```bash
anno-server \
  --control 0.0.0.0:9000 \
  --api 0.0.0.0:8080 \
  --registry-file /etc/anno/clients.json
```

### 3. 在 Web 后台创建客户端条目

访问 `http://<server>:8080`，使用 `.env` 中配置的密码登录，进入 **客户端管理 → 客户端注册表**，新建客户端条目，复制生成的 Key。

### 4. 启动客户端

```bash
anno-client \
  --server <server-ip>:9000 \
  --name my-client \
  --key <从后台复制的Key>
```

### 5. 配置端口映射

在 Web 后台 **在线客户端** tab 中为已连接的客户端添加端口映射，或通过 API：

```bash
curl -X POST http://<server>:8080/api/clients/<id>/mappings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"server_port":8443,"protocol":"tcp","target_host":"127.0.0.1","target_port":443}'
```

---

## anno-server 参数


| 参数                           | 默认值            | 说明                             |
| ---------------------------- | -------------- | ------------------------------ |
| `--control`                  | `0.0.0.0:9000` | 控制面监听地址，客户端连接到此端口              |
| `--api`                      | `0.0.0.0:8080` | HTTP 管理 API 及 Web UI 监听地址      |
| `--registry-file`            | `clients.json` | 客户端注册表 JSON 文件路径               |
| `--api-token`                | 空（不启用）         | 静态 Bearer Token（与密码登录二选一或叠加使用） |
| `--tunnel-queue-capacity`    | `256`          | 每个会话的隧道数据缓冲帧数，超出时丢弃            |
| `--control-channel-capacity` | `1024`         | 发往客户端的控制帧缓冲大小                  |
| `--udp-session-timeout-secs` | `300`          | UDP 会话空闲超时（秒）                  |
| `--cleanup-interval-secs`    | `30`           | 过期会话清理间隔（秒）                    |
| `--conn-ready-timeout-secs`  | `60`           | 等待客户端 ConnReady 的超时（秒）         |
| `--max-control-connections`  | `0`（不限）        | 最大并发控制连接数                      |


**环境变量**（可写入 `.env` 文件）：


| 变量                    | 说明                                      |
| --------------------- | --------------------------------------- |
| `ADMIN_PASSWORD_HASH` | bcrypt hash，用于 Web 后台密码登录               |
| `RUST_LOG`            | 日志级别，如 `info`、`debug`、`anno_server=debug` |


---

## anno-client 参数


| 参数                           | 必填  | 默认值    | 说明                             |
| ---------------------------- | --- | ------ | ------------------------------ |
| `--server`                   | 是   | —      | 服务端控制面地址，如 `1.2.3.4:9000`      |
| `--name`                     | 是   | —      | 客户端名称，与服务端注册表中的名称对应            |
| `--key`                      | 是   | —      | 服务端注册表中为该客户端生成的认证 Key          |
| `--http-proxy`               | 否   | —      | 本地 HTTP/HTTPS 代理端口（CONNECT 协议） |
| `--tunnel-queue-capacity`    | 否   | `256`  | 隧道数据缓冲帧数                       |
| `--control-channel-capacity` | 否   | `1024` | 控制帧缓冲大小                        |


**环境变量**：


| 变量         | 说明   |
| ---------- | ---- |
| `RUST_LOG` | 日志级别 |


---

## 客户端注册表（clients.json）

服务端在 `--registry-file` 路径自动维护，格式如下：

```json
{
  "clients": [
    {
      "name": "my-client",
      "key": "550e8400-e29b-41d4-a716-446655440000",
      "description": "办公室内网",
      "created_at": 1713200000
    }
  ]
}
```

- 所有客户端必须在注册表中存在且 key 匹配才能连接
- 可通过 Web 后台或 API 管理条目，支持重新生成 key（旧 key 立即失效）

---

## 管理 API

所有 `/api/*` 接口需要在请求头携带登录后获取的 token：

```
Authorization: Bearer <token>
```


| 方法       | 路径                                   | 说明                        |
| -------- | ------------------------------------ | ------------------------- |
| `POST`   | `/api/login`                         | 密码登录，返回 `{"token":"..."}` |
| `GET`    | `/api/clients`                       | 列出所有客户端（含映射）              |
| `GET`    | `/api/clients/:id`                   | 获取单个客户端                   |
| `DELETE` | `/api/clients/:id`                   | 删除客户端                     |
| `GET`    | `/api/clients/:id/mappings`          | 列出端口映射                    |
| `POST`   | `/api/clients/:id/mappings`          | 添加端口映射                    |
| `PUT`    | `/api/clients/:id/mappings/:port`    | 更新端口映射                    |
| `DELETE` | `/api/clients/:id/mappings/:port`    | 删除端口映射                    |
| `GET`    | `/api/stats`                         | 服务端统计信息                   |
| `GET`    | `/api/registry`                      | 列出客户端注册表                  |
| `POST`   | `/api/registry`                      | 创建客户端条目                   |
| `GET`    | `/api/registry/:name`                | 获取单个条目                    |
| `PUT`    | `/api/registry/:name`                | 更新条目描述                    |
| `DELETE` | `/api/registry/:name`                | 删除条目                      |
| `POST`   | `/api/registry/:name/regenerate-key` | 重新生成 key                  |
| `GET`    | `/metrics`                           | Prometheus 指标（无需认证）       |


---

## 前端开发

```bash
cd frontend
npm install

# 开发模式（/api 代理到 localhost:8080）
npm run dev

# 生产构建
VITE_API_BASE=http://<server>:8080 npm run build
```

将 `dist/` 目录下的静态文件通过 nginx 或其他 Web 服务器托管。