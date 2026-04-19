# anno

内网穿透 / 端口转发。包含 Rust 服务端、Rust 客户端和 React 管理 Web UI。

## 组件


| 组件            | 说明                            |
| ------------- | ----------------------------- |
| `anno-server` | 控制面 + 公网监听 + HTTP 管理 API      |
| `anno-client` | 连接服务端，TCP/UDP 转发，可选本地 HTTP 代理 |
| `common`      | 二进制帧协议                        |
| `frontend`    | React + Ant Design 管理界面（Vite） |


控制面二进制帧由 `common` 定义，**帧版本为 v4**（`VERSION = 0x04`）。请**同版本**构建并部署 `anno-server` 与 `anno-client`，否则将因版本不匹配无法建立控制连接。v4 在 v3 的基础上新增：客户端发起的 GoAway 处理、独立的 `ErrorCode::AuthFailed`、帧头 `features` bitmap（保留供后续扩展）。

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
  --key <从后台复制的Key>
```

### 5. 配置端口映射

在 Web 后台 **客户端管理** 页面为任一客户端（无论是否在线）添加端口映射，或通过 API：

```bash
curl -X POST http://<server>:8080/api/clients/<id>/mappings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"server_port":8443,"protocol":"tcp","target_host":"127.0.0.1","target_port":443}'
```

支持的 `protocol` 取值：`tcp`、`udp`、`both`、`http_proxy`。其中 `http_proxy` 为特殊协议：服务端监听 TCP，并自动转发到客户端当前随机分配的本地 HTTP 代理端口，客户端重启后仍会自动映射到新端口；此模式下 `target_host`/`target_port` 字段可省略。示例：

```bash
curl -X POST http://<server>:8080/api/clients/<id>/mappings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"server_port":9443,"protocol":"http_proxy"}'
```

---

## anno-server 参数


| 参数                             | 默认值            | 说明                          |
| ------------------------------ | -------------- | --------------------------- |
| `--control`                    | `0.0.0.0:9000` | 控制面监听地址，客户端连接到此端口           |
| `--api`                        | `0.0.0.0:8080` | HTTP 管理 API 及 Web UI 监听地址   |
| `--registry-file`              | `clients.json` | 客户端注册表 JSON 文件路径            |
| `--tunnel-queue-capacity`      | `256`          | 每个会话的隧道数据缓冲帧数，超出时丢弃         |
| `--control-channel-capacity`   | `1024`         | 发往客户端的控制帧缓冲大小               |
| `--udp-session-timeout-secs`   | `300`          | UDP 会话空闲超时（秒）               |
| `--cleanup-interval-secs`      | `30`           | 过期会话清理间隔（秒）                 |
| `--conn-ready-timeout-secs`    | `60`           | 等待客户端 ConnReady 的超时（秒）      |
| `--max-control-connections`    | `0`（不限）        | 最大并发控制连接数                   |
| `--max-sessions-per-client`    | `0`（不限）        | 每客户端最大并发隧道会话数               |
| `--public-bind`                | `0.0.0.0`      | 所有端口映射公共监听的绑定地址             |
| `--control-ping-interval-secs` | `20`           | 服务端控制连接 Ping 周期（秒）          |
| `--control-idle-timeout-secs`  | `60`           | 控制连接空闲断连阈值（秒）               |
| `--register-timeout-secs`      | `10`           | 等待客户端首帧 Register 的超时（秒）     |
| `--tcp-send-timeout-secs`      | `5`            | 服务端向会话 mpsc 发 TCP 帧的超时（秒）   |
| `--metrics-listen`             | —              | 专用 Prometheus /metrics 监听地址 |


若配置了 `ADMIN_PASSWORD_HASH`，访问受保护的管理 API 须在登录后使用 Web 返回的 **Bearer session token**（不再支持静态 API token）。

**环境变量**（可写入 `.env` 文件）：


| 变量                    | 说明                                        |
| --------------------- | ----------------------------------------- |
| `ADMIN_PASSWORD_HASH` | bcrypt hash，用于 Web 后台密码登录                 |
| `RUST_LOG`            | 日志级别，如 `info`、`debug`、`anno_server=debug` |


---

## anno-client 参数


| 参数                           | 必填  | 默认值     | 说明                                            |
| ---------------------------- | --- | ------- | --------------------------------------------- |
| `--server`                   | 是   | —       | 服务端控制面地址，如 `1.2.3.4:9000`                     |
| `--key`                      | 是   | —       | 注册表中为该客户端生成的认证 Key（客户端无需配置名称）                 |
| `--http-proxy`               | 否   | `0`（随机） | 本地 HTTP/HTTPS 代理端口（CONNECT 协议）；默认绑定随机端口并上报服务端 |
| `--no-http-proxy`            | 否   | `false` | 关闭本地 HTTP 代理（覆盖 `--http-proxy`）               |
| `--tunnel-queue-capacity`    | 否   | `256`   | 隧道数据缓冲帧数                                      |
| `--control-channel-capacity` | 否   | `1024`  | 控制帧缓冲大小                                       |
| `--ping-interval-secs`       | 否   | `15`    | 客户端向服务端发 Ping 的周期（秒）                          |
| `--idle-timeout-secs`        | 否   | `45`    | 未收到服务端帧时的重连阈值（秒）                              |
| `--tcp-send-timeout-secs`    | 否   | `5`     | 客户端 TCP 隧道入队超时（秒）                             |


客户端启动时会默认绑定一个**随机端口**作为本地 HTTP/HTTPS 代理（CONNECT 协议）。实际端口在 `bind` 完成后通过 `Register` 帧上报给服务端，Web 后台可见。若需关闭本地代理可使用 `--no-http-proxy`；若需固定端口可使用 `--http-proxy <port>`。

结合服务端的 `http_proxy` 协议映射，服务端会把某个公网端口自动转发到“客户端当前随机 HTTP 代理端口”；客户端重启并分配到新的随机端口后，该映射会**自动重新指向新端口**，无需修改映射配置。

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
      "created_at": 1713200000,
      "mappings": [
        {
          "server_port": 8443,
          "protocol": "tcp",
          "target_host": "127.0.0.1",
          "target_port": 443
        }
      ]
    }
  ]
}
```

- 所有客户端必须在注册表中存在且 key 匹配才能连接
- 可通过 Web 后台或 API 管理条目，支持重新生成 key（旧 key 立即失效）
- `mappings` 字段由服务端自动维护，记录端口转发规则；重启后自动还原，客户端上线即生效

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

## systemd 部署

从 GitHub Release 拉取预编译二进制，创建配置目录和环境变量文件，再装一个 `Restart=always` 的 systemd unit 即可。需要 `curl` 与 `htpasswd`（后者来自 `apache2-utils` / `httpd-tools`）。

### 1. 拉取二进制

```bash
ARCH=$(uname -m); [ "$ARCH" = "arm64" ] && ARCH=aarch64
BASE=https://github.com/metolab/anno/releases/latest/download

# 服务端机器
sudo curl -fL "$BASE/anno-server-$ARCH" -o /usr/local/bin/anno-server
sudo chmod +x /usr/local/bin/anno-server

# 客户端机器
sudo curl -fL "$BASE/anno-client-$ARCH" -o /usr/local/bin/anno-client
sudo chmod +x /usr/local/bin/anno-client
```

### 2. 创建配置目录与环境变量文件

```bash
sudo install -d -m 0750 /etc/anno
```

**服务端** `/etc/anno/server.env`（生成 bcrypt 密码哈希并写入）：

```bash
read -rsp "admin password: " P; echo
HASH=$(htpasswd -bnBC 10 "" "$P" | tr -d ':\n' | sed 's/$2y/$2b/')
sudo tee /etc/anno/server.env >/dev/null <<EOF
ADMIN_PASSWORD_HASH=$HASH
RUST_LOG=info
ANNO_SERVER_ARGS=--control 0.0.0.0:9000 --api 0.0.0.0:8080 --registry-file /etc/anno/clients.json
EOF
unset P HASH
```

**客户端** `/etc/anno/client.env`（`ANNO_KEY` 由服务端 Web 后台生成）：

```bash
sudo tee /etc/anno/client.env >/dev/null <<'EOF'
ANNO_SERVER=1.2.3.4:9000
ANNO_KEY=xxxx-xxxx-xxxx
RUST_LOG=info
ANNO_CLIENT_ARGS=--http-proxy 0
EOF
```

### 3. 写入 systemd unit

`Restart=always` + `RestartSec=3` 实现无限重启；`EnvironmentFile=-` 前缀表示文件不存在也不报错。

`**/etc/systemd/system/anno-server.service**`：

```ini
[Unit]
Description=anno server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/anno/server.env
ExecStart=/usr/local/bin/anno-server $ANNO_SERVER_ARGS
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

`**/etc/systemd/system/anno-client.service**`：

```ini
[Unit]
Description=anno client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/anno/client.env
ExecStart=/usr/local/bin/anno-client --server ${ANNO_SERVER} --key ${ANNO_KEY} $ANNO_CLIENT_ARGS
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 4. 启用

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now anno-server    # 服务端
sudo systemctl enable --now anno-client    # 客户端
journalctl -u anno-server -f               # 查看日志
```

---

## 功能黑盒测试

依赖：`bash`、`curl`、`python3`。在项目根目录执行：

```bash
bash tests/functional_test.sh              # 全部用例（会先 cargo build）
bash tests/functional_test.sh T01 T03       # 仅指定用例
```

环境变量可覆盖端口：`CTRL_PORT`、`API_PORT`、`MAP_TCP`、`MAP_UDP` 等（见脚本头部注释）。

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