# DNS 回归演练台（serve-stale，两轮并行）

在值班场景里演练“内部服务的权威 DNS 失联时解析器继续给出已确认地址、但被删除
（NXDOMAIN）后绝不复活旧地址”的行为，并用网页编排可回归的用例。

网页上有 **两轮（轮次 A / 轮次 B）**，彼此隔离：每轮有自己的权威端进程、
解析器进程、SQLite 数据库、缓存和日志，**从空缓存开始**，因此两轮可以并行，
各自切换权威模式、现场查询、查看日志，互不影响。

## 用例编排

每轮最多 **12 步**，步骤按顺序执行：

| 步骤 | 内容 |
|---|---|
| 权威设置 | 切换本轮权威端：`a`（可填 A 地址）、`nxdomain`、`delay`（可填延迟秒数）、`timeout`（不应答）。动作生效时把**步骤号**写入该轮控制表。 |
| 等待 | 休眠指定秒数；**全用例合计最多 30 秒**。 |
| 查询 | 向本轮解析器发真实 UDP 查询 `service.example` A，填写预期 **RCODE**、**A 地址**、**权威设置步骤号**；后两项可留空表示“无”。 |

运行后页面逐条列出真实答复（RCODE、A、TTL、来源、设置步骤号、耗时）与预期
逐项对照，并在每条步骤上标出通过 / 失败 / 未执行 / 中断。

## 设置步骤号：区分“同一个 A 地址被设置过两次”

因为地址本身无法说明解析器用了哪一次设置，权威端把**实际采用的设置步骤号**
放进答复（附加段 TXT `_auth.<域名> "step=<n>"`）。解析器在缓存 A 或 NXDOMAIN
时把这个号一并存入 SQLite（`cache.auth_step`），并在下列三种答复里原样带回
（附加段 TXT `_src.<域名> "source=… auth_step=<n>"`）：

- 回源取到新的 A / NXDOMAIN；
- 命中新鲜缓存；
- 上游超时、沿用旧的 A（stale）。

没有对应的设置步骤（例如网页上的手动切换、现场查询触发的回源）时留空。

## 中断处理

- 端点启动失败（端口无法分配、进程起不来、探测无应答）→ 轮次标为中断，
  写明**启动**中断及原因，所有步骤标为未执行，不残留进程。
- 查询步骤**未收到 DNS 报文**（超时/传输错误）→ 在该步骤标为中断并写明原因，
  之前已测得的结果保留。
- 任一子进程意外退出 → 在当期步骤标为中断。
- 无论正常结束还是中断，轮次收尾都会**回收本轮进程与端口**；“结束并回收”
  按钮可随时手动回收。

## 运行

```bash
docker compose up --build
# 页面: http://localhost:8000
```

Compose 只常驻一个 `web` 服务；每个轮次的权威端与解析器由网页在容器内以
子进程拉起（各自独立端口与数据库），页面显示本轮端口。如需从宿主机直接 dig
某轮解析器，按显示的端口在 compose 中加对应 `ports` 映射即可。

本机无 Docker 时：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db ROUND_DB_DIR=/tmp/dns/rounds WEB_PORT=8000 python -m app.web
```

自测（自动拉起网页，覆盖并行、步骤号、中断与启动失败，约 2 分钟）：

```bash
python tests/selftest.py
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**。
- 固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
  其余名称 REFUSED，非 A 查询返回 NODATA。

## 文件

```
app/common.py        配置 + SQLite 状态面（含 step_no / auth_step 与迁移）
app/auth_server.py   可控权威端（答复带回实际设置步骤号）
app/resolver.py      缓存/serve-stale 解析器（缓存并回带步骤号）
app/rounds.py        每轮进程/端口/数据库生命周期与回收
app/regression.py    用例校验、逐条执行与对照
app/web.py           FastAPI 两轮回归控制台
tests/selftest.py    端到端自测
Dockerfile / docker-compose.yml / requirements.txt
```
