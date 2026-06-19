# WoW Register Lite

一个用于 AzerothCore 的轻量账号注册网站。前端提供注册表单，Flask 后端校验输入，并通过 AzerothCore worldserver SOAP 执行固定格式的账号创建命令。

## 功能

- 账号名、密码、确认密码、邮箱格式校验
- 通过 SOAP 执行 `account create username password`
- 用户登录和基础 Dashboard
- Dashboard 服务器状态面板
- 登录用户修改密码
- 绑定邮箱和邮件密码重置
- GM 可维护客户端下载链接，普通用户只可下载
- 当前在线玩家查询
- 问题提交、图片上传、状态处理和 GM 回复
- 注册数学验证码
- 注册成功、重复账号、SOAP 不可用等友好提示
- 简单 IP 限流
- 基础日志记录到 `logs/app.log`
- 响应式深色魔幻风格页面

## 本地运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env
# 编辑 .env，填入 SOAP_PASS、MYSQL_PASS 和 SECRET_KEY

python app.py
```

访问：

```text
http://127.0.0.1:8000/
```

## 正式运行

```powershell
waitress-serve --host=0.0.0.0 --port=8000 app:app
```

对外开放时请使用 HTTPS，并通过 IIS、Nginx 或其他反向代理转发到本地 Python 服务。

## AzerothCore SOAP 配置

在 `worldserver.conf` 中启用 SOAP：

```ini
SOAP.Enabled = 1
SOAP.IP = "127.0.0.1"
SOAP.Port = 7878
```

修改后需要重启 `worldserver`。

SOAP 端口只应该监听 `127.0.0.1`，不要直接暴露到公网。

创建一个专门用于网站的 SOAP 账号，例如 `websoap`，并给它足够执行 `account create` 的权限。该账号不要作为玩家账号使用。

## 环境变量

| 名称 | 默认值 | 说明 |
| --- | --- | --- |
| `SOAP_HOST` | `127.0.0.1` | AzerothCore SOAP 地址 |
| `SOAP_PORT` | `7878` | AzerothCore SOAP 端口 |
| `SOAP_USER` | `websoap` | SOAP 账号 |
| `SOAP_PASS` | `change-me` | SOAP 密码 |
| `SOAP_TIMEOUT_SECONDS` | `8` | SOAP 请求超时时间 |
| `MYSQL_HOST` | `127.0.0.1` | MySQL 地址 |
| `MYSQL_PORT` | `3306` | MySQL 端口 |
| `MYSQL_USER` | `acore` | MySQL 用户 |
| `MYSQL_PASS` | `change-me` | MySQL 密码 |
| `MYSQL_AUTH_DB` | `acore_auth` | AzerothCore 账号库 |
| `MYSQL_CHARACTERS_DB` | `acore_characters` | AzerothCore 角色库 |
| `SITE_TITLE` | `My WoW Server` | 页面服务器名称 |
| `REALMLIST` | `wow.example.com` | 页面展示的 realmlist |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | 邮件重置链接使用的站点外部地址 |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | 限流窗口 |
| `RATE_LIMIT_MAX_ATTEMPTS` | `3` | 每个窗口允许提交次数 |
| `GM_DOWNLOAD_LEVEL` | `3` | 可管理下载链接的 GM 等级 |
| `MAX_UPLOAD_MB` | `5` | 问题提交图片大小限制 |
| `SMTP_HOST` | 空 | SMTP 服务器地址 |
| `SMTP_PORT` | `587` | SMTP 端口 |
| `SMTP_USER` | 空 | SMTP 登录账号 |
| `SMTP_PASS` | 空 | SMTP 应用专用密码 |
| `SMTP_FROM` | `SMTP_USER` | 发件人地址 |
| `PASSWORD_RESET_EXPIRE_MINUTES` | `30` | 重置链接有效分钟数 |

也可以复制 `.env.example` 为 `.env`，项目启动时会自动读取 `.env`。`.env` 已加入 `.gitignore`，不要提交真实密码。

## 页面

- `/`：登录和注册入口，预留密码找回链接
- `/dashboard`：登录后的账号基础信息
- `/downloads`：客户端下载链接；GM 可添加、编辑、删除
- `/online`：当前在线角色查询
- `/account/security`：修改密码和绑定邮箱
- `/forgot-password`：通过账号名和已绑定邮箱申请重置链接
- `/reset-password/<token>`：一次性密码重置页面
- `/issues`：问题提交，支持上传图片；GM 可筛选状态、修改状态、填写回复

## 验收清单

- 本机访问 `http://127.0.0.1:8000/` 可以打开注册页面
- 合法账号和密码可以成功注册
- 已有账号可以登录并进入 Dashboard
- 登录用户可以修改密码
- 用户可以绑定邮箱并通过邮件重置密码
- Dashboard 能显示服务器状态
- GM 账号可以维护下载链接
- 普通用户可以查看并打开下载链接
- 用户可以提交问题和上传图片
- GM 可以回复问题并更新处理状态
- HeidiSQL 中可以在 `acore_auth.account` 表看到新账号
- 游戏客户端可以用新账号正常登录
- 重复注册同名账号时，页面提示账号已存在
- 非法账号名会被阻止提交
- 两次密码不一致时，页面提示错误
- `worldserver` 关闭时，页面提示注册服务暂时不可用
- SOAP 端口没有暴露到公网
- Python 后端只执行固定格式的 `account create username password email`

## 安全说明

后端会校验所有用户输入。账号名只允许英文字母、数字和下划线，密码不允许空格，提交到 SOAP 的命令固定为 `account create username password`，不会允许用户提交任意 GM 命令。

正式开放给玩家前建议增加：

- HTTPS
- Cloudflare Turnstile 验证码
- 更完整的 IP 限流
- 使用环境变量或 `.env` 管理真实 SOAP 密码，不要把真实密码提交到 GitHub
- 对问题提交增加处理状态、回复和后台列表筛选

## 邮件找回配置

密码重置邮件使用 SMTP 发送。以常见的 587 STARTTLS 为例：

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASS=邮箱服务商提供的应用专用密码
SMTP_FROM=noreply@example.com
SMTP_USE_TLS=true
SMTP_USE_SSL=false
PASSWORD_RESET_EXPIRE_MINUTES=30
PUBLIC_BASE_URL=https://你的域名
```

新注册账号必须填写邮箱。旧账号需要登录后到“账号安全”绑定邮箱，才能使用密码找回。
