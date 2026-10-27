# FileDesk：Python 网页文件管理器

一个轻量的 Flask 文件管理网页，包含：

- 文件列表、当前目录搜索、目录导航
- 多文件上传、文件下载
- 从 HTTP/HTTPS 公网 URL 拉取文件
- UTF-8 文本文件在线编辑、保存、只读预览
- 删除文件；目录仅允许删除空目录
- 可选密码登录、CSRF 校验、路径越界保护
- 现代响应式界面

## 运行环境

建议 Python 3.10+。

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## 启动

### Windows PowerShell

```powershell
$env:FILE_MANAGER_PASSWORD = "请替换为强密码"
$env:FILE_MANAGER_ROOT = "D:\managed_files"
python app.py
```

### Linux

```bash
export FILE_MANAGER_PASSWORD='请替换为强密码'
export FILE_MANAGER_ROOT="$HOME/managed_files"
python app.py
```

默认地址：`http://127.0.0.1:5000`

环境变量：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `FILE_MANAGER_PASSWORD` | 空 | 设置后启用密码登录；建议始终设置 |
| `FILE_MANAGER_ROOT` | `./managed_files` | 可管理文件的根目录，不能越界访问 |
| `FILE_MANAGER_HOST` | `127.0.0.1` | 默认仅本机访问 |
| `FILE_MANAGER_PORT` | `5000` | Web 端口 |
| `FILE_MANAGER_MAX_UPLOAD_MB` | `100` | 单次请求最大上传体积（MB） |
| `FILE_MANAGER_MAX_PULL_MB` | `100` | 远程拉取文件最大体积（MB） |
| `FILE_MANAGER_SECRET_KEY` | 启动时随机生成 | 若需要跨重启保持会话，设置为固定随机密钥 |

## 局域网或服务器部署

若要从其他设备访问，设置 `FILE_MANAGER_HOST=0.0.0.0`，并务必设置强密码。生产环境建议放在 Nginx 反向代理之后，启用 HTTPS，并限制来源 IP。不要直接将 Flask 开发服务器暴露到公网。

## 功能说明与限制

- 文本预览和编辑仅面向 UTF-8 文本；常见代码、配置、JSON、Markdown、日志等文件可识别。
- HTML 以纯文本展示，不会执行或渲染，避免将上传文件当作网页执行。
- 在线编辑限制为 5 MB，防止大文件占用内存。
- 远程拉取只允许 HTTP/HTTPS 公网 IP；拒绝私有/环回地址和重定向，降低 SSRF 风险。若 URL 需要跳转，请填写最终下载地址。
- 上传时遇到同名文件会跳过，不会覆盖；远程拉取也不会覆盖已有文件。
- 删除目录时仅允许删除空目录。
- 此版本面向个人或可信环境；如果部署到公网，建议进一步增加限流、审计日志、反向代理访问控制和更严格的 DNS/IP 绑定校验。
