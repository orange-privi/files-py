import ipaddress
import os
import secrets
import socket
import mimetypes
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests
from flask import (
    Flask, abort, flash, redirect, render_template_string, request,
    send_file, session, url_for
)
from werkzeug.utils import secure_filename

APP_NAME = "FileDesk"
ROOT_DIR = Path(os.environ.get("FILE_MANAGER_ROOT", "./managed_files")).resolve()
PASSWORD = os.environ.get("FILE_MANAGER_PASSWORD", "printf955")
HOST = os.environ.get("FILE_MANAGER_HOST", "0.0.0.0")
PORT = int(os.environ.get("FILE_MANAGER_PORT", "8000"))
MAX_UPLOAD_MB = int(os.environ.get("FILE_MANAGER_MAX_UPLOAD_MB", "100"))
MAX_PULL_MB = int(os.environ.get("FILE_MANAGER_MAX_PULL_MB", "100"))
TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".py", ".js", ".ts", ".tsx", ".jsx", ".html",
    ".css", ".scss", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".sql", ".sh", ".bash", ".bat", ".ps1", ".java",
    ".kt", ".kts", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".php",
    ".rb", ".pl", ".lua", ".r", ".csv", ".log", ".env", ".gitignore", ".dockerfile"
}
ROOT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FILE_MANAGER_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def relative_path(path: Path) -> str:
    return path.relative_to(ROOT_DIR).as_posix()


def safe_path(raw: str = "") -> Path:
    """Resolve a user-supplied relative path and prevent escaping ROOT_DIR."""
    raw = unquote(raw or "").replace("\\", "/")
    candidate = (ROOT_DIR / raw).resolve()
    try:
        candidate.relative_to(ROOT_DIR)
    except ValueError:
        abort(403, "路径越界")
    return candidate


def is_text_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {
        ".env", ".gitignore", "dockerfile", "makefile"
    }:
        return True
    mime, _ = mimetypes.guess_type(path.name)
    if mime and (mime.startswith("text/") or mime in {
        "application/json", "application/xml", "application/javascript"
    }):
        return True
    try:
        with path.open("rb") as f:
            sample = f.read(8192)
        return b"\x00" not in sample and sample.decode("utf-8") is not None
    except (UnicodeDecodeError, OSError):
        return False


def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "app_name": APP_NAME}


@app.before_request
def require_login():
    if PASSWORD and request.endpoint not in {"login", "static"} and not session.get("logged_in"):
        return redirect(url_for("login", next=request.path))


def check_csrf():
    if not secrets.compare_digest(str(request.form.get("_csrf", "")), str(session.get("_csrf", ""))):
        abort(400, "CSRF 校验失败，请刷新页面后重试")


def breadcrumbs(rel: str):
    items = [{"name": "全部文件", "path": ""}]
    current = ""
    for part in [p for p in rel.split("/") if p]:
        current = f"{current}/{part}".strip("/")
        items.append({"name": part, "path": current})
    return items


def list_entries(folder: Path):
    entries = []
    try:
        children = list(folder.iterdir())
    except OSError:
        return entries
    children.sort(key=lambda p: (not p.is_dir(), p.name.casefold()))
    for p in children:
        try:
            stat = p.stat()
            entries.append({
                "name": p.name,
                "path": relative_path(p),
                "is_dir": p.is_dir(),
                "size": stat.st_size,
                "modified": __import__("datetime").datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "text": is_text_file(p) if p.is_file() else False,
                "ext": (p.suffix[1:].upper() if p.suffix else ("文件夹" if p.is_dir() else "FILE")),
            })
        except OSError:
            continue
    return entries


def url_is_public(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, "仅支持 http/https 地址"
    if parsed.username or parsed.password:
        return False, "地址中不能包含用户名或密码"
    host = parsed.hostname
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return False, "出于安全考虑，不允许拉取 localhost 地址"
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))}
        if not addresses:
            return False, "无法解析远程主机"
        for addr in addresses:
            ip = ipaddress.ip_address(addr.split("%")[0])
            if not ip.is_global:
                return False, "出于安全考虑，只允许拉取公网 IP 地址"
    except (OSError, ValueError):
        return False, "无法解析远程主机地址"
    return True, ""


LOGIN_HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · FileDesk</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 20% 10%,#dceafe,transparent 35%),linear-gradient(135deg,#f5f7fb,#e9eef7);font:15px system-ui,-apple-system,"Segoe UI",sans-serif;color:#182235}.panel{width:min(420px,calc(100% - 32px));padding:34px;background:#fff;border:1px solid #e8edf5;border-radius:24px;box-shadow:0 24px 70px #23395d18}.logo{width:48px;height:48px;display:grid;place-items:center;border-radius:15px;background:#2563eb;color:#fff;font-size:24px}.muted{color:#718096}input,button{font:inherit}input{width:100%;padding:13px 14px;border:1px solid #dce3ef;border-radius:12px;margin:10px 0 16px}button{width:100%;border:0;border-radius:12px;padding:13px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer}.error{color:#b42318;margin-bottom:12px}</style></head><body><main class="panel"><div class="logo">▤</div><h1>欢迎使用 FileDesk</h1><p class="muted">登录后管理你的文件</p>{% for msg in get_flashed_messages() %}<div class="error">{{msg}}</div>{% endfor %}<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><label>访问密码</label><input type="password" name="password" required autofocus placeholder="输入管理密码"><button>安全登录</button></form></main></body></html>"""

PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · FileDesk</title><style>
:root{--bg:#f4f7fb;--panel:#fff;--ink:#172238;--muted:#77839a;--line:#e8edf5;--blue:#356df3;--blue2:#edf3ff;--green:#17865b;--red:#c24141}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}.shell{display:flex;min-height:100vh}.side{width:245px;background:#fff;border-right:1px solid var(--line);padding:25px 17px;display:flex;flex-direction:column;gap:26px;flex-shrink:0}.brand{display:flex;align-items:center;gap:11px;padding:0 9px;font-size:18px;font-weight:800;letter-spacing:-.4px}.brandmark{width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,#4c82ff,#2458e8);color:#fff;display:grid;place-items:center;font-size:20px;box-shadow:0 8px 20px #356df333}.nav-label{font-size:11px;font-weight:800;letter-spacing:1.1px;color:#a1aabd;padding:0 12px;margin-bottom:8px}.navitem{display:flex;gap:12px;align-items:center;padding:11px 12px;border-radius:11px;color:#64718a;margin:3px 0}.navitem.active,.navitem:hover{background:var(--blue2);color:var(--blue);font-weight:700}.navicon{width:20px;text-align:center;font-size:17px}.sidefoot{margin-top:auto;padding:15px;background:#f7f9fd;border:1px solid var(--line);border-radius:14px;color:var(--muted);font-size:12px}.main{min-width:0;flex:1;padding:32px clamp(18px,3vw,46px);max-width:1600px;margin:0 auto;width:100%}.topline{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:25px}.eyebrow{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:1.3px;text-transform:uppercase}.h1{font-size:29px;letter-spacing:-1px;margin:4px 0 3px}.subtitle{color:var(--muted)}.avatar{width:40px;height:40px;display:grid;place-items:center;border-radius:50%;background:#e6edff;color:#315fe3;font-weight:800}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line);background:#fff;color:#34425c;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer;white-space:nowrap}.btn:hover{border-color:#b8c9f5;background:#f9fbff}.btn.primary{background:var(--blue);color:#fff;border-color:var(--blue);box-shadow:0 5px 12px #356df322}.btn.primary:hover{background:#2458d9}.btn.danger{color:var(--red)}.card{background:var(--panel);border:1px solid var(--line);border-radius:17px;box-shadow:0 5px 18px #1b315008;overflow:hidden}.cardhead{padding:18px 21px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}.cardhead h2{font-size:15px;margin:0}.muted{color:var(--muted)}.crumbs{display:flex;gap:8px;align-items:center;flex-wrap:wrap;color:var(--muted);font-size:13px}.crumbs a:hover{color:var(--blue)}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px;margin-bottom:22px}.stat{padding:18px 20px;background:#fff;border:1px solid var(--line);border-radius:15px}.statlabel{font-size:12px;color:var(--muted)}.statnum{font-size:23px;font-weight:800;margin-top:5px;letter-spacing:-.5px}.staticon{float:right;font-size:20px;background:#f0f4ff;border-radius:10px;padding:6px}.tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%;white-space:nowrap}th{text-align:left;color:#8b96aa;font-size:11px;text-transform:uppercase;letter-spacing:.7px;background:#fbfcfe;padding:12px 18px;font-weight:800}td{padding:14px 18px;border-top:1px solid #f0f3f8}tr:hover td{background:#fcfdff}.filecell{display:flex;align-items:center;gap:12px;min-width:200px}.fileicon{width:39px;height:42px;border-radius:10px;background:#edf3ff;color:#356df3;display:grid;place-items:center;font-size:17px;flex-shrink:0}.fileicon.folder{background:#fff3d7;color:#d79a16}.filename{font-weight:700;max-width:380px;overflow:hidden;text-overflow:ellipsis}.subname{font-size:11px;color:#9aa4b5;margin-top:2px}.tag{font-size:10px;font-weight:800;letter-spacing:.3px;padding:5px 8px;border-radius:7px;background:#f0f3f8;color:#69758b}.tag.text{background:#e7f8ef;color:#17865b}.actions{display:flex;gap:6px;align-items:center}.iconbtn{border:1px solid transparent;background:transparent;color:#78849a;padding:7px 9px;border-radius:8px;cursor:pointer;font-size:13px}.iconbtn:hover{background:#edf3ff;color:var(--blue)}.flash{padding:12px 15px;border-radius:11px;background:#eaf8ef;color:#13784d;margin-bottom:16px}.flash.error{background:#fff0ef;color:#b42318}.workspace{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:18px;align-items:start}.editorbox{background:#fff;border:1px solid var(--line);border-radius:16px;overflow:hidden}.editorbar{padding:14px 18px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);gap:10px}.editor{width:100%;min-height:60vh;border:0;outline:0;resize:vertical;padding:22px;font:13px/1.75 ui-monospace,SFMono-Regular,Consolas,monospace;color:#23314a;tab-size:4}.preview{padding:24px;min-height:60vh;white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.8 ui-monospace,monospace}.sidecard{padding:18px}.sidecard h3{margin:0 0 14px;font-size:14px}.detailrow{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f3f8;font-size:12px}.detailrow span:first-child{color:var(--muted)}.formcard{padding:22px}.field{margin:0 0 17px}.field label{display:block;font-weight:700;margin-bottom:7px}.field input,.field textarea{width:100%;padding:12px 13px;border:1px solid #dce3ef;border-radius:10px;background:#fff;font:inherit;outline:none}.field input:focus,.field textarea:focus{border-color:#7ba0ff;box-shadow:0 0 0 3px #356df315}.field small{display:block;color:var(--muted);margin-top:6px}.empty{text-align:center;padding:58px 20px;color:var(--muted)}.emptyicon{font-size:36px;margin-bottom:10px}.notice{padding:13px 15px;background:#fff8e7;color:#926b14;border-radius:11px;font-size:12px;margin-bottom:18px}.mobiletop{display:none}
@media(max-width:900px){.side{width:72px;padding:20px 10px}.brand{padding:0;justify-content:center}.brandname,.nav-label,.navtext,.sidefoot{display:none}.navitem{justify-content:center;padding:12px 5px}.navicon{font-size:19px}.workspace{grid-template-columns:1fr}.stats{gap:9px}.stat{padding:14px}.main{padding:24px 16px}}
@media(max-width:560px){.topline{align-items:flex-start}.h1{font-size:24px}.stats{grid-template-columns:1fr 1fr}.stats .stat:last-child{display:none}.cardhead{align-items:flex-start;flex-direction:column}.toolbar{width:100%}.toolbar .btn{flex:1}.avatar{display:none}.main{padding:20px 12px}.editor{min-height:50vh;padding:15px}}
</style></head><body><div class="shell">
<aside class="side"><a class="brand" href="{{url_for('index')}}"><span class="brandmark">▤</span><span class="brandname">FileDesk</span></a>
<div><div class="nav-label">工作空间</div><a class="navitem {{'active' if page=='files' else ''}}" href="{{url_for('index')}}"><span class="navicon">▦</span><span class="navtext">全部文件</span></a><a class="navitem {{'active' if page=='pull' else ''}}" href="{{url_for('pull_page')}}"><span class="navicon">↙</span><span class="navtext">远程拉取</span></a></div>
<div><div class="nav-label">工具</div><a class="navitem" href="{{url_for('index')}}"><span class="navicon">⌕</span><span class="navtext">文件浏览</span></a></div>
<div class="sidefoot"><b>本地存储空间</b><p>文件保存在服务器指定目录中。文本文件支持在线编辑与预览。</p></div></aside>
<main class="main"><div class="topline"><div><div class="eyebrow">PERSONAL WORKSPACE</div><div class="h1">{{title}}</div><div class="subtitle">{{subtitle}}</div></div><div class="avatar">FD</div></div>
{% for category,msg in get_flashed_messages(with_categories=true) %}<div class="flash {{'error' if category=='error' else ''}}">{{msg}}</div>{% endfor %}
{% if page=='files' %}
<div class="stats"><div class="stat"><span class="staticon">▦</span><div class="statlabel">当前目录文件</div><div class="statnum">{{entries|length}}</div></div><div class="stat"><span class="staticon">⌁</span><div class="statlabel">文本文件</div><div class="statnum">{{text_count}}</div></div><div class="stat"><span class="staticon">↗</span><div class="statlabel">存储位置</div><div class="statnum" style="font-size:15px;margin-top:11px">安全目录内</div></div></div>
<div class="toolbar" style="margin-bottom:17px"><form action="{{url_for('index')}}" method="get" style="display:flex;gap:8px;flex:1;min-width:190px"><input name="q" value="{{q}}" placeholder="搜索当前目录文件…" style="min-width:0;flex:1;border:1px solid var(--line);border-radius:10px;padding:10px 13px;font:inherit;background:#fff"><input type="hidden" name="path" value="{{current}}"><button class="btn" type="submit">搜索</button></form><a class="btn primary" href="{{url_for('upload_page',path=current)}}">＋ 上传文件</a><a class="btn" href="{{url_for('pull_page',path=current)}}">↙ 拉取远程文件</a></div>
<div class="card"><div class="cardhead"><div><h2>文件浏览器</h2><div class="crumbs" style="margin-top:7px">{% for crumb in crumbs %}{% if not loop.first %}<span>›</span>{% endif %}<a href="{{url_for('index',path=crumb.path)}}">{{crumb.name}}</a>{% endfor %}</div></div><span class="tag">{{entries|length}} 项</span></div>
<div class="tablewrap"><table><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>修改时间</th><th>操作</th></tr></thead><tbody>
{% if parent is not none %}<tr><td><a class="filecell" href="{{url_for('index',path=parent)}}"><span class="fileicon folder">↰</span><span><span class="filename">返回上级目录</span><div class="subname">..</div></span></a></td><td><span class="tag">目录</span></td><td>—</td><td>—</td><td></td></tr>{% endif %}
{% for e in entries %}<tr><td><div class="filecell"><span class="fileicon {{'folder' if e.is_dir else ''}}">{{'▰' if e.is_dir else ('⌘' if e.text else '▤')}}</span><span><a class="filename" href="{{url_for('index',path=e.path) if e.is_dir else (url_for('edit_file',path=e.path) if e.text else url_for('download_file',path=e.path))}}">{{e.name}}</a><div class="subname">{{'文件夹' if e.is_dir else ('可在线编辑' if e.text else '可下载文件')}}</div></span></div></td><td><span class="tag {{'text' if e.text else ''}}">{{'文件夹' if e.is_dir else e.ext}}</span></td><td>{{'-' if e.is_dir else human_size(e.size)}}</td><td>{{e.modified}}</td><td><div class="actions">{% if e.is_dir %}<a class="iconbtn" href="{{url_for('index',path=e.path)}}">打开</a>{% else %}{% if e.text %}<a class="iconbtn" href="{{url_for('edit_file',path=e.path)}}">编辑</a>{% endif %}<a class="iconbtn" href="{{url_for('download_file',path=e.path)}}">下载</a>{% endif %}<form method="post" action="{{url_for('delete_file')}}" onsubmit="return confirm('确定删除 {{e.name}} 吗？此操作不可撤销。')"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{e.path}}"><input type="hidden" name="back" value="{{current}}"><button class="iconbtn" type="submit" title="删除">删除</button></form></div></td></tr>{% endfor %}
{% if not entries %}<tr><td colspan="5"><div class="empty"><div class="emptyicon">▱</div><b>这里还没有文件</b><p>上传文件，或从远程 URL 拉取文件开始使用。</p></div></td></tr>{% endif %}
</tbody></table></div></div>
{% elif page=='edit' %}
<div class="toolbar" style="margin-bottom:16px"><div class="crumbs" style="flex:1"><a href="{{url_for('index',path=parent)}}">全部文件</a><span>›</span><b>{{file_name}}</b></div><a class="btn" href="{{url_for('download_file',path=path)}}">↓ 下载原文件</a><a class="btn" href="{{url_for('preview_file',path=path)}}">预览</a></div>
<form method="post" action="{{url_for('save_file')}}"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{path}}"><div class="workspace"><div class="editorbox"><div class="editorbar"><div><b>{{file_name}}</b><div class="subname">UTF-8 · 纯文本编辑器</div></div><div class="toolbar"><button class="btn primary" type="submit">保存更改</button></div></div><textarea class="editor" name="content" spellcheck="false" autocapitalize="off">{{content}}</textarea><div class="editorbar"><span class="muted" id="count">正在编辑</span><span class="muted">保存将覆盖原文件</span></div></div><aside class="card sidecard"><h3>文件信息</h3><div class="detailrow"><span>文件名</span><b style="text-align:right;overflow-wrap:anywhere">{{file_name}}</b></div><div class="detailrow"><span>文件大小</span><b>{{file_size}}</b></div><div class="detailrow"><span>编码</span><b>UTF-8</b></div><div class="detailrow"><span>编辑模式</span><b>纯文本</b></div><p class="muted" style="font-size:12px;margin-top:16px">保存前建议保留备份。编辑器不会执行代码或渲染 HTML。</p></aside></div></form>
<script>const ed=document.querySelector('.editor'),count=document.querySelector('#count');function upd(){count.textContent=ed.value.length.toLocaleString()+' 个字符 · '+new Blob([ed.value]).size.toLocaleString()+' 字节'}ed.addEventListener('input',upd);upd();</script>
{% elif page=='preview' %}
<div class="toolbar" style="margin-bottom:16px"><div class="crumbs" style="flex:1"><a href="{{url_for('index',path=parent)}}">全部文件</a><span>›</span><b>{{file_name}}</b></div><a class="btn" href="{{url_for('edit_file',path=path)}}">编辑文件</a><a class="btn" href="{{url_for('download_file',path=path)}}">下载</a></div><div class="card"><div class="cardhead"><h2>文本预览 · {{file_name}}</h2><span class="tag text">只读</span></div><pre class="preview">{{content}}</pre></div>
{% elif page=='upload' %}
<div class="card"><div class="cardhead"><h2>上传文件</h2><span class="tag">UPLOAD</span></div><form class="formcard" method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{current}}"><div class="field"><label>选择文件</label><input type="file" name="files" multiple required><small>支持一次选择多个文件，单个文件最大 {{max_upload}} MB。</small></div><div class="field"><label>上传到目录</label><input value="{{'/' + current if current else '/'}}" readonly></div><button class="btn primary" type="submit">开始上传</button> <a class="btn" href="{{url_for('index',path=current)}}">取消</a></form></div>
{% elif page=='pull' %}
<div class="card"><div class="cardhead"><h2>从远程地址拉取</h2><span class="tag">REMOTE FETCH</span></div><form class="formcard" method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{current}}"><div class="field"><label>文件 URL</label><input name="url" type="url" required placeholder="https://example.com/files/data.json"><small>仅允许 HTTP/HTTPS 公网地址；为防止服务器被利用访问内网，localhost、私有 IP 和重定向会被拒绝。</small></div><div class="field"><label>保存文件名（可选）</label><input name="filename" placeholder="留空时使用 URL 中的文件名"></div><div class="field"><label>保存目录</label><input value="{{'/' + current if current else '/'}}" readonly></div><div class="notice">请仅拉取你有权访问和保存的文件。下载内容大小限制为 {{max_pull}} MB。</div><button class="btn primary" type="submit">↙ 拉取并保存</button> <a class="btn" href="{{url_for('index',path=current)}}">返回文件列表</a></form></div>
{% endif %}
</main></div></body></html>"""


@app.template_global()
def human_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


@app.route("/login", methods=["GET", "POST"])
def login():
    if not PASSWORD:
        return redirect(url_for("index"))
    if request.method == "POST":
        check_csrf()
        if secrets.compare_digest(request.form.get("password", ""), PASSWORD):
            session["logged_in"] = True
            return redirect(request.args.get("next") or url_for("index"))
        flash("密码不正确，请重试。")
    return render_template_string(LOGIN_HTML)


@app.route("/")
def index():
    folder = safe_path(request.args.get("path", ""))
    if not folder.is_dir():
        abort(404)
    current = relative_path(folder) if folder != ROOT_DIR else ""
    q = request.args.get("q", "").strip().casefold()
    entries = list_entries(folder)
    if q:
        entries = [e for e in entries if q in e["name"].casefold()]
    parent = None
    if folder != ROOT_DIR:
        parent_path = folder.parent
        parent = relative_path(parent_path) if parent_path != ROOT_DIR else ""
    return render_template_string(
        PAGE, page="files", title="全部文件", subtitle="管理、查找并维护你的文件",
        entries=entries, current=current, parent=parent, crumbs=breadcrumbs(current),
        q=q, text_count=sum(1 for e in entries if e["text"]), human_size=human_size
    )


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    current = request.args.get("path", "") if request.method == "GET" else request.form.get("path", "")
    folder = safe_path(current)
    if not folder.is_dir():
        abort(404)
    if request.method == "POST":
        check_csrf()
        files = request.files.getlist("files")
        saved, errors = 0, []
        for file in files:
            name = secure_filename(file.filename or "")
            if not name:
                continue
            dest = safe_path((relative_path(folder) + "/" if folder != ROOT_DIR else "") + name)
            if dest.exists():
                errors.append(f"{name} 已存在，未覆盖")
                continue
            try:
                file.save(dest)
                saved += 1
            except OSError as exc:
                errors.append(f"{name}: {exc}")
        if saved:
            flash(f"成功上传 {saved} 个文件。")
        for err in errors:
            flash(err, "error")
        return redirect(url_for("index", path=current))
    return render_template_string(PAGE, page="upload", title="上传文件", subtitle="将本地文件安全保存到工作空间",
                                  current=relative_path(folder) if folder != ROOT_DIR else "", max_upload=MAX_UPLOAD_MB)


@app.route("/pull", methods=["GET", "POST"])
def pull_page():
    current = request.args.get("path", "") if request.method == "GET" else request.form.get("path", "")
    folder = safe_path(current)
    if not folder.is_dir():
        abort(404)
    if request.method == "POST":
        check_csrf()
        url = request.form.get("url", "").strip()
        ok, reason = url_is_public(url)
        if not ok:
            flash(reason, "error")
            return redirect(url_for("pull_page", path=current))
        parsed = urlparse(url)
        name = secure_filename(request.form.get("filename", "").strip() or Path(unquote(parsed.path)).name or "download")
        if not name:
            name = "download"
        dest = safe_path((relative_path(folder) + "/" if folder != ROOT_DIR else "") + name)
        if dest.exists():
            flash("目标文件已存在，请更换文件名，避免意外覆盖。", "error")
            return redirect(url_for("pull_page", path=current))
        tmp = dest.with_name(dest.name + ".part")
        try:
            with requests.get(url, stream=True, timeout=(8, 30), allow_redirects=False,
                              headers={"User-Agent": "FileDesk/1.0"}) as response:
                if 300 <= response.status_code < 400:
                    raise ValueError("远程地址返回重定向，出于安全考虑已拒绝；请填写最终文件 URL。")
                response.raise_for_status()
                length = int(response.headers.get("Content-Length", "0") or 0)
                if length > MAX_PULL_MB * 1024 * 1024:
                    raise ValueError(f"文件超过 {MAX_PULL_MB} MB 限制。")
                total = 0
                with tmp.open("wb") as out:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_PULL_MB * 1024 * 1024:
                            raise ValueError(f"文件超过 {MAX_PULL_MB} MB 限制。")
                        out.write(chunk)
            tmp.replace(dest)
            flash(f"拉取成功：{name}（{human_size(dest.stat().st_size)}）")
            return redirect(url_for("index", path=current))
        except Exception as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            flash(f"拉取失败：{exc}", "error")
            return redirect(url_for("pull_page", path=current))
    return render_template_string(PAGE, page="pull", title="远程拉取", subtitle="通过 URL 将远程文件保存到当前目录",
                                  current=relative_path(folder) if folder != ROOT_DIR else "", max_pull=MAX_PULL_MB)


@app.route("/download")
def download_file():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/edit")
def edit_file():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    if not is_text_file(path):
        flash("该文件不是可识别的文本文件，仅支持下载。", "error")
        return redirect(url_for("index", path=relative_path(path.parent) if path.parent != ROOT_DIR else ""))
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        flash("文件不是 UTF-8 编码，暂不支持在线编辑。", "error")
        return redirect(url_for("index", path=relative_path(path.parent) if path.parent != ROOT_DIR else ""))
    rel = relative_path(path)
    parent = relative_path(path.parent) if path.parent != ROOT_DIR else ""
    return render_template_string(PAGE, page="edit", title="在线编辑", subtitle="编辑文本内容并保存到服务器",
                                  path=rel, parent=parent, file_name=path.name, content=content,
                                  file_size=human_size(path.stat().st_size))


@app.route("/preview")
def preview_file():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    if not is_text_file(path):
        abort(415, "该文件不支持文本预览")
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, "仅支持 UTF-8 文本文件")
    rel = relative_path(path)
    parent = relative_path(path.parent) if path.parent != ROOT_DIR else ""
    return render_template_string(PAGE, page="preview", title="文本预览", subtitle="以只读方式查看文件内容",
                                  path=rel, parent=parent, file_name=path.name, content=content)


@app.route("/save", methods=["POST"])
def save_file():
    check_csrf()
    path = safe_path(request.form.get("path", ""))
    if not path.is_file() or not is_text_file(path):
        abort(400, "只能保存已存在的文本文件")
    content = request.form.get("content", "")
    if len(content.encode("utf-8")) > 5 * 1024 * 1024:
        abort(413, "文本文件最大支持 5 MB 在线编辑")
    # Write to a temporary file and atomically replace the original.
    temp = path.with_name(path.name + ".saving")
    try:
        temp.write_text(content, encoding="utf-8", newline="")
        os.replace(temp, path)
        flash("文件已保存。")
    except OSError as exc:
        temp.unlink(missing_ok=True)
        flash(f"保存失败：{exc}", "error")
    return redirect(url_for("edit_file", path=relative_path(path)))


@app.route("/delete", methods=["POST"])
def delete_file():
    check_csrf()
    path = safe_path(request.form.get("path", ""))
    back = request.form.get("back", "")
    if path == ROOT_DIR:
        abort(403)
    try:
        if path.is_dir():
            # Only remove empty folders to avoid accidental recursive deletion.
            path.rmdir()
        elif path.is_file():
            path.unlink()
        else:
            abort(404)
        flash("已删除。")
    except OSError as exc:
        flash(f"删除失败：目录可能非空，或文件正被占用。({exc})", "error")
    return redirect(url_for("index", path=back))


@app.errorhandler(413)
def too_large(_):
    return "请求文件过大。请调整 FILE_MANAGER_MAX_UPLOAD_MB 配置。", 413


if __name__ == "__main__":
    if not PASSWORD:
        print("警告：未设置 FILE_MANAGER_PASSWORD。当前仅绑定本机地址；如需局域网/公网访问，请先设置密码。")
    print(f"{APP_NAME} 工作目录：{ROOT_DIR}")
    print(f"访问地址：http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
