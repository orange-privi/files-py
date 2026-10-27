import ipaddress
import mimetypes
import os
import secrets
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
from flask import (
    Flask, abort, flash, redirect, render_template_string, request,
    send_file, session, url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

APP_NAME = "FileDesk"
ROOT_DIR = Path(os.environ.get("FILE_MANAGER_ROOT", "./managed_files")).resolve()
PASSWORD = os.environ.get("FILE_MANAGER_PASSWORD", "")
HOST = os.environ.get("FILE_MANAGER_HOST", "0.0.0.0")
PORT = int(os.environ.get("FILE_MANAGER_PORT", "8000"))
MAX_UPLOAD_MB = int(os.environ.get("FILE_MANAGER_MAX_UPLOAD_MB", "100"))
MAX_PULL_MB = int(os.environ.get("FILE_MANAGER_MAX_PULL_MB", "100"))
EDIT_MAX_MB = int(os.environ.get("FILE_MANAGER_EDIT_MAX_MB", "5"))
LINK_MAX_AGE = int(os.environ.get("FILE_MANAGER_LINK_MAX_AGE", str(7 * 24 * 3600)))
SECRET_KEY = os.environ.get("FILE_MANAGER_SECRET_KEY", "")
if not PASSWORD and HOST not in {"127.0.0.1", "localhost", "::1"}:
    raise RuntimeError("安全启动已阻止：监听非本机地址时必须设置 FILE_MANAGER_PASSWORD 环境变量。")

TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".py", ".js", ".ts", ".tsx", ".jsx", ".html",
    ".css", ".scss", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".sql", ".sh", ".bash", ".bat", ".ps1", ".java",
    ".kt", ".kts", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".php",
    ".rb", ".pl", ".lua", ".r", ".csv", ".log", ".env", ".gitignore", ".dockerfile",
}
ROOT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
link_signer = URLSafeTimedSerializer(app.secret_key, salt="filedesk-download-link-v1")


def safe_path(raw: str = "") -> Path:
    raw = unquote(raw or "").replace("\\", "/")
    candidate = (ROOT_DIR / raw).resolve()
    try:
        candidate.relative_to(ROOT_DIR)
    except ValueError:
        abort(403, "路径越界")
    return candidate


def relative_path(path: Path) -> str:
    return path.relative_to(ROOT_DIR).as_posix()


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} B" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024


def fmt_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def is_text_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {".env", ".gitignore", "dockerfile", "makefile"}:
        return True
    mime, _ = mimetypes.guess_type(path.name)
    if mime and (mime.startswith("text/") or mime in {"application/json", "application/xml", "application/javascript"}):
        return True
    try:
        with path.open("rb") as stream:
            sample = stream.read(8192)
        return b"\x00" not in sample and sample.decode("utf-8") is not None
    except (UnicodeDecodeError, OSError):
        return False


def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "app_name": APP_NAME, "human_size": human_size}


@app.before_request
def require_login():
    # Signed share links are intentionally usable without a browser login until they expire.
    if PASSWORD and request.endpoint not in {"login", "shared_download", "static"} and not session.get("logged_in"):
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))


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


def file_metadata(path: Path) -> dict:
    stat = path.stat()
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    try:
        created = fmt_time(stat.st_birthtime)
    except AttributeError:
        # On Linux, st_ctime is metadata-change time, not guaranteed creation time.
        created = "系统未提供创建时间" if os.name != "nt" else fmt_time(stat.st_ctime)
    return {
        "name": path.name,
        "path": relative_path(path),
        "size": stat.st_size,
        "size_human": human_size(stat.st_size),
        "mime": mime,
        "extension": path.suffix.lower() or "无扩展名",
        "modified": fmt_time(stat.st_mtime),
        "created": created,
        "accessed": fmt_time(stat.st_atime),
        "is_dir": path.is_dir(),
        "is_text": is_text_file(path),
    }


def list_entries(folder: Path):
    entries = []
    try:
        children = list(folder.iterdir())
    except OSError:
        return entries
    children.sort(key=lambda p: (not p.is_dir(), p.name.casefold()))
    for path in children:
        try:
            stat = path.stat()
            mime = "inode/directory" if path.is_dir() else (mimetypes.guess_type(path.name)[0] or "application/octet-stream")
            entries.append({
                "name": path.name,
                "path": relative_path(path),
                "is_dir": path.is_dir(),
                "size": stat.st_size,
                "size_human": "—" if path.is_dir() else human_size(stat.st_size),
                "modified": fmt_time(stat.st_mtime),
                "mime": mime,
                "ext": "文件夹" if path.is_dir() else (path.suffix[1:].upper() if path.suffix else "FILE"),
                "text": is_text_file(path) if path.is_file() else False,
                "created": file_metadata(path)["created"] if path.is_file() else "—",
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
            if not ipaddress.ip_address(addr.split("%")[0]).is_global:
                return False, "出于安全考虑，只允许拉取公网 IP 地址"
    except (OSError, ValueError):
        return False, "无法解析远程主机地址"
    return True, ""


LOGIN_HTML = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · FileDesk</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(ellipse at 15% 15%,#b8c9ff 0,transparent 38%),radial-gradient(ellipse at 90% 80%,#b6f0e2 0,transparent 36%),#edf1fb;font:15px system-ui;color:#17233e}.glass{width:min(420px,calc(100% - 32px));padding:34px;background:#ffffffa8;border:1px solid #ffffffc9;border-radius:28px;box-shadow:0 28px 80px #263c721c;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}.logo{width:52px;height:52px;display:grid;place-items:center;border-radius:17px;background:linear-gradient(135deg,#667dff,#4a52d9);color:white;font-size:25px;box-shadow:0 10px 28px #5268df55}h1{margin:20px 0 5px;letter-spacing:-.8px}.muted{color:#71809c}input,button{font:inherit}input{width:100%;padding:14px;border:1px solid #d8dfef;background:#ffffffb8;border-radius:13px;margin:10px 0 16px;outline:none}input:focus{border-color:#7387f9;box-shadow:0 0 0 4px #7387f922}button{width:100%;border:0;border-radius:13px;padding:14px;background:linear-gradient(135deg,#6179ff,#4e55d8);color:white;font-weight:750;cursor:pointer;box-shadow:0 8px 22px #5968dc3b}.error{color:#b42318;margin:12px 0}</style></head><body><main class="glass"><div class="logo">▤</div><h1>欢迎使用 FileDesk</h1><p class="muted">登录后管理你的文件空间</p>{% for msg in get_flashed_messages() %}<div class="error">{{msg}}</div>{% endfor %}<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><label>访问密码</label><input type="password" name="password" required autofocus placeholder="输入管理密码"><button>安全登录　→</button></form></main></body></html>'''

PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · FileDesk</title><style>
:root{--ink:#1d2945;--muted:#73809b;--line:#ffffffb8;--blue:#5368e8;--blue2:#edf0ff;--green:#16835b;--red:#bf414c;--glass:rgba(255,255,255,.67)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 6% 5%,#c4d2ff 0,transparent 32%),radial-gradient(ellipse at 92% 88%,#bdeee4 0,transparent 34%),linear-gradient(135deg,#f0f3ff,#edf5f8 55%,#f5f1ff);background-attachment:fixed}a{color:inherit;text-decoration:none}button,input,textarea{font:inherit}.shell{display:flex;min-height:100vh;padding:18px;gap:18px}.glass{background:var(--glass);border:1px solid var(--line);box-shadow:0 18px 55px #34436a12, inset 0 1px #ffffffc9;backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px)}.side{width:238px;flex-shrink:0;border-radius:24px;padding:23px 15px;display:flex;flex-direction:column;gap:27px;align-self:stretch;position:sticky;top:18px;height:calc(100vh - 36px)}.brand{display:flex;align-items:center;gap:11px;padding:0 8px;font-size:19px;font-weight:850;letter-spacing:-.6px}.brandmark{width:42px;height:42px;border-radius:15px;background:linear-gradient(140deg,#7187ff,#4c50d5);color:#fff;display:grid;place-items:center;font-size:22px;box-shadow:0 9px 24px #5c6be34a}.nav-label{font-size:10px;font-weight:850;letter-spacing:1.4px;color:#8c98b0;padding:0 12px;margin-bottom:8px}.navitem{display:flex;gap:12px;align-items:center;padding:12px;border-radius:13px;color:#687692;margin:4px 0;transition:.2s}.navitem:hover,.navitem.active{background:#ffffffa6;color:#4f61dc;box-shadow:0 5px 18px #4557b50d;font-weight:750}.navicon{width:21px;text-align:center;font-size:18px}.sidefoot{margin-top:auto;padding:15px;background:#ffffff75;border:1px solid #ffffffc4;border-radius:17px;color:var(--muted);font-size:12px}.sidefoot b{color:var(--ink)}.main{min-width:0;flex:1;max-width:1700px;margin:0 auto;padding:17px 18px 36px;width:100%}.topline{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:26px}.eyebrow{color:#6676e5;font-size:10px;font-weight:850;letter-spacing:1.8px;text-transform:uppercase}.h1{font-size:clamp(25px,2.3vw,34px);letter-spacing:-1.2px;font-weight:800;margin:4px 0}.subtitle{color:var(--muted)}.avatar{width:43px;height:43px;display:grid;place-items:center;border-radius:16px;background:#ffffffa6;border:1px solid #fff;color:#5666dd;font-weight:850;box-shadow:0 6px 20px #34436a0c}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid #ffffffd6;background:#ffffff8c;color:#34415f;padding:10px 14px;border-radius:12px;font-weight:720;cursor:pointer;white-space:nowrap;transition:transform .18s,box-shadow .18s,background .18s;box-shadow:0 5px 14px #35446c08}.btn:hover{transform:translateY(-1px);background:#ffffffd9;box-shadow:0 9px 20px #35446c13}.btn.primary{background:linear-gradient(135deg,#687df8,#515bdc);color:#fff;border-color:#ffffff7a;box-shadow:0 8px 20px #5a6be43b}.btn.primary:hover{box-shadow:0 11px 25px #5a6be450}.btn.danger{color:var(--red)}.card{background:var(--glass);border:1px solid var(--line);border-radius:21px;box-shadow:0 15px 45px #34436a0d,inset 0 1px #ffffffd6;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);overflow:hidden}.cardhead{padding:19px 22px;border-bottom:1px solid #ffffffb5;display:flex;justify-content:space-between;align-items:center;gap:12px}.cardhead h2{font-size:15px;margin:0}.muted{color:var(--muted)}.crumbs{display:flex;gap:8px;align-items:center;flex-wrap:wrap;color:var(--muted);font-size:12px}.crumbs a:hover{color:var(--blue)}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px;margin-bottom:22px}.stat{padding:19px 21px;background:#ffffff8a;border:1px solid #ffffffd4;border-radius:19px;box-shadow:0 9px 25px #34436a08;backdrop-filter:blur(18px)}.statlabel{font-size:12px;color:var(--muted)}.statnum{font-size:25px;font-weight:850;margin-top:5px;letter-spacing:-.8px}.staticon{float:right;font-size:19px;background:#ffffffad;border:1px solid white;border-radius:12px;padding:7px 9px;color:#5b6de4}.search{min-width:0;flex:1;border:1px solid #ffffffdf;border-radius:12px;padding:11px 14px;font:inherit;background:#ffffff9c;outline:none;box-shadow:inset 0 1px #fff}.search:focus{border-color:#8997ff;box-shadow:0 0 0 4px #687df81b}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;white-space:nowrap}th{text-align:left;color:#8b96aa;font-size:10px;text-transform:uppercase;letter-spacing:.9px;background:#ffffff55;padding:13px 18px;font-weight:850}td{padding:14px 18px;border-top:1px solid #ffffffb7}tbody tr{transition:background .15s}tbody tr:hover td{background:#ffffff70}.filecell{display:flex;align-items:center;gap:12px;min-width:200px}.fileicon{width:40px;height:42px;border-radius:13px;background:#e8edffb8;color:#596ce3;display:grid;place-items:center;font-size:18px;flex-shrink:0;border:1px solid #fff}.fileicon.folder{background:#fff0c9b8;color:#c28c22}.filename{font-weight:760;max-width:350px;overflow:hidden;text-overflow:ellipsis}.subname{font-size:11px;color:#8a96ad;margin-top:2px}.tag{font-size:10px;font-weight:850;letter-spacing:.3px;padding:5px 9px;border-radius:8px;background:#ffffff9c;color:#6a7690;border:1px solid #ffffffb8}.tag.text{background:#e2f7edb8;color:#16835b}.actions{display:flex;gap:4px;align-items:center}.iconbtn{border:1px solid transparent;background:transparent;color:#73809b;padding:7px 9px;border-radius:9px;cursor:pointer;font-size:12px}.iconbtn:hover{background:#ffffffba;color:#4d60df}.flash{padding:12px 15px;border-radius:13px;background:#dff7e9d9;color:#13784d;margin-bottom:16px;border:1px solid #ffffffb8}.flash.error{background:#ffe7e8d9;color:#b42318}.workspace{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:start}.editorbox{background:#ffffff85;border:1px solid #ffffffd6;border-radius:20px;overflow:hidden;box-shadow:0 15px 45px #34436a0d;backdrop-filter:blur(20px)}.editorbar{padding:14px 18px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #ffffffb8;gap:10px}.editor{width:100%;min-height:60vh;border:0;outline:0;resize:vertical;padding:22px;background:#ffffff42;font:13px/1.8 ui-monospace,SFMono-Regular,Consolas,monospace;color:#263450;tab-size:4}.preview{padding:24px;min-height:60vh;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.85 ui-monospace,monospace}.sidecard{padding:19px}.sidecard h3{margin:0 0 14px;font-size:14px}.detailrow{display:flex;justify-content:space-between;gap:14px;padding:11px 0;border-bottom:1px solid #ffffffbf;font-size:12px}.detailrow span:first-child{color:var(--muted);flex-shrink:0}.detailrow b{font-weight:700;text-align:right;overflow-wrap:anywhere;white-space:normal}.formcard{padding:22px}.field{margin:0 0 17px}.field label{display:block;font-weight:750;margin-bottom:7px}.field input,.field textarea{width:100%;padding:12px 13px;border:1px solid #ffffffdf;border-radius:12px;background:#ffffffa1;font:inherit;outline:none}.field input:focus,.field textarea:focus{border-color:#8796ff;box-shadow:0 0 0 4px #687df818}.field small{display:block;color:var(--muted);margin-top:6px}.empty{text-align:center;padding:58px 20px;color:var(--muted)}.emptyicon{font-size:36px;margin-bottom:10px}.notice{padding:13px 15px;background:#fff3d9c9;color:#8d6714;border-radius:12px;font-size:12px;margin-bottom:18px;border:1px solid #ffffffb8}.urlbox{display:flex;gap:8px;margin-top:8px}.urlbox input{min-width:0;flex:1}.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:#5869db;background:#eef0ffcc;border-radius:999px;padding:5px 10px}.empty b{color:var(--ink)}
@media(max-width:1050px){.side{width:76px;padding:20px 10px}.brand{padding:0;justify-content:center}.brandname,.nav-label,.navtext,.sidefoot{display:none}.navitem{justify-content:center;padding:13px 5px}.navicon{font-size:20px}.workspace{grid-template-columns:1fr}.main{padding:15px 5px}.shell{padding:12px;gap:12px}.side{top:12px;height:calc(100vh - 24px)}}
@media(max-width:620px){.topline{align-items:flex-start}.h1{font-size:25px}.stats{grid-template-columns:1fr 1fr;gap:9px}.stat{padding:14px}.stats .stat:last-child{display:none}.cardhead{align-items:flex-start;flex-direction:column}.toolbar{width:100%}.toolbar .btn{flex:1}.avatar{display:none}.shell{padding:8px;gap:8px}.side{width:54px;padding:14px 5px;border-radius:17px}.brandmark{width:36px;height:36px}.main{padding:15px 2px}.editor{min-height:50vh;padding:15px}.filecell{min-width:170px}td,th{padding:12px}.urlbox{flex-direction:column}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
</style></head><body><div class="shell"><aside class="side glass"><a class="brand" href="{{url_for('index')}}"><span class="brandmark">▤</span><span class="brandname">FileDesk</span></a><div><div class="nav-label">WORKSPACE</div><a class="navitem {{'active' if page=='files' else ''}}" href="{{url_for('index')}}"><span class="navicon">▦</span><span class="navtext">全部文件</span></a><a class="navitem {{'active' if page=='pull' else ''}}" href="{{url_for('pull_page')}}"><span class="navicon">↙</span><span class="navtext">远程拉取</span></a></div><div><div class="nav-label">TOOLS</div><a class="navitem" href="{{url_for('index')}}"><span class="navicon">⌕</span><span class="navtext">文件浏览</span></a></div><div class="sidefoot"><b>安全文件空间</b><p>毛玻璃工作台<br>文本可预览、编辑与保存。</p></div></aside>
<main class="main"><div class="topline"><div><div class="eyebrow">PERSONAL WORKSPACE</div><div class="h1">{{title}}</div><div class="subtitle">{{subtitle}}</div></div><div class="avatar">FD</div></div>{% for category,msg in get_flashed_messages(with_categories=true) %}<div class="flash {{'error' if category=='error' else ''}}">{{msg}}</div>{% endfor %}
{% if page=='files' %}<div class="stats"><div class="stat"><span class="staticon">▦</span><div class="statlabel">当前目录项目</div><div class="statnum">{{entries|length}}</div></div><div class="stat"><span class="staticon">⌁</span><div class="statlabel">文本文件</div><div class="statnum">{{text_count}}</div></div><div class="stat"><span class="staticon">◷</span><div class="statlabel">当前目录</div><div class="statnum" style="font-size:15px;margin-top:12px">{{'根目录' if not current else current}}</div></div></div>
<div class="toolbar" style="margin-bottom:18px"><form action="{{url_for('index')}}" method="get" style="display:flex;gap:8px;flex:1;min-width:180px"><input class="search" name="q" value="{{q}}" placeholder="搜索当前目录…"><input type="hidden" name="path" value="{{current}}"><button class="btn" type="submit">⌕ 搜索</button></form><a class="btn primary" href="{{url_for('upload_page',path=current)}}">＋ 上传文件</a><a class="btn" href="{{url_for('pull_page',path=current)}}">↙ 远程拉取</a></div>
<div class="card"><div class="cardhead"><div><h2>文件浏览器</h2><div class="crumbs" style="margin-top:7px">{% for crumb in crumbs %}{% if not loop.first %}<span>›</span>{% endif %}<a href="{{url_for('index',path=crumb.path)}}">{{crumb.name}}</a>{% endfor %}</div></div><span class="pill">● {{entries|length}} 项</span></div><div class="tablewrap"><table><thead><tr><th>名称</th><th>类型 / MIME</th><th>大小</th><th>修改日期</th><th>操作</th></tr></thead><tbody>
{% if parent is not none %}<tr><td><a class="filecell" href="{{url_for('index',path=parent)}}"><span class="fileicon folder">↰</span><span><span class="filename">返回上级目录</span><div class="subname">..</div></span></a></td><td>目录</td><td>—</td><td>—</td><td></td></tr>{% endif %}
{% for e in entries %}<tr><td><div class="filecell"><span class="fileicon {{'folder' if e.is_dir else ''}}">{{'▰' if e.is_dir else ('⌘' if e.text else '▤')}}</span><span><a class="filename" href="{{url_for('index',path=e.path) if e.is_dir else (url_for('edit_file',path=e.path) if e.text else url_for('file_info',path=e.path))}}">{{e.name}}</a><div class="subname">{{'文件夹' if e.is_dir else ('文本 · 可预览编辑' if e.text else '文件 · 可生成下载链接')}}</div></span></div></td><td><span class="tag {{'text' if e.text else ''}}">{{e.ext}}</span><div class="subname" style="max-width:180px;overflow:hidden;text-overflow:ellipsis" title="{{e.mime}}">{{e.mime}}</div></td><td>{{e.size_human}}</td><td>{{e.modified}}</td><td><div class="actions">{% if e.is_dir %}<a class="iconbtn" href="{{url_for('index',path=e.path)}}">打开</a>{% else %}<a class="iconbtn" href="{{url_for('file_info',path=e.path)}}">详情 / 链接</a>{% if e.text %}<a class="iconbtn" href="{{url_for('edit_file',path=e.path)}}">编辑</a>{% endif %}<a class="iconbtn" href="{{url_for('download_file',path=e.path)}}">下载</a>{% endif %}<form method="post" action="{{url_for('delete_file')}}" onsubmit="return confirm('确定删除该项目吗？此操作不可撤销。')"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{e.path}}"><input type="hidden" name="back" value="{{current}}"><button class="iconbtn" type="submit">删除</button></form></div></td></tr>{% endfor %}
{% if not entries %}<tr><td colspan="5"><div class="empty"><div class="emptyicon">▱</div><b>这里还没有文件</b><p>上传文件，或从远程 URL 拉取文件开始使用。</p></div></td></tr>{% endif %}</tbody></table></div></div>
{% elif page=='info' %}<div class="toolbar" style="margin-bottom:16px"><div class="crumbs" style="flex:1"><a href="{{url_for('index',path=parent)}}">全部文件</a><span>›</span><b>{{meta.name}}</b></div><a class="btn" href="{{url_for('download_file',path=meta.path)}}">↓ 直接下载</a>{% if meta.is_text %}<a class="btn" href="{{url_for('preview_file',path=meta.path)}}">预览</a><a class="btn primary" href="{{url_for('edit_file',path=meta.path)}}">编辑文件</a>{% endif %}</div><div class="workspace"><section class="card"><div class="cardhead"><h2>文件信息</h2><span class="tag">{{meta.extension}}</span></div><div style="padding:20px"><div class="filecell" style="margin-bottom:20px"><span class="fileicon">▤</span><div><div class="filename" style="max-width:100%;overflow-wrap:anywhere">{{meta.name}}</div><div class="subname">{{meta.path}}</div></div></div>{% for label,value in [('文件名',meta.name),('相对路径',meta.path),('扩展名',meta.extension),('MIME 类型',meta.mime),('精确大小',meta.size|string+' bytes'),('易读大小',meta.size_human),('修改时间',meta.modified),('创建时间',meta.created),('最近访问',meta.accessed)] %}<div class="detailrow"><span>{{label}}</span><b>{{value}}</b></div>{% endfor %}</div></section><aside class="card sidecard"><h3>下载链接</h3><p class="muted" style="font-size:12px">生成的链接有效期为 {{link_days}} 天，可分享给无需登录的接收者。请把链接视为临时访问凭证。</p><label class="muted" for="download-url" style="font-size:11px">签名下载 URL</label><div class="urlbox"><input id="download-url" class="search" readonly value="{{share_url}}"><button class="btn primary" type="button" onclick="copyLink()">复制链接</button></div><div id="copy-status" class="subname" style="margin-top:8px"></div><p class="muted" style="font-size:12px;margin-top:18px">此链接不要求登录，但过期后会失效。若文件被移动或删除，链接也将不可用。</p></aside></div>
{% elif page=='edit' %}<div class="toolbar" style="margin-bottom:16px"><div class="crumbs" style="flex:1"><a href="{{url_for('index',path=parent)}}">全部文件</a><span>›</span><b>{{file_name}}</b></div><a class="btn" href="{{url_for('file_info',path=path)}}">文件详情 / 下载链接</a><a class="btn" href="{{url_for('preview_file',path=path)}}">预览</a></div><form method="post" action="{{url_for('save_file')}}"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{path}}"><div class="workspace"><div class="editorbox"><div class="editorbar"><div><b>{{file_name}}</b><div class="subname">UTF-8 · 纯文本编辑器</div></div><button class="btn primary" type="submit">保存更改</button></div><textarea class="editor" name="content" spellcheck="false" autocapitalize="off">{{content}}</textarea><div class="editorbar"><span class="muted" id="count">正在编辑</span><span class="muted">保存将覆盖原文件</span></div></div><aside class="card sidecard"><h3>文件信息</h3><div class="detailrow"><span>文件名</span><b>{{file_name}}</b></div><div class="detailrow"><span>文件大小</span><b>{{file_size}}</b></div><div class="detailrow"><span>编码</span><b>UTF-8</b></div><div class="detailrow"><span>编辑模式</span><b>纯文本</b></div><p class="muted" style="font-size:12px;margin-top:16px">HTML、脚本和代码均以纯文本方式编辑，不会执行或渲染。</p></aside></div></form><script>const ed=document.querySelector('.editor'),count=document.querySelector('#count');function upd(){count.textContent=ed.value.length.toLocaleString()+' 个字符 · '+new Blob([ed.value]).size.toLocaleString()+' 字节'}ed.addEventListener('input',upd);upd();</script>
{% elif page=='preview' %}<div class="toolbar" style="margin-bottom:16px"><div class="crumbs" style="flex:1"><a href="{{url_for('index',path=parent)}}">全部文件</a><span>›</span><b>{{file_name}}</b></div><a class="btn" href="{{url_for('file_info',path=path)}}">详情 / 下载链接</a><a class="btn primary" href="{{url_for('edit_file',path=path)}}">编辑文件</a></div><div class="card"><div class="cardhead"><h2>文本预览 · {{file_name}}</h2><span class="tag text">只读</span></div><pre class="preview">{{content}}</pre></div>
{% elif page=='upload' %}<div class="card"><div class="cardhead"><h2>上传文件</h2><span class="tag">UPLOAD</span></div><form class="formcard" method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{current}}"><div class="field"><label>选择文件</label><input type="file" name="files" multiple required><small>支持一次选择多个文件，单个请求最大 {{max_upload}} MB。</small></div><div class="field"><label>上传到目录</label><input value="{{'/' + current if current else '/'}}" readonly></div><button class="btn primary" type="submit">开始上传</button> <a class="btn" href="{{url_for('index',path=current)}}">取消</a></form></div>
{% elif page=='pull' %}<div class="card"><div class="cardhead"><h2>从远程地址拉取</h2><span class="tag">REMOTE FETCH</span></div><form class="formcard" method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><input type="hidden" name="path" value="{{current}}"><div class="field"><label>文件 URL</label><input name="url" type="url" required placeholder="https://example.com/files/data.json"><small>仅允许 HTTP/HTTPS 公网地址；拒绝私有 IP 和重定向以降低 SSRF 风险。</small></div><div class="field"><label>保存文件名（可选）</label><input name="filename" placeholder="留空时使用 URL 中的文件名"></div><div class="field"><label>保存目录</label><input value="{{'/' + current if current else '/'}}" readonly></div><div class="notice">请仅拉取你有权访问和保存的文件。下载内容大小限制为 {{max_pull}} MB。</div><button class="btn primary" type="submit">↙ 拉取并保存</button> <a class="btn" href="{{url_for('index',path=current)}}">返回文件列表</a></form></div>{% endif %}</main></div>
<script>async function copyLink(){const input=document.getElementById('download-url'),status=document.getElementById('copy-status');try{await navigator.clipboard.writeText(input.value);status.textContent='已复制到剪贴板';}catch(e){input.select();document.execCommand('copy');status.textContent='已复制到剪贴板';}}</script></body></html>'''


@app.route("/login", methods=["GET", "POST"])
def login():
    if not PASSWORD:
        return redirect(url_for("index"))
    if request.method == "POST":
        check_csrf()
        if secrets.compare_digest(request.form.get("password", ""), PASSWORD):
            session["logged_in"] = True
            next_url = request.args.get("next", "")
            # Avoid open redirects: only allow local relative URLs.
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))
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
        entries = [entry for entry in entries if q in entry["name"].casefold()]
    parent = None
    if folder != ROOT_DIR:
        parent_path = folder.parent
        parent = relative_path(parent_path) if parent_path != ROOT_DIR else ""
    return render_template_string(PAGE, page="files", title="全部文件", subtitle="管理、查找并维护你的文件",
        entries=entries, current=current, parent=parent, crumbs=breadcrumbs(current), q=q,
        text_count=sum(1 for entry in entries if entry["text"]))


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    current = request.args.get("path", "") if request.method == "GET" else request.form.get("path", "")
    folder = safe_path(current)
    if not folder.is_dir():
        abort(404)
    if request.method == "POST":
        check_csrf()
        saved, errors = 0, []
        for uploaded in request.files.getlist("files"):
            name = secure_filename(uploaded.filename or "")
            if not name:
                continue
            dest = safe_path((relative_path(folder) + "/" if folder != ROOT_DIR else "") + name)
            if dest.exists():
                errors.append(f"{name} 已存在，未覆盖")
                continue
            try:
                uploaded.save(dest)
                saved += 1
            except OSError as exc:
                errors.append(f"{name}: {exc}")
        if saved:
            flash(f"成功上传 {saved} 个文件。")
        for error in errors:
            flash(error, "error")
        return redirect(url_for("index", path=current))
    return render_template_string(PAGE, page="upload", title="上传文件", subtitle="将本地文件保存到工作空间",
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
        name = secure_filename(request.form.get("filename", "").strip() or Path(unquote(parsed.path)).name or "download") or "download"
        dest = safe_path((relative_path(folder) + "/" if folder != ROOT_DIR else "") + name)
        if dest.exists():
            flash("目标文件已存在，请更换文件名，避免意外覆盖。", "error")
            return redirect(url_for("pull_page", path=current))
        tmp = dest.with_name(dest.name + ".part")
        try:
            with requests.get(url, stream=True, timeout=(8, 30), allow_redirects=False, headers={"User-Agent": "FileDesk/1.0"}) as response:
                if 300 <= response.status_code < 400:
                    raise ValueError("远程地址返回重定向，已拒绝；请填写最终文件 URL。")
                response.raise_for_status()
                length = int(response.headers.get("Content-Length", "0") or 0)
                if length > MAX_PULL_MB * 1024 * 1024:
                    raise ValueError(f"文件超过 {MAX_PULL_MB} MB 限制。")
                total = 0
                with tmp.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_PULL_MB * 1024 * 1024:
                            raise ValueError(f"文件超过 {MAX_PULL_MB} MB 限制。")
                        output.write(chunk)
            tmp.replace(dest)
            flash(f"拉取成功：{name}（{human_size(dest.stat().st_size)}）")
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            flash(f"拉取失败：{exc}", "error")
        return redirect(url_for("index", path=current))
    return render_template_string(PAGE, page="pull", title="远程拉取", subtitle="通过 URL 将远程文件保存到当前目录",
        current=relative_path(folder) if folder != ROOT_DIR else "", max_pull=MAX_PULL_MB)


@app.route("/download")
def download_file():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name, conditional=True, max_age=0)


@app.route("/file-info")
def file_info():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    meta = file_metadata(path)
    token = link_signer.dumps({"path": meta["path"]})
    share_path = url_for("shared_download", token=token)
    public_base = os.environ.get("FILE_MANAGER_PUBLIC_BASE_URL", "").rstrip("/")
    share_url = f"{public_base}{share_path}" if public_base else url_for("shared_download", token=token, _external=True)
    parent = relative_path(path.parent) if path.parent != ROOT_DIR else ""
    return render_template_string(PAGE, page="info", title="文件详情", subtitle="查看元数据并生成可分享的下载链接",
        meta=meta, parent=parent, share_url=share_url, link_days=max(1, LINK_MAX_AGE // 86400))


@app.route("/shared/<token>")
def shared_download(token):
    try:
        payload = link_signer.loads(token, max_age=LINK_MAX_AGE)
    except SignatureExpired:
        abort(410, "下载链接已过期，请重新生成。")
    except BadSignature:
        abort(403, "下载链接无效。")
    path = safe_path(payload.get("path", ""))
    if not path.is_file():
        abort(404, "文件不存在或已被删除。")
    return send_file(path, as_attachment=True, download_name=path.name, conditional=True, max_age=0)


@app.route("/edit")
def edit_file():
    path = safe_path(request.args.get("path", ""))
    if not path.is_file():
        abort(404)
    if not is_text_file(path):
        flash("该文件不是可识别的文本文件，仅支持下载。", "error")
        return redirect(url_for("index", path=relative_path(path.parent) if path.parent != ROOT_DIR else ""))
    if path.stat().st_size > EDIT_MAX_MB * 1024 * 1024:
        flash(f"文件超过 {EDIT_MAX_MB} MB 在线编辑限制。", "error")
        return redirect(url_for("file_info", path=relative_path(path)))
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        flash("文件不是 UTF-8 编码，暂不支持在线编辑。", "error")
        return redirect(url_for("index", path=relative_path(path.parent) if path.parent != ROOT_DIR else ""))
    rel = relative_path(path)
    parent = relative_path(path.parent) if path.parent != ROOT_DIR else ""
    return render_template_string(PAGE, page="edit", title="在线编辑", subtitle="编辑文本内容并保存到服务器",
        path=rel, parent=parent, file_name=path.name, content=content, file_size=human_size(path.stat().st_size))


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
    if len(content.encode("utf-8")) > EDIT_MAX_MB * 1024 * 1024:
        abort(413, f"文本文件最大支持 {EDIT_MAX_MB} MB 在线编辑")
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
    return f"请求文件过大。请调整 FILE_MANAGER_MAX_UPLOAD_MB（当前 {MAX_UPLOAD_MB} MB）。", 413


if __name__ == "__main__":
    if not PASSWORD and HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("安全启动已阻止：监听非本机地址时必须设置 FILE_MANAGER_PASSWORD 环境变量。")
    if not SECRET_KEY:
        print("提示：未设置 FILE_MANAGER_SECRET_KEY，重启后之前生成的分享链接会失效。")
    print(f"{APP_NAME} 工作目录：{ROOT_DIR}")
    print(f"访问地址：http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
