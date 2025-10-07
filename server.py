import os, io, time, hmac, hashlib, sqlite3, socket, ipaddress, secrets, json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, UploadFile, WebSocket, WebSocketDisconnect, Depends, Response, status, Cookie
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from passlib.hash import pbkdf2_sha256
import qrcode

# --------------------
# ======= CONFIG =====
# --------------------

# thêm ở đầu file (gần CONFIG) cho tiện chỉnh sau này
ALLOWED_EXTS = {".zip", ".rar", ".apk"}
# Tăng buffer ghi để giảm overhead I/O (đây là buffer RAM, không phải chunk protocol)
MAX_UPLOAD_CHUNK = 32 * 1024 * 1024  # 16MB
SECRET_KEY = os.environ.get("NAS_MINI_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXP_MIN = 24*60  # 24h
QR_EXP_SEC = 120     # QR token expiry: 2 minutes
DB_PATH = "nas_mini.db"
DATA_ROOT = "data"   # per-user folders: data/<username>

# --- Tạo thư mục và DB nếu chưa có ---
os.makedirs(DATA_ROOT, exist_ok=True)
if not os.path.exists(DB_PATH):
    open(DB_PATH, "w").close()

app = FastAPI(title="NAS Mini (Local)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

# -------------------------
# ====== SIMPLE DB =========
# -------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS qr_tokens(
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expire_at INTEGER NOT NULL
    )""")
    conn.commit()
    conn.close()
init_db()

# -------------------------
# ===== AUTH HELPERS ======
# -------------------------
def create_jwt(username: str):
    exp = datetime.utcnow() + timedelta(minutes=JWT_EXP_MIN)
    payload = {"sub": username, "exp": int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)

def verify_jwt(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return data.get("sub")
    except JWTError:
        return None

def require_user(request: Request) -> Optional[str]:
    token = request.cookies.get("session")
    if not token:
        return None
    username = verify_jwt(token)
    return username

def set_session_cookie(resp: Response, token: str):
    # HttpOnly cookie for session
    resp.set_cookie("session", token, httponly=True, samesite="lax")

# -------------------------
# ===== WEBSOCKETS =========
# -------------------------
class Hub:
    # connections keyed by username -> set of websockets
    rooms: dict[str, set] = {}

    @classmethod
    async def join(cls, username: str, ws: WebSocket):
        await ws.accept()
        cls.rooms.setdefault(username, set()).add(ws)

    @classmethod
    def leave(cls, username: str, ws: WebSocket):
        try:
            cls.rooms.get(username, set()).discard(ws)
        except:
            pass

    @classmethod
    async def broadcast(cls, username: str, message: dict):
        dead = []
        for ws in list(cls.rooms.get(username, set())):
            try:
                await ws.send_json(message)
            except:
                dead.append(ws)
        for ws in dead:
            cls.rooms.get(username, set()).discard(ws)

# -------------------------
# ====== UTILITIES =========
# -------------------------
def lan_ip() -> str:
    # try to detect primary LAN IPv4
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def user_dir(username: str) -> str:
    p = os.path.join(DATA_ROOT, username)
    os.makedirs(p, exist_ok=True)
    return p

def list_user_files(username: str):
    p = user_dir(username)
    files = []
    for name in sorted(os.listdir(p)):
        full = os.path.join(p, name)
        if os.path.isfile(full):
            stat = os.stat(full)
            files.append({
                "name": name,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime)
            })
    return files

def human_bytes(n:int):
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

# -------------------------
# ======= PAGES =============
# -------------------------
INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>NAS Mini • Local</title>
<style>
:root{
  --bg: #0b1020; --text:#e4ecff; --panel:#121936; --muted:#8aa1ff;
  --acc:#6aa3ff; --good:#22c55e; --bad:#ef4444; --warn:#f59e0b;
  --card: rgba(255,255,255,0.04);
}
:root.light{
  --bg:#f6f8ff; --text:#0b1020; --panel:#ffffff; --muted:#4c5bd6;
  --acc:#3366ff; --good:#16a34a; --bad:#dc2626; --warn:#d97706;
  --card: rgba(0,0,0,0.04);
}
*{box-sizing:border-box}
html,body{height:100%; margin:0; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; background:var(--bg); color:var(--text); transition: background .4s ease, color .4s ease}
a{color:var(--muted); text-decoration:none}
header{display:flex; align-items:center; gap:12px; padding:16px 18px; position:sticky; top:0; backdrop-filter:saturate(180%) blur(14px); background:linear-gradient(180deg, rgba(0,0,0,.35), rgba(0,0,0,0)) }
.logo{display:flex; align-items:center; gap:10px; font-weight:700;}
.badge{font-size:12px; padding:4px 8px; border-radius:999px; background:var(--card); color:var(--muted)}
.wrap{max-width:1100px; margin:0 auto; padding:18px}
.grid{display:grid; grid-template-columns: 1fr; gap:18px}
@media(min-width:900px){ .grid{ grid-template-columns: 1.2fr .8fr } }
.card{background:var(--card); border-radius:18px; padding:16px; box-shadow: 0 6px 22px rgba(0,0,0,.18);}
h2{margin:0 0 10px 0; font-size:18px}
.btn{border:0; border-radius:14px; padding:10px 14px; cursor:pointer; background:var(--acc); color:white; font-weight:600; transition: transform .06s ease, opacity .2s ease}
.btn:active{ transform: translateY(1px) }
.btn.ghost{ background:transparent; color:var(--text); border:1px solid rgba(255,255,255,.14) }
.row{display:flex; gap:10px; align-items:center; flex-wrap:wrap}

.progress{height:10px; border-radius:999px; background:rgba(255,255,255,.12); overflow:hidden}
.progress > div{height:100%; width:0%; background:linear-gradient(90deg, var(--acc), #00d4ff); transition: width .2s ease}

.zone{border:2px dashed rgba(255,255,255,.2); border-radius:16px; padding:20px; text-align:center; opacity:.9}
.zone.drag{ border-color: var(--muted); background: rgba(255,255,255,.04) }

.list{width:100%; border-collapse:collapse}
.list thead th{font-size:12px; text-transform:uppercase; letter-spacing:.06em; text-align:left; opacity:.7; padding:8px}
.list tbody td{padding:10px 8px; border-top:1px solid rgba(255,255,255,.08)}
.cell-actions{display:flex; gap:8px; flex-wrap:wrap}

.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px}
.mini{font-size:12px; opacity:.8}
.right{margin-left:auto}
.hidden{display:none !important}

.fade-in{ animation: fade .4s ease both }
@keyframes fade{ from{opacity:0; transform: translateY(8px)} to{opacity:1; transform:none} }

.switch{display:inline-flex; align-items:center; gap:8px; cursor:pointer}
.switch input{display:none}
.switch span{width:44px; height:26px; background:rgba(255,255,255,.2); border-radius:999px; position:relative; transition:.25s}
.switch span::after{content:""; width:20px; height:20px; background:white; border-radius:50%; position:absolute; left:3px; top:3px; transition:.25s}
:root.light .switch span{background:rgba(0,0,0,.18)}
:root.light .switch span::after{left:21px}

.qr-wrap{display:flex; align-items:center; gap:10px; flex-wrap:wrap}
.qr{border-radius:12px; background:var(--panel); padding:8px}

.tip{font-size:12px; opacity:.8}

footer{padding:28px; text-align:center; opacity:.6}
</style>
</head>
<body>
<header>
  <div class="logo"><svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 12h16M4 17h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> NAS Mini</div>
  <span class="badge" id="who"></span>
  <div class="right row">
    <label class="switch"><input id="themeToggle" type="checkbox"/><span></span></label>
    <button class="btn ghost" id="logoutBtn">Đăng xuất</button>
  </div>
</header>

<div class="wrap">
  <div class="grid">
    <div class="card fade-in">
      <h2>Upload</h2>
      <div class="zone" id="dropZone">Kéo thả file vào đây hoặc <input type="file" id="fileInput" multiple></div>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="startBtn">Bắt đầu Upload</button>
        <button class="btn ghost" id="pauseBtn">Tạm dừng</button>
        <span class="mini" id="speed">Tốc độ: 0 MB/s • 0 Mbps</span>
        <span class="mini" id="status"></span>
      </div>
      <div class="progress" style="margin-top:10px"><div id="bar"></div></div>
      <div class="mini mono" id="progText">0% (0 / 0)</div>
    </div>

    <div class="card fade-in">
      <h2>Đăng nhập nhanh bằng QR</h2>
      <div class="qr-wrap">
        <button class="btn" id="genQR">Tạo QR</button>
        <button class="btn ghost hidden" id="hideQR">Ẩn QR</button>
        <img id="qrImg" class="qr hidden" width="150" height="150"/>
      </div>
      <div class="tip">Mở camera trên điện thoại, quét QR để auto login cùng tài khoản này. Token tự hết hạn sau 2 phút.</div>
    </div>
  </div>

  <div class="card fade-in" style="margin-top:18px">
    <div class="row">
      <h2 style="margin-right:auto">Files của tôi</h2>
      <button class="btn ghost" id="refreshBtn">Refresh</button>
    </div>
    <table class="list" id="fileTable">
      <thead><tr><th>Tên file</th><th>Kích thước</th><th>Cập nhật</th><th>Hành động</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<footer class="mini">NAS Mini • chạy trên mạng LAN của bạn – nhanh như NAS tại nhà</footer>

<script>
const $ = sel => document.querySelector(sel)
let filesQueue = []
let uploading = false
let controller = null
let ws = null
let username = ""
let theme = localStorage.getItem("theme") || "dark"
if(theme==="light") document.documentElement.classList.add("light")
$("#themeToggle").checked = (theme==="light")
$("#themeToggle").onchange = () => {
  document.documentElement.classList.toggle("light")
  localStorage.setItem("theme", document.documentElement.classList.contains("light") ? "light" : "dark")
}

async function me(){
  const r = await fetch('/api/me')
  const j = await r.json()
  if(!j.ok){ location.href="/auth"; return }
  username = j.username
  $("#who").textContent = "@" + username
  connectWS()
  refreshList()
}
me()

function connectWS(){
  try {
    ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      if(msg.type === "progress"){
        // Nếu server có gửi đủ thông tin tiến độ thì cập nhật %
        if (msg.total && msg.bytes) {
          const pct = (msg.bytes / msg.total) * 100;
          setProgress(pct, msg.bytes, msg.total, msg.speedMBs || 0, msg.speedMbps || 0);
        } else {
          // Nếu server chỉ gửi tốc độ (không gửi total) thì chỉ update tốc độ
          $("#speed").textContent = `Tốc độ: ${(msg.speedMBs||0).toFixed(2)} MB/s • ${(msg.speedMbps||0).toFixed(2)} Mbps`;
        }
      }
      if(msg.type === "refresh"){
        refreshList();
      }
    }
  } catch(e){
    console.error("WS error:", e);
  }
}

function setProgress(pct, bytes, total, speedMBs, speedMbps){
  $("#bar").style.width = (pct.toFixed(2)) + "%"
  $("#progText").textContent = `${pct.toFixed(1)}% (${fmtBytes(bytes)} / ${fmtBytes(total)})`
  $("#speed").textContent = `Tốc độ: ${speedMBs.toFixed(2)} MB/s • ${speedMbps.toFixed(2)} Mbps`
}

function fmtBytes(n){
  const u=["B","KB","MB","GB","TB"]
  let i=0; let x=n
  while(x>=1024 && i<u.length-1){ x/=1024; i++ }
  return x.toFixed(2)+" "+u[i]
}

// Drag & drop
$("#dropZone").addEventListener("dragover", e=>{e.preventDefault(); $("#dropZone").classList.add("drag")})
$("#dropZone").addEventListener("dragleave", e=>{$("#dropZone").classList.remove("drag")})
$("#dropZone").addEventListener("drop", e=>{
  e.preventDefault(); $("#dropZone").classList.remove("drag")
  filesQueue = Array.from(e.dataTransfer.files)
  $("#status").textContent = `${filesQueue.length} file đã chọn`
})
$("#fileInput").addEventListener("change", e=>{
  filesQueue = Array.from(e.target.files)
  $("#status").textContent = `${filesQueue.length} file đã chọn`
})

$("#pauseBtn").onclick = ()=>{
  if(uploading && controller){ controller.abort(); uploading=false; $("#status").textContent="Đã tạm dừng." }
}

$("#startBtn").onclick = async ()=>{
  if(!filesQueue.length){ alert("Chọn file trước nhé!"); return }
  uploading = true
  controller = new AbortController()
  for(const f of filesQueue){
    if(!uploading) break
    await uploadOne(f, controller.signal)
  }
  uploading=false
  controller=null
  $("#status").textContent="Hoàn tất hoặc đã dừng."
}

async function uploadOne(file, signal){
  // gửi theo 1 stream duy nhất (không chia chunk) để tận dụng băng thông
  const form = new FormData()
  form.append("file", file)
  const started = performance.now()
  let lastBytes = 0
  let sentBytes = 0

  const xhr = new XMLHttpRequest()
  xhr.open("POST", "/api/upload")
  xhr.upload.onprogress = (e)=>{
    if(e.lengthComputable){
      const now = performance.now()
      sentBytes = e.loaded
      const dt = (now - started) / 1000
      const speedMBs = (sentBytes / (1024*1024)) / (dt || 1)
      const speedMbps = speedMBs * 8
      const pct = (sentBytes / e.total) * 100
      setProgress(pct, sentBytes, e.total, speedMBs, speedMbps)
    }
  }
  xhr.onload = ()=>{
    refreshList()
    // reset thanh tiến độ nhưng giữ số liệu hiển thị (theo yêu cầu: không mất chỗ % khi xong)
    $("#status").textContent = xhr.status===200 ? `Đã upload: ${file.name}` : `Lỗi upload: ${file.name}`
  }
  xhr.onerror = ()=>{ $("#status").textContent = "Lỗi mạng khi upload." }
  xhr.onabort = ()=>{ $("#status").textContent = "Đã tạm dừng."; }
  if(signal){
    signal.addEventListener("abort", ()=>{ try{xhr.abort()}catch(e){} })
  }
  xhr.send(form)
}

// Files table
async function refreshList(){
  const r = await fetch("/api/files")
  const j = await r.json()
  const tb = $("#fileTable tbody")
  tb.innerHTML = ""
  for(const it of j.files){
    const tr = document.createElement("tr")
    tr.innerHTML = `<td class="mono">${it.name}</td>
    <td>${fmtBytes(it.size)}</td>
    <td>${new Date(it.mtime*1000).toLocaleString()}</td>
    <td class="cell-actions">
      <a class="btn" href="/api/download?name=${encodeURIComponent(it.name)}">Tải xuống</a>
      <button class="btn ghost" data-del="${it.name}">Xoá</button>
    </td>`
    tb.appendChild(tr)
  }
  tb.querySelectorAll("button[data-del]").forEach(btn=>{
    btn.onclick = async ()=>{
      const name = btn.getAttribute("data-del")
      if(!confirm("Xoá file này?")) return
      const r = await fetch("/api/delete?name="+encodeURIComponent(name), {method:"POST"})
      refreshList()
    }
  })
}

// QR login
$("#genQR").onclick = async ()=>{
  const r = await fetch("/api/qr/create")
  const j = await r.json()
  if(!j.ok){ alert(j.error||"Không tạo được QR"); return }
  $("#qrImg").src = "data:image/png;base64," + j.png_b64
  $("#qrImg").classList.remove("hidden")
  $("#hideQR").classList.remove("hidden")
}
$("#hideQR").onclick = ()=>{
  $("#qrImg").classList.add("hidden")
  $("#hideQR").classList.add("hidden")
}

// logout
$("#logoutBtn").onclick = async ()=>{
  await fetch("/api/logout", {method:"POST"})
  location.href="/auth"
}

// On scroll animations (nhẹ nhàng)
const onScroll = ()=>{
  document.querySelectorAll('.fade-in').forEach(el=>{
    const rect = el.getBoundingClientRect()
    if(rect.top < innerHeight - 60) el.style.opacity=1
  })
}
document.addEventListener('scroll', onScroll)
</script>
</body>
</html>
"""

AUTH_HTML = r"""<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Đăng nhập • NAS Mini</title>
<style>
:root{ --bg:#0b1020; --text:#e4ecff; --card:rgba(255,255,255,.05); --acc:#6aa3ff}
:root.light{ --bg:#eef3ff; --text:#0b1020; --card:rgba(0,0,0,.06); --acc:#3366ff}
html,body{height:100%; margin:0; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; background:var(--bg); color:var(--text); transition:.35s}
.wrap{min-height:100%; display:flex; align-items:center; justify-content:center; padding:24px}
.card{width:100%; max-width:420px; background:var(--card); padding:22px; border-radius:18px; box-shadow: 0 10px 30px rgba(0,0,0,.25)}
h1{margin:0 0 10px 0}
label{display:block; font-size:13px; opacity:.8; margin-top:10px}
input{width:100%; padding:12px 12px; border-radius:12px; border:1px solid rgba(255,255,255,.2); background:transparent; color:var(--text); outline:none}
.row{display:flex; gap:10px; align-items:center; margin-top:14px}
.btn{border:0; padding:10px 14px; border-radius:12px; background:var(--acc); color:white; font-weight:700; cursor:pointer}
.btn.ghost{background:transparent; color:var(--text); border:1px solid rgba(255,255,255,.18)}
.mini{font-size:12px; opacity:.8}
.switch{display:inline-flex; align-items:center; gap:8px; cursor:pointer}
.switch input{display:none}
.switch span{width:44px; height:26px; background:rgba(255,255,255,.2); border-radius:999px; position:relative; transition:.25s}
.switch span::after{content:""; width:20px; height:20px; background:white; border-radius:50%; position:absolute; left:3px; top:3px; transition:.25s}
:root.light .switch span{background:rgba(0,0,0,.18)}
:root.light .switch span::after{left:21px}
.err{color:#ef4444; min-height:20px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div style="display:flex; gap:10px; align-items:center; justify-content:space-between">
      <h1>NAS Mini</h1>
      <label class="switch" title="Đổi theme">
        <input id="themeToggle" type="checkbox"/><span></span>
      </label>
    </div>
    <div class="mini">Đăng nhập để vào trang chính (chưa login sẽ tự chuyển về trang này).</div>

    <div style="margin-top:12px">
      <label>Tên đăng nhập</label>
      <input id="user" placeholder="username" autocomplete="username"/>
      <label>Mật khẩu</label>
      <input id="pass" type="password" placeholder="••••••••" autocomplete="current-password"/>
      <div class="row">
        <button class="btn" id="loginBtn">Đăng nhập</button>
        <button class="btn ghost" id="regBtn">Đăng ký</button>
      </div>
      <div class="err" id="err"></div>
    </div>
    <div class="mini">Đăng ký: mỗi IP chỉ tạo tối đa 2 tài khoản.</div>
  </div>
</div>
<script>
let theme = localStorage.getItem("theme") || "dark"
if(theme==="light") document.documentElement.classList.add("light")
document.querySelector("#themeToggle").checked = (theme==="light")
document.querySelector("#themeToggle").onchange = ()=>{
  document.documentElement.classList.toggle("light")
  localStorage.setItem("theme", document.documentElement.classList.contains("light") ? "light":"dark")
}
const $ = s=>document.querySelector(s)
const err = $("#err")
$("#loginBtn").onclick = async ()=>{
  err.textContent=""
  const r = await fetch("/api/login", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({username: $("#user").value.trim(), password: $("#pass").value})})
  const j = await r.json()
  if(j.ok){ location.href="/" } else { err.textContent = j.error || "Sai thông tin đăng nhập" }
}
$("#regBtn").onclick = async ()=>{
  err.textContent=""
  const r = await fetch("/api/register", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({username: $("#user").value.trim(), password: $("#pass").value})})
  const j = await r.json()
  if(j.ok){ location.href="/" } else { err.textContent = j.error || "Đăng ký thất bại" }
}
// Gắn sự kiện cho nút Refresh
$("#refreshBtn").onclick = ()=> refreshList()
</script>
</body></html>
"""

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: Optional[str] = Depends(require_user)):
    if not user:
        return HTMLResponse("", status_code=307, headers={"Location": "/auth"})
    return HTMLResponse(INDEX_HTML)

@app.get("/auth", response_class=HTMLResponse)
async def auth_page(request: Request, user: Optional[str] = Depends(require_user)):
    if user:
        return HTMLResponse("", status_code=307, headers={"Location": "/"})
    return HTMLResponse(AUTH_HTML)

# -------------------------
# ===== API: AUTH ==========
# -------------------------
@app.post("/api/register")
async def api_register(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return JSONResponse({"ok": False, "error": "Thiếu username/password"}, status_code=400)

    # limit: per IP only 2 accounts
    ip = request.client.host
    conn = db(); c = conn.cursor()
    # count users created by this IP: we store in users table? Not stored; quick check: count of users with username suffix? Simpler approach:
    # We'll maintain a meta table keyed by ip
    c.execute("""CREATE TABLE IF NOT EXISTS ip_quota(ip TEXT PRIMARY KEY, count INTEGER)""")
    conn.commit()
    c.execute("SELECT count FROM ip_quota WHERE ip=?", (ip,))
    row = c.fetchone()
    cnt = row["count"] if row else 0
    if cnt >= 2:
        conn.close()
        return JSONResponse({"ok": False, "error": "Mỗi IP chỉ được tạo tối đa 2 tài khoản"}, status_code=403)

    pw_hash = pbkdf2_sha256.hash(password)
    try:
        c.execute("INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
                  (username, pw_hash, datetime.utcnow().isoformat()))
        # bump quota
        if row:
            c.execute("UPDATE ip_quota SET count=count+1 WHERE ip=?", (ip,))
        else:
            c.execute("INSERT INTO ip_quota(ip, count) VALUES(?,1)", (ip,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return JSONResponse({"ok": False, "error": "Username đã tồn tại"}, status_code=409)
    finally:
        conn.close()

    os.makedirs(user_dir(username), exist_ok=True)
    token = create_jwt(username)
    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, token)
    return resp

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    conn = db(); c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row or not pbkdf2_sha256.verify(password, row["password_hash"]):
        return JSONResponse({"ok": False, "error": "Sai username hoặc mật khẩu"}, status_code=401)
    token = create_jwt(username)
    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, token)
    return resp

@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp

@app.get("/api/me")
async def api_me(user: Optional[str] = Depends(require_user)):
    if not user: return JSONResponse({"ok": False})
    return JSONResponse({"ok": True, "username": user})

# -------------------------
# ===== API: QR LOGIN ======
# -------------------------
def new_qr_token(username: str):
    token = secrets.token_urlsafe(24)
    expire_at = int(time.time()) + QR_EXP_SEC
    conn = db(); c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO qr_tokens(token, username, expire_at) VALUES(?,?,?)",
              (token, username, expire_at))
    conn.commit(); conn.close()
    return token, expire_at

@app.get("/api/qr/create")
async def api_qr_create(user: Optional[str] = Depends(require_user)):
    if not user: return JSONResponse({"ok": False, "error":"Chưa đăng nhập"}, status_code=401)
    token, exp = new_qr_token(user)
    # QR chứa URL claim
    url = f"{get_base_url()}/api/qr/claim?token={token}"
    img = qrcode.make(url)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    import base64
    b64 = base64.b64encode(buf.getvalue()).decode()
    return JSONResponse({"ok": True, "token": token, "expire": exp, "png_b64": b64})

def get_base_url():
    # derive base URL from LAN IP + uvicorn port (default 8000)
    host = lan_ip()
    port = int(os.environ.get("PORT", "8000"))
    return f"http://{host}:{port}"

@app.get("/api/qr/claim")
async def api_qr_claim(token: str, response: Response):
    now = int(time.time())
    conn = db(); c = conn.cursor()
    c.execute("SELECT username, expire_at FROM qr_tokens WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return PlainTextResponse("QR không hợp lệ", status_code=400)
    if row["expire_at"] < now:
        conn.close()
        return PlainTextResponse("QR đã hết hạn", status_code=400)
    username = row["username"]
    # one-time: delete token
    c.execute("DELETE FROM qr_tokens WHERE token=?", (token,))
    conn.commit(); conn.close()
    # set session cookie => auto login
    tok = create_jwt(username)
    response = HTMLResponse("<script>location.href='/'</script>")
    set_session_cookie(response, tok)
    return response

# -------------------------
# ===== API: FILES =========
# -------------------------
@app.get("/api/files")
async def api_files(user: Optional[str] = Depends(require_user)):
    if not user:
        return JSONResponse({"ok": False}, status_code=401)
    return JSONResponse({"ok": True, "files": list_user_files(user)})



from fastapi import UploadFile, File

@app.post("/api/upload")
async def api_upload(
    user: Optional[str] = Depends(require_user),
    file: UploadFile = File(...)
):
    if not user:
        return JSONResponse({"ok": False}, status_code=401)

    if not file or not file.filename:
        return JSONResponse({"ok": False, "error": "Thiếu file"}, status_code=400)

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()

    # Chỉ cho phép file nén
    if ext not in ALLOWED_EXTS:
        return JSONResponse({
            "ok": False,
            "error": "Chỉ hỗ trợ file nén (.zip, .rar, .apk)"
        }, status_code=400)

    target_dir = user_dir(user)
    os.makedirs(target_dir, exist_ok=True)
    target = os.path.join(target_dir, filename)

    # Stream 1 phát từ request -> file (một request duy nhất)
    total = 0
    t0 = time.time()
    with open(target, "wb") as f:
        while True:
            chunk = await file.read(MAX_UPLOAD_CHUNK)  # buffer I/O, không phải chia nhiều request
            if not chunk:
                break
            f.write(chunk)
            total += len(chunk)

            # tốc độ realtime để các thiết bị khác cùng tài khoản thấy
            dt = max(time.time() - t0, 1e-6)
            speedMBs = (total / (1024 * 1024)) / dt
            await Hub.broadcast(user, {
                "type": "progress",
                "percent": 0,        # không cố tính % (multipart có overhead), client tự lo phần trăm bằng XHR
                "bytes": total,
                "total": 0,
                "speedMBs": speedMBs,
                "speedMbps": speedMBs * 8
            })

    await Hub.broadcast(user, {"type": "refresh"})
    return JSONResponse({"ok": True, "message": f"Đã upload {filename}"})


@app.get("/api/download")
async def api_download(name: str, user: Optional[str] = Depends(require_user)):
    if not user:
        return PlainTextResponse("Unauthorized", status_code=401)
    p = os.path.join(user_dir(user), name)
    if not os.path.isfile(p):
        return PlainTextResponse("Not found", status_code=404)
    return FileResponse(p, filename=name)


@app.post("/api/delete")
async def api_delete(name: str, user: Optional[str] = Depends(require_user)):
    if not user:
        return JSONResponse({"ok": False}, status_code=401)
    p = os.path.join(user_dir(user), name)
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
    await Hub.broadcast(user, {"type": "refresh"})
    return JSONResponse({"ok": True})
# -------------------------
# ===== WS: PROGRESS =======
# -------------------------
@app.websocket("/ws")
async def ws_main(websocket: WebSocket):
    # accept only if has valid cookie session
    await websocket.accept()  # accept first to read cookies (Starlette quirk)
    cookie = websocket.cookies.get("session")
    user = verify_jwt(cookie) if cookie else None
    if not user:
        await websocket.close(code=4401)
        return
    try:
        await Hub.join(user, websocket)
        while True:
            # keep alive; clients don't need to send
            await websocket.receive_text()
    except WebSocketDisconnect:
        Hub.leave(user, websocket)
    except Exception:
        Hub.leave(user, websocket)

# -------------------------
# ===== MIDDLEWARE REDIR ===
# -------------------------
@app.middleware("http")
async def require_auth_mw(request: Request, call_next):
    # gate: any path not /auth or /api/login/register/qr/claim must require login
    public_paths = ["/auth", "/api/login", "/api/register", "/api/qr/claim"]
    if request.url.path.startswith(tuple(public_paths)) or request.url.path.startswith("/static") or request.url.path.startswith("/api/lan"):
        return await call_next(request)
    # allow root "/" (handled in route) and /api/me etc.
    # If not logged in and requesting non-public page -> redirect to /auth
    token = request.cookies.get("session")
    if (request.url.path not in ["/", "/api/me"]) and (not token or not verify_jwt(token)):
        if request.method == "GET" and not request.url.path.startswith("/api"):
            return HTMLResponse("", status_code=307, headers={"Location": "/auth"})
    return await call_next(request)

# -------------------------
# ===== Extra: LAN link ====
# -------------------------
@app.get("/api/lan")
async def api_lan():
    return {"host": lan_ip(), "url": f"{get_base_url()}/"}

