#!/usr/bin/env python3
"""
森空岛自动签到 — 防漏签系统
支持多账号、按游戏筛选、SMTP 邮件通知

用法:
  python main.py --mode full      主力签到
  python main.py --mode retry     补签（检测上午结果）
  python main.py --mode check     看门狗（全天零签到告警）
"""

import argparse
import hashlib
import hmac
import json
import os
import smtplib
import sys
import time
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests

# ── 路径 ──────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
STATE_FILE = BASE_DIR / ".checkin_state.json"


# ═══════════════════════════════════════════════════════════
# 配置加载
# ═══════════════════════════════════════════════════════════

def load_config():
    if "SKLAND_CONFIG" in os.environ:
        return json.loads(os.environ["SKLAND_CONFIG"])
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    print("[ERROR] 找不到 config.json，且未设置 SKLAND_CONFIG 环境变量")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════
# 森空岛 API 核心
# ═══════════════════════════════════════════════════════════

# 旧版请求头 — 新版有验参，旧版可直接绕过
LOGIN_HEADER = {
    "User-Agent": "Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0",
    "Accept-Encoding": "gzip",
    "Connection": "close",
}

# API 请求头基础（cred 在外面填充）
API_HEADER = {
    "cred": "",
    "User-Agent": "Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0",
    "Accept-Encoding": "gzip",
    "Connection": "close",
}

# 签名头 — 四个字段，顺序必须保持（platform, timestamp, dId, vName）
SIGN_HEADER_TEMPLATE = {"platform": "1", "timestamp": "", "dId": "de9759a5afaa634f", "vName": "1.0.1"}

APP_CODE = "4ca99fa6b56cc2ba"


def _generate_sign(token: str, path: str, body_or_query: str) -> tuple[str, dict]:
    """生成森空岛请求签名

    签名算法: HMAC-SHA256(path + body_or_query + timestamp + header_json, token) → MD5
    - path: API 路径（不含域名）
    - body_or_query: GET 时用 query string, POST 时用 json.dumps(body)
    """
    token_bytes = token.encode("utf-8")
    timestamp = str(int(time.time()) - 2)
    header_ca = SIGN_HEADER_TEMPLATE.copy()
    header_ca["timestamp"] = timestamp
    header_ca_str = json.dumps(header_ca, separators=(",", ":"))
    sign_str = path + body_or_query + timestamp + header_ca_str
    hex_s = hmac.new(token_bytes, sign_str.encode("utf-8"), hashlib.sha256).hexdigest()
    md5 = hashlib.md5(hex_s.encode("utf-8")).hexdigest()
    return md5, header_ca


def _api_get(cred: str, sign_token: str, path: str, query: str = "") -> dict:
    """带签名的 GET 请求"""
    sign, header_ca = _generate_sign(sign_token, path, query)
    url = f"https://zonai.skland.com{path}"
    if query:
        url += f"?{query}"
    headers = API_HEADER.copy()
    headers["cred"] = cred
    headers["sign"] = sign
    for k, v in header_ca.items():
        headers[k] = v
    r = requests.get(url, headers=headers, timeout=30)
    return r.json()


def _api_post(cred: str, sign_token: str, path: str, body: dict) -> dict:
    """带签名的 POST 请求（form-encoded）"""
    body_json = json.dumps(body, separators=(",", ":"))
    sign, header_ca = _generate_sign(sign_token, path, body_json)
    url = f"https://zonai.skland.com{path}"
    headers = API_HEADER.copy()
    headers["cred"] = cred
    headers["sign"] = sign
    for k, v in header_ca.items():
        headers[k] = v
    # CRITICAL: 使用 data= 而非 json=，否则签名校验失败
    r = requests.post(url, headers=headers, data=body, timeout=30)
    return r.json()


def get_cred(token: str) -> tuple[str, str]:
    """
    Token → Grant Code → Cred
    返回 (cred, sign_token)
    """
    # Step 1: 获取 OAuth2 授权代码（必须用 json=）
    grant_resp = requests.post(
        "https://as.hypergryph.com/user/oauth2/v2/grant",
        json={"appCode": APP_CODE, "token": token, "type": 0},
        timeout=30,
    ).json()

    if grant_resp.get("status") != 0:
        raise Exception(f"获取授权代码失败: {grant_resp}")

    code = grant_resp["data"]["code"]

    # Step 2: 用授权代码换取 Cred（必须用 json=）
    cred_resp = requests.post(
        "https://zonai.skland.com/api/v1/user/auth/generate_cred_by_code",
        json={"code": code, "kind": 1},
        timeout=30,
    ).json()

    if cred_resp.get("code") != 0:
        raise Exception(f"获取 Cred 失败: {cred_resp}")

    return cred_resp["data"]["cred"], cred_resp["data"]["token"]


def get_bindings(cred: str, sign_token: str) -> list[dict]:
    """获取账号绑定的游戏角色列表"""
    data = _api_get(cred, sign_token, "/api/v1/game/player/binding")
    if data.get("code") != 0:
        raise Exception(f"获取绑定列表失败: {data}")

    bindings = []
    for game in data["data"]["list"]:
        app_code = game["appCode"]
        app_name = game.get("appName", app_code)
        for bind in game["bindingList"]:
            if not bind.get("isDelete", False):
                bindings.append({
                    "appCode": app_code,
                    "appName": app_name,
                    "uid": bind["uid"],
                    "gameId": bind["channelMasterId"],
                    "nickName": bind.get("nickName", ""),
                    "channelName": bind.get("channelName", ""),
                })
    return bindings


def do_attendance(cred: str, sign_token: str, uid: str, game_id: str) -> dict:
    """执行签到 — 先 GET 检查今日状态，未签再 POST"""
    import urllib.parse

    # Step 1: GET 查询今日签到记录
    query = urllib.parse.urlencode({"uid": uid, "gameId": game_id})
    record_data = _api_get(cred, sign_token, "/api/v1/game/attendance", query)

    # 检查今日是否已签到
    if record_data.get("code") == 0:
        records = record_data.get("data", {}).get("records", [])
        today_start = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d")))
        for rec in records:
            if int(rec.get("ts", 0)) >= today_start:
                return {"code": 10001, "message": "今日已签到"}

    # Step 2: POST 签到
    body = {"uid": uid, "gameId": game_id}
    data = _api_post(cred, sign_token, "/api/v1/game/attendance", body)
    return data


# ═══════════════════════════════════════════════════════════
# 邮件通知
# ═══════════════════════════════════════════════════════════

def send_mail(subject: str, body_text: str):
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    to_addr = os.environ.get("SMTP_TO")

    missing = [k for k, v in {
        "SMTP_HOST": host, "SMTP_PORT": port,
        "SMTP_USER": user, "SMTP_PASSWORD": password, "SMTP_TO": to_addr,
    }.items() if not v]

    if missing:
        print(f"[WARN] SMTP 未配置 ({', '.join(missing)})，跳过邮件通知")
        return

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    try:
        port_int = int(port or "465")
        if port_int == 465:
            server = smtplib.SMTP_SSL(host, port_int, timeout=15)
        else:
            server = smtplib.SMTP(host, port_int, timeout=15)
            server.starttls()
        server.login(user, password)
        server.sendmail(user, to_addr, msg.as_string())
        server.quit()
        print(f"[MAIL] 已发送: {subject}")
    except Exception as e:
        print(f"[ERROR] 邮件发送失败: {e}")


# ═══════════════════════════════════════════════════════════
# 签到逻辑
# ═══════════════════════════════════════════════════════════

ACCOUNT_ORDER = [
    ("arknights", "明日方舟"),
    ("endfield", "明日方舟终末地"),
]

_ACCOUNT_CN = dict(ACCOUNT_ORDER)


def _game_key(app_code: str) -> str:
    return _ACCOUNT_CN.get(app_code, app_code)


def do_checkin(config: dict) -> list[str]:
    """执行所有账号签到，返回结果行列表"""
    lines = []
    accounts = config.get("accounts", [])

    for acc in accounts:
        if not acc.get("enabled", True):
            continue

        name = acc.get("name", "未知")
        token = acc.get("token", "")
        wanted = set(acc.get("games", []))

        if not token:
            lines.append(f"[{name}] 未配置 Token，跳过")
            continue

        lines.append(f"\n{'='*50}")
        lines.append(f"[{name}]")
        lines.append(f"{'='*50}")

        try:
            cred, sign_token = get_cred(token)
        except Exception as e:
            lines.append(f"  ❌ 获取 Cred 失败: {e}")
            continue

        try:
            bindings = get_bindings(cred, sign_token)
        except Exception as e:
            lines.append(f"  ❌ 获取绑定列表失败: {e}")
            continue

        lines.append(f"  绑定角色: {len(bindings)} 个")

        signed_any = False
        for b in bindings:
            app_code = b["appCode"]
            game_name = _game_key(app_code)

            # 按用户配置筛选游戏
            if wanted and app_code not in wanted:
                lines.append(f"  - [{game_name}] {b['nickName']} ({b['channelName']}) → 跳过（未启用）")
                continue

            try:
                result = do_attendance(cred, sign_token, b["uid"], b["gameId"])
                code = result.get("code", -1)

                if code == 0:
                    awards = result.get("data", {}).get("awards", [])
                    award_desc = ", ".join(
                        f"{a.get('resource', {}).get('name', '?')}x{a.get('count', '?')}"
                        for a in awards
                    ) if awards else "已签过"
                    lines.append(f"  ✅ [{game_name}] {b['nickName']} → {award_desc}")
                    signed_any = True
                elif code == 10001:
                    lines.append(f"  ℹ️ [{game_name}] {b['nickName']} → 今日已签到")
                    signed_any = True
                else:
                    msg = result.get("message", str(result))
                    lines.append(f"  ❌ [{game_name}] {b['nickName']} → {msg}")
            except Exception as e:
                lines.append(f"  ❌ [{game_name}] {b['nickName']} → 异常: {e}")

        if not signed_any:
            lines.append(f"  ⚠️ 未签到任何游戏")

    return lines


def save_state(lines: list[str]):
    today = time.strftime("%Y-%m-%d")
    state = {"date": today, "lines": lines, "time": time.strftime("%H:%M:%S")}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)


def load_state() -> dict | None:
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ═══════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="森空岛自动签到")
    parser.add_argument("--mode", choices=["full", "retry", "check"], default="full",
                        help="full=主力签到, retry=补签, check=看门狗")
    args = parser.parse_args()

    config = load_config()
    today = time.strftime("%Y-%m-%d")

    if args.mode == "full":
        print(f"[{today}] 🚀 主力签到开始")
        lines = do_checkin(config)
        save_state(lines)
        # 每行打印
        output = "\n".join(lines)
        print(output)

        # 发送邮件通知（始终发送，包含结果）
        send_mail(
            f"森空岛签到结果 {today}",
            f"签到时间: {today} {time.strftime('%H:%M:%S')}\n\n{output}",
        )

    elif args.mode == "retry":
        state = load_state()
        if state and state.get("date") == today:
            prev = "\n".join(state.get("lines", []))
            if "❌" in prev:
                print(f"[{today}] 🔄 发现上午签到有失败，执行补签")
                lines = do_checkin(config)
                save_state(lines)
                output = "\n".join(lines)
                print(output)
                send_mail(
                    f"森空岛补签结果 {today}",
                    f"补签时间: {today} {time.strftime('%H:%M:%S')}\n\n{output}",
                )
            else:
                print(f"[{today}] ✅ 上午签到全部成功，无需补签")
        else:
            print(f"[{today}] ⚠️ 上午签到状态不存在，直接补签")
            lines = do_checkin(config)
            save_state(lines)
            output = "\n".join(lines)
            print(output)

    elif args.mode == "check":
        state = load_state()
        if not state or state.get("date") != today:
            msg = f"{today} 全天零签到记录！可能是系统故障，请手动检查！"
            print(f"[{today}] 🚨 {msg}")
            send_mail(f"🚨 森空岛签到告警 {today}", msg)
            sys.exit(1)
        else:
            print(f"[{today}] ✅ 今日有签到记录")
            prev = "\n".join(state.get("lines", []))
            if "❌" in prev:
                send_mail(f"⚠️ 森空岛签到异常 {today}", prev)
                sys.exit(1)


if __name__ == "__main__":
    main()
