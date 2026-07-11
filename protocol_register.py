#!/usr/bin/env python3
"""Pure-protocol Grok (x.ai) registration.

Browser Turnstile widgets fail on GitHub Actions (empty iframe src).
This path solves Turnstile via CapSolver / YesCaptcha / 2Captcha, then
registers through accounts.x.ai APIs and extracts sso cookies.
"""
from __future__ import annotations

import json
import os
import random
import re
import string
import struct
import time
from typing import Callable, Optional

ACCOUNTS_URL = "https://accounts.x.ai"
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
# Fallback next-action; will try to refresh from HTML when possible.
DEFAULT_NEXT_ACTION = "7f69646bb11542f4cad728680077c67a09624b94e0"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _varint(n: int) -> bytes:
    buf = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def _pb_string(field: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    tag = (field << 3) | 2
    return _varint(tag) + _varint(len(encoded)) + encoded


def _grpc_frame(body: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(body)) + body


def _rand_name(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n)).capitalize()


def _rand_password(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n)) + "!aA1"


def _log(fn: Optional[Callable[[str], None]], msg: str) -> None:
    if fn:
        fn(msg)
    else:
        print(msg)


def _http_session(proxy: str = ""):
    """Prefer curl_cffi for TLS fingerprint; fallback to requests."""
    proxy = (proxy or "").strip()
    try:
        from curl_cffi import requests as cffi_requests

        s = cffi_requests.Session(impersonate="chrome131")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.headers.update({"user-agent": UA})
        return s, "curl_cffi"
    except Exception:
        import requests

        s = requests.Session()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.headers.update({"user-agent": UA})
        return s, "requests"


def solve_turnstile_token(sitekey: str, page_url: str, config: dict, log_fn=None) -> str:
    """Solve Turnstile via CapSolver / YesCaptcha / 2Captcha."""
    import requests

    cap_key = str(config.get("capsolver_api_key") or os.environ.get("CAPSOLVER_API_KEY") or "").strip()
    yes_key = str(config.get("yescaptcha_api_key") or os.environ.get("YESCAPTCHA_API_KEY") or "").strip()
    two_key = str(config.get("twocaptcha_api_key") or os.environ.get("TWOCAPTCHA_API_KEY") or "").strip()

    # CapSolver
    if cap_key:
        _log(log_fn, "[*] CapSolver 解决 Turnstile...")
        for task_type in ("AntiTurnstileTaskProxyLess", "TurnstileTaskProxyLess"):
            try:
                r = requests.post(
                    "https://api.capsolver.com/createTask",
                    json={
                        "clientKey": cap_key,
                        "task": {
                            "type": task_type,
                            "websiteURL": page_url,
                            "websiteKey": sitekey,
                        },
                    },
                    timeout=60,
                )
                data = r.json()
                task_id = data.get("taskId")
                if not task_id:
                    _log(log_fn, f"[Debug] CapSolver {task_type} create failed: {data}")
                    continue
                for _ in range(40):
                    time.sleep(3)
                    res = requests.post(
                        "https://api.capsolver.com/getTaskResult",
                        json={"clientKey": cap_key, "taskId": task_id},
                        timeout=60,
                    ).json()
                    if res.get("status") == "ready":
                        token = str((res.get("solution") or {}).get("token") or "").strip()
                        if token:
                            _log(log_fn, f"[+] CapSolver 成功 ({task_type}), len={len(token)}")
                            return token
                    if res.get("status") == "failed" or res.get("errorId"):
                        _log(log_fn, f"[Debug] CapSolver {task_type} failed: {res}")
                        break
            except Exception as exc:
                _log(log_fn, f"[Debug] CapSolver {task_type} exception: {exc}")

    # YesCaptcha
    if yes_key:
        _log(log_fn, "[*] YesCaptcha 解决 Turnstile...")
        try:
            r = requests.post(
                "https://api.yescaptcha.com/createTask",
                json={
                    "clientKey": yes_key,
                    "task": {
                        "type": "TurnstileTaskProxyless",
                        "websiteURL": page_url,
                        "websiteKey": sitekey,
                    },
                },
                timeout=60,
            )
            data = r.json()
            task_id = data.get("taskId")
            if not task_id:
                raise RuntimeError(f"YesCaptcha create failed: {data}")
            for _ in range(60):
                time.sleep(3)
                d = requests.post(
                    "https://api.yescaptcha.com/getTaskResult",
                    json={"clientKey": yes_key, "taskId": task_id},
                    timeout=60,
                ).json()
                if d.get("status") == "ready":
                    token = str((d.get("solution") or {}).get("token") or "").strip()
                    if token:
                        _log(log_fn, f"[+] YesCaptcha 成功, len={len(token)}")
                        return token
                if d.get("errorId", 0) != 0:
                    raise RuntimeError(f"YesCaptcha error: {d}")
            raise TimeoutError("YesCaptcha timeout")
        except Exception as exc:
            _log(log_fn, f"[Debug] YesCaptcha exception: {exc}")

    # 2Captcha
    if two_key:
        _log(log_fn, "[*] 2Captcha 解决 Turnstile...")
        try:
            create = requests.post(
                "https://2captcha.com/in.php",
                data={
                    "key": two_key,
                    "method": "turnstile",
                    "sitekey": sitekey,
                    "pageurl": page_url,
                    "json": 1,
                },
                timeout=60,
            ).json()
            if create.get("status") != 1:
                raise RuntimeError(f"2Captcha create failed: {create}")
            task_id = create.get("request")
            for _ in range(60):
                time.sleep(5)
                data = requests.get(
                    "https://2captcha.com/res.php",
                    params={"key": two_key, "action": "get", "id": task_id, "json": 1},
                    timeout=60,
                ).json()
                if data.get("status") == 1:
                    token = str(data.get("request") or "").strip()
                    if token:
                        _log(log_fn, f"[+] 2Captcha 成功, len={len(token)}")
                        return token
                if str(data.get("request") or "") not in ("CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"):
                    # keep waiting on NOT_READY only
                    if "NOT_READY" not in str(data.get("request") or ""):
                        _log(log_fn, f"[Debug] 2Captcha res: {data}")
            raise TimeoutError("2Captcha timeout")
        except Exception as exc:
            _log(log_fn, f"[Debug] 2Captcha exception: {exc}")

    raise RuntimeError(
        "Turnstile 无法解决：未配置或打码失败。"
        "请在 GitHub Secrets 添加 YESCAPTCHA_API_KEY / CAPSOLVER_API_KEY / TWOCAPTCHA_API_KEY 之一。"
    )


def fetch_next_action(session, log_fn=None) -> str:
    """Best-effort refresh of Next.js server action id from signup HTML."""
    try:
        r = session.get(f"{ACCOUNTS_URL}/sign-up?redirect=grok-com", timeout=30)
        html = r.text or ""
        # look for next-action hashes
        m = re.search(r'"([a-f0-9]{40,})"', html)
        # better: look near createUserAndSession or server actions
        candidates = re.findall(r'([a-f0-9]{40,44})', html)
        # also data-action / next-action meta
        m2 = re.search(r'next-action["\']?\s*[:=]\s*["\']([a-f0-9]{20,})', html, re.I)
        if m2:
            return m2.group(1)
        # common pattern in RSC payloads
        m3 = re.search(r'createUserAndSession[^"]{0,80}([a-f0-9]{40})', html, re.I)
        if m3:
            return m3.group(1)
        # fallback keep default; many deployments still accept old action with 404-ish body
        _log(log_fn, f"[Debug] next-action not found in HTML, candidates={len(candidates)}")
    except Exception as exc:
        _log(log_fn, f"[Debug] fetch next-action failed: {exc}")
    return DEFAULT_NEXT_ACTION


def register_protocol(
    email: str,
    code: str,
    config: dict,
    password: str = "",
    given_name: str = "",
    family_name: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
) -> dict:
    """Register one Grok account via protocol and return sso cookies."""
    email = str(email or "").strip()
    code = str(code or "").strip()
    if not email or not code:
        raise RuntimeError("email/code required")

    password = password or _rand_password()
    given_name = given_name or _rand_name()
    family_name = family_name or _rand_name()
    proxy = str(config.get("proxy") or "").strip()

    s, backend = _http_session(proxy)
    _log(log_fn, f"[*] 协议注册启动 backend={backend} email={email}")

    # Step1: send OTP (even if already sent via browser path; ignore errors)
    try:
        body = _pb_string(1, email)
        r = s.post(
            f"{ACCOUNTS_URL}/auth_mgmt.AuthManagement/CreateEmailValidationCode",
            headers={
                "content-type": "application/grpc-web+proto",
                "x-grpc-web": "1",
                "origin": "https://accounts.x.ai",
                "referer": "https://accounts.x.ai/sign-up",
            },
            data=_grpc_frame(body),
            timeout=60,
        )
        _log(log_fn, f"[Debug] CreateEmailValidationCode status={getattr(r, 'status_code', '?')}")
    except Exception as exc:
        _log(log_fn, f"[Debug] CreateEmailValidationCode skipped: {exc}")

    # Step2: verify OTP
    try:
        body = _pb_string(1, email) + _pb_string(2, code)
        resp = s.post(
            f"{ACCOUNTS_URL}/auth_mgmt.AuthManagement/VerifyEmailValidationCode",
            headers={
                "content-type": "application/grpc-web+proto",
                "x-grpc-web": "1",
                "origin": "https://accounts.x.ai",
                "referer": "https://accounts.x.ai/sign-up",
            },
            data=_grpc_frame(body),
            timeout=60,
        )
        content = getattr(resp, "content", b"") or b""
        ok = b"grpc-status:0" in content or getattr(resp, "status_code", 0) == 200
        _log(log_fn, f"[*] VerifyEmailValidationCode ok={ok} status={getattr(resp, 'status_code', '?')}")
    except Exception as exc:
        _log(log_fn, f"[Debug] VerifyEmailValidationCode exception: {exc}")

    # Step3: solve turnstile + signup
    page_url = "https://accounts.x.ai/sign-up"
    turnstile = solve_turnstile_token(TURNSTILE_SITEKEY, page_url, config, log_fn=log_fn)
    next_action = fetch_next_action(s, log_fn=log_fn) or DEFAULT_NEXT_ACTION
    _log(log_fn, f"[Debug] using next-action={next_action[:16]}...")

    payload = [
        {
            "emailValidationCode": code,
            "createUserAndSessionRequest": {
                "email": email,
                "givenName": given_name,
                "familyName": family_name,
                "clearTextPassword": password,
                "tosAcceptedVersion": 1,
            },
            "turnstileToken": turnstile,
        }
    ]
    r = s.post(
        f"{ACCOUNTS_URL}/sign-up",
        headers={
            "content-type": "application/json",
            "next-action": next_action,
            "origin": "https://accounts.x.ai",
            "referer": "https://accounts.x.ai/sign-up",
        },
        json=payload,
        timeout=90,
    )
    body_text = getattr(r, "text", "") or ""
    _log(log_fn, f"[*] sign-up status={getattr(r, 'status_code', '?')} body_len={len(body_text)}")
    if len(body_text) < 2000:
        _log(log_fn, f"[Debug] sign-up body: {body_text[:800]}")

    # If next-action invalid, try DEFAULT once more
    if getattr(r, "status_code", 0) >= 400 or "Invalid" in body_text or "error" in body_text.lower()[:200]:
        if next_action != DEFAULT_NEXT_ACTION:
            _log(log_fn, "[*] retry sign-up with default next-action")
            r = s.post(
                f"{ACCOUNTS_URL}/sign-up",
                headers={
                    "content-type": "application/json",
                    "next-action": DEFAULT_NEXT_ACTION,
                    "origin": "https://accounts.x.ai",
                    "referer": "https://accounts.x.ai/sign-up",
                },
                json=payload,
                timeout=90,
            )
            body_text = getattr(r, "text", "") or ""
            _log(log_fn, f"[*] sign-up retry status={getattr(r, 'status_code', '?')} body_len={len(body_text)}")

    # Step4: follow set-cookie URLs
    urls = re.findall(r"https://auth\.[^\"\s\\]+/set-cookie[^\"\s\\]*", body_text)
    for url in urls:
        url = url.replace("\\u0026", "&").replace("\\u003d", "=").replace("\\/", "/")
        try:
            _log(log_fn, f"[*] set-cookie: {url[:80]}...")
            s.get(
                url,
                headers={"user-agent": UA, "accept": "text/html", "referer": "https://accounts.x.ai/"},
                allow_redirects=True,
                timeout=60,
            )
        except Exception as exc:
            _log(log_fn, f"[Debug] set-cookie failed: {exc}")

    # Collect cookies
    cookies = {}
    try:
        for c in s.cookies:
            cookies[c.name] = c.value
    except Exception:
        try:
            cookies = dict(s.cookies)
        except Exception:
            cookies = {}

    # Also try regex sso from body
    if not cookies.get("sso"):
        m = re.search(r'"sso"\s*:\s*"([^"]+)"', body_text)
        if m:
            cookies["sso"] = m.group(1)
        m = re.search(r"sso=([^;\"&\s]+)", body_text)
        if m and not cookies.get("sso"):
            cookies["sso"] = m.group(1)

    sso = str(cookies.get("sso") or "").strip()
    sso_rw = str(cookies.get("sso-rw") or cookies.get("sso_rw") or "").strip()
    if not sso:
        # dump snippet for debug
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"debug_signup_{int(time.time())}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(body_text)
            _log(log_fn, f"[Debug] 已保存 sign-up 响应: {path}")
        except Exception:
            pass
        raise RuntimeError(f"协议注册未拿到 sso cookie。cookies={list(cookies.keys())} status={getattr(r, 'status_code', '?')}")

    _log(log_fn, f"[+] 协议注册成功 sso={sso[:28]}... sso_rw_len={len(sso_rw)}")
    return {
        "email": email,
        "password": password,
        "given_name": given_name,
        "family_name": family_name,
        "sso": sso,
        "sso_rw": sso_rw,
        "cookies": cookies,
    }
