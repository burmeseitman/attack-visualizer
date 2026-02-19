#!/usr/bin/env python3
"""Live Hacker Attack Visualizer (educational simulator).

This app intentionally simulates attack patterns in a safe, local-only way.
It does not execute real attacks against systems or databases.
"""

from __future__ import annotations

import json
import math
import mimetypes
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
HOST = "127.0.0.1"
PORT = 8000


@dataclass
class BruteForceResult:
    target: str
    charset: str
    search_space: int
    attempts_used: int
    cap: int
    cracked: bool
    estimated_seconds: float
    logs: list[dict[str, Any]]


def sanitize_target(raw_target: str, charset: str, max_len: int = 6) -> str:
    cleaned = "".join(ch.lower() for ch in raw_target if ch.lower() in charset)
    if not cleaned:
        return "admin"
    return cleaned[:max_len]


def word_to_index(word: str, charset: str) -> int:
    base = len(charset)
    index_map = {ch: i for i, ch in enumerate(charset)}
    total = 0
    n = len(word)
    for i, ch in enumerate(word):
        power = n - i - 1
        total += index_map[ch] * (base**power)
    return total + 1


def index_to_word(index: int, length: int, charset: str) -> str:
    base = len(charset)
    index -= 1
    chars = [charset[0]] * length
    for i in range(length - 1, -1, -1):
        chars[i] = charset[index % base]
        index //= base
    return "".join(chars)


def simulate_bruteforce(payload: dict[str, Any]) -> BruteForceResult:
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw_target = str(payload.get("target", "admin"))
    target = sanitize_target(raw_target, charset)

    try:
        cap = int(payload.get("attempt_cap", 500000))
    except (TypeError, ValueError):
        cap = 500000
    cap = max(1000, min(cap, 5_000_000))

    search_space = len(charset) ** len(target)
    hit_attempt = word_to_index(target, charset)
    cracked = hit_attempt <= cap
    attempts_used = hit_attempt if cracked else cap

    # Estimated as synthetic benchmark for teaching purposes.
    estimated_seconds = attempts_used * 0.00042

    checkpoints = 10
    logs: list[dict[str, Any]] = []
    for step in range(1, checkpoints + 1):
        attempt = max(1, math.floor(attempts_used * (step / checkpoints)))
        candidate = index_to_word(min(attempt, search_space), len(target), charset)
        status = "probing"
        if step == checkpoints and cracked:
            candidate = target
            status = "match found"
        elif step == checkpoints and not cracked:
            status = "cap reached"

        logs.append(
            {
                "attempt": attempt,
                "candidate": candidate,
                "status": status,
            }
        )

    return BruteForceResult(
        target=target,
        charset=charset,
        search_space=search_space,
        attempts_used=attempts_used,
        cap=cap,
        cracked=cracked,
        estimated_seconds=estimated_seconds,
        logs=logs,
    )


def classify_sqli(payload_text: str) -> str:
    text = payload_text.lower()
    if "union select" in text:
        return "union_leak"
    if "drop table" in text:
        return "destructive_intent"
    if re.search(r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1\b", text) or "' or '1'='1" in text:
        return "auth_bypass"
    return "none"


def simulate_sqli(payload: dict[str, Any]) -> dict[str, Any]:
    payload_catalog = {
        "auth_bypass": "' OR '1'='1' --",
        "union_dump": "' UNION SELECT username, password FROM users --",
        "destructive": "'; DROP TABLE users; --",
        "none": "normal input",
    }

    selected_key = str(payload.get("payload_key", "auth_bypass"))
    selected_payload = payload_catalog.get(selected_key, payload_catalog["auth_bypass"])

    username = str(payload.get("username", "guest"))
    password = str(payload.get("password", selected_payload))

    sample_users = [
        {"username": "admin", "password": "q9x1"},
        {"username": "analyst", "password": "safe-pass"},
        {"username": "student", "password": "learn123"},
    ]

    unsafe_query = (
        "SELECT * FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    safe_query = "SELECT * FROM users WHERE username = ? AND password = ?"

    classification = classify_sqli(f"{username} {password}")

    exact_match = any(
        row["username"] == username and row["password"] == password for row in sample_users
    )

    if classification == "auth_bypass":
        unsafe_outcome = {
            "label": "Authentication bypassed",
            "records_exposed": len(sample_users),
            "impact": "All user rows become visible due to always-true condition.",
        }
    elif classification == "union_leak":
        unsafe_outcome = {
            "label": "Data unioned",
            "records_exposed": len(sample_users),
            "impact": "Attacker-controlled UNION may merge additional sensitive data.",
        }
    elif classification == "destructive_intent":
        unsafe_outcome = {
            "label": "Dangerous command attempted",
            "records_exposed": len(sample_users),
            "impact": "Potential schema damage if multi-statements are allowed.",
        }
    else:
        unsafe_outcome = {
            "label": "No injection detected",
            "records_exposed": 1 if exact_match else 0,
            "impact": "Regular authentication path.",
        }

    safe_outcome = {
        "label": "Parameterized query blocks injection",
        "records_exposed": 1 if exact_match else 0,
        "impact": "Input treated as data, not SQL code.",
    }

    return {
        "payload": selected_payload,
        "classification": classification,
        "unsafe_query": unsafe_query,
        "safe_query": safe_query,
        "unsafe_outcome": unsafe_outcome,
        "safe_outcome": safe_outcome,
        "mitigations": [
            "Use parameterized queries/prepared statements everywhere.",
            "Apply least-privilege database credentials.",
            "Validate and constrain user inputs on server side.",
            "Enable audit logging and anomaly detection for query patterns.",
        ],
    }


class AppHandler(BaseHTTPRequestHandler):
    server_version = "LiveHackerVisualizer/1.0"

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path: Path) -> None:
        if not file_path.exists() or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        ctype, _ = mimetypes.guess_type(file_path.name)
        data = file_path.read_bytes()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send_file(STATIC_DIR / "index.html")
            return

        if path.startswith("/static/"):
            rel = path.removeprefix("/static/")
            requested = (STATIC_DIR / rel).resolve()
            if STATIC_DIR not in requested.parents and requested != STATIC_DIR:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            self._send_file(requested)
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON payload."}, status=HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/bruteforce":
            result = simulate_bruteforce(payload)
            self._send_json(
                {
                    "target": result.target,
                    "charset": result.charset,
                    "search_space": result.search_space,
                    "attempts_used": result.attempts_used,
                    "attempt_cap": result.cap,
                    "cracked": result.cracked,
                    "estimated_seconds": result.estimated_seconds,
                    "logs": result.logs,
                    "explanation": (
                        "Brute force tries every candidate combination until a match is found "
                        "or the configured attempt cap is reached."
                    ),
                    "mitigations": [
                        "Increase password length and complexity.",
                        "Use rate limiting and account lockout policies.",
                        "Enable MFA to reduce password-only risk.",
                        "Store passwords with adaptive hashing (Argon2, bcrypt).",
                    ],
                }
            )
            return

        if path == "/api/sqli":
            self._send_json(simulate_sqli(payload))
            return

        self._send_json({"error": "Endpoint not found."}, status=HTTPStatus.NOT_FOUND)


def run() -> None:
    with ThreadingHTTPServer((HOST, PORT), AppHandler) as httpd:
        print(f"Live Hacker Attack Visualizer running on http://{HOST}:{PORT}")
        print("Educational simulation only. Do not use for unauthorized activities.")
        httpd.serve_forever()


if __name__ == "__main__":
    run()
