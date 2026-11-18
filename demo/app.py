#!/usr/bin/env python3
"""Deliberately vulnerable local fixture for testing redteam-self-audit.

Local only. Binds 127.0.0.1. Do not expose this app.
Known issues: SQLi login, reflected/stored XSS, IDOR, missing admin auth,
plaintext password API, path traversal, mass assignment, open redirect,
debug secret.
"""
import argparse
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "vulnapp.db"
FILES = BASE / "files"
SESSIONS = {}


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY, owner TEXT, item TEXT, total REAL, note TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY, author TEXT, body TEXT
        );
        """
    )
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO users (username,password,role,email) VALUES (?,?,?,?)",
            [
                ("alice", "alice123", "user", "alice@example.local"),
                ("bob", "bob123", "user", "bob@example.local"),
                ("admin", "admin123", "admin", "admin@example.local"),
            ],
        )
        c.executemany(
            "INSERT INTO orders (owner,item,total,note) VALUES (?,?,?,?)",
            [
                ("alice", "Widget", 19.99, "alice order"),
                ("bob", "Gadget", 49.99, "bob order"),
            ],
        )
        c.execute("INSERT INTO comments (author,body) VALUES (?,?)", ("alice", "hello"))
    conn.commit()
    conn.close()


def db():
    return sqlite3.connect(DB)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("sid="):
                return SESSIONS.get(part[4:])
        return None

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(url.query)

        if url.path == "/health":
            return self._send(200, "ok", "text/plain")
        if url.path == "/":
            return self._send(
                200,
                "<h1>VulnApp</h1><form action='/search'><input name='q'></form>"
                "<a href='/login'>login</a> <a href='/comments'>comments</a>",
            )
        if url.path == "/search":
            q = qs.get("q", [""])[0]
            return self._send(200, f"<h1>Search</h1><p>Results for: {q}</p>")
        if url.path == "/me":
            user = self._user()
            if not user:
                return self._send(401, "unauthorized", "text/plain")
            conn = db()
            row = conn.execute(
                "SELECT id,username,role,email FROM users WHERE username=?", (user,)
            ).fetchone()
            conn.close()
            return self._send(200, f"<p>id={row[0]} user={row[1]} role={row[2]} email={row[3]}</p>")
        if url.path.startswith("/orders/"):
            user = self._user()
            if not user:
                return self._send(401, "unauthorized", "text/plain")
            oid = url.path.split("/")[-1]
            conn = db()
            row = conn.execute(
                "SELECT id,owner,item,total,note FROM orders WHERE id=?", (oid,)
            ).fetchone()
            conn.close()
            if not row:
                return self._send(404, "not found", "text/plain")
            return self._send(
                200,
                f"<p>order={row[0]} owner={row[1]} item={row[2]} total={row[3]} note={row[4]}</p>",
            )
        if url.path == "/admin":
            return self._send(200, "<h1>Admin</h1><p>flag=ADMIN-PANEL-OPEN</p>")
        if url.path == "/api/users":
            conn = db()
            rows = conn.execute("SELECT id,username,password,role,email FROM users").fetchall()
            conn.close()
            return self._send(200, json.dumps(rows), "application/json")
        if url.path == "/comments":
            conn = db()
            rows = conn.execute("SELECT author,body FROM comments").fetchall()
            conn.close()
            body = "<h1>Comments</h1>" + "".join(
                f"<div><b>{author}</b>: {text}</div>" for author, text in rows
            )
            return self._send(200, body)
        if url.path == "/download":
            name = qs.get("file", [""])[0]
            path = FILES / name
            try:
                return self._send(200, path.read_bytes(), "application/octet-stream")
            except Exception:
                return self._send(404, "not found", "text/plain")
        if url.path == "/redirect":
            nxt = qs.get("next", ["/"])[0]
            return self._send(302, "", headers={"Location": nxt})
        if url.path == "/debug":
            return self._send(200, f"<p>secret=dev-secret-key</p><p>db={DB}</p>")
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode(errors="replace")

        if url.path == "/login":
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                try:
                    data = json.loads(raw)
                except Exception:
                    return self._send(400, "bad json", "text/plain")
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
            else:
                qs = urllib.parse.parse_qs(raw)
                username = qs.get("username", [""])[0]
                password = qs.get("password", [""])[0]
            conn = db()
            query = (
                f"SELECT username,role FROM users WHERE username = '{username}' "
                f"AND password = '{password}'"
            )
            try:
                row = conn.execute(query).fetchone()
            except Exception as exc:
                conn.close()
                return self._send(500, f"SQL error: {exc}", "text/plain")
            conn.close()
            if not row:
                return self._send(401, "invalid credentials", "text/plain")
            sid = os.urandom(8).hex()
            SESSIONS[sid] = row[0]
            return self._send(
                200,
                f"welcome {row[0]} role={row[1]}",
                headers={"Set-Cookie": f"sid={sid}; Path=/; HttpOnly"},
            )

        if url.path == "/comments":
            data = json.loads(raw or "{}")
            conn = db()
            conn.execute(
                "INSERT INTO comments (author,body) VALUES (?,?)",
                (self._user() or "anon", data.get("body", "")),
            )
            conn.commit()
            conn.close()
            return self._send(200, "ok", "text/plain")

        if url.path == "/profile":
            data = json.loads(raw or "{}")
            user = self._user()
            if not user:
                return self._send(401, "unauthorized", "text/plain")
            conn = db()
            if "role" in data:
                conn.execute("UPDATE users SET role=? WHERE username=?", (data["role"], user))
            conn.commit()
            conn.close()
            return self._send(200, "profile updated", "text/plain")

        return self._send(404, "not found", "text/plain")

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5001")))
    args = parser.parse_args()
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"vulnapp on http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
