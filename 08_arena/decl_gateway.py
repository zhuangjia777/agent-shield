#!/usr/bin/env python3
"""申报目标网关（M3 目标申报）：红队容器打申报目标的唯一通道。

背景：红队容器只接 internal 隔离网（物理禁出网，这是卖点不是缺陷）。
用户申报一个宿主/外部目标后，不去给红队开网——那会把默认路由交给
非 internal 网络，外网通了、还能直打靶机绕过 WAF，隔离全废。
改为起一个单用途中继容器：只接隔离网 + 一条申报专用网，
只把 TCP 流量转发到那一个申报 host:port，其余一律不代理。

边界哲学不变：申报闸在宿主侧（用户点头才起）；中继是单目标、只读镜像、
无 shell 依赖；每条连接落盘审计；无裁判——申报目标只能出证据不能定胜负。
"""
import json
import os
import select
import socket
import sys
import threading
import time

DECL_HOST = os.environ["DECL_HOST"]   # 申报目标（127.0.0.1 会换成宿主地址）
DECL_PORT = int(os.environ["DECL_PORT"])
AUDIT = os.environ.get("DECL_AUDIT", "/audit/decl_events.jsonl")
LISTEN_PORT = int(os.environ.get("DECL_LISTEN", "8000"))


def audit(entry: dict):
    entry["at"] = time.strftime("%F %T")
    try:
        with open(AUDIT, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def pipe(a: socket.socket, b: socket.socket, st: dict, direction: str):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            st[direction] += len(data)
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(conn: socket.socket, addr):
    st = {"up": 0, "down": 0}
    try:
        up = socket.create_connection((DECL_HOST, DECL_PORT), timeout=10)
    except OSError as e:
        audit({"evt": "decl_conn", "peer": addr[0], "ok": False, "err": str(e)[:120]})
        conn.close()
        return
    audit({"evt": "decl_conn", "peer": addr[0], "ok": True,
           "to": f"{DECL_HOST}:{DECL_PORT}"})
    t1 = threading.Thread(target=pipe, args=(conn, up, st, "up"))
    t2 = threading.Thread(target=pipe, args=(up, conn, st, "down"))
    t1.start(); t2.start(); t1.join(); t2.join()
    conn.close(); up.close()
    audit({"evt": "decl_done", "peer": addr[0], "bytes_up": st["up"], "bytes_down": st["down"]})


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(16)
    print(f"decl-gw: :{LISTEN_PORT} -> {DECL_HOST}:{DECL_PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
