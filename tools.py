import os
import urllib.parse
import base64
import threading
import asyncio


def resource_path(relative_path):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, relative_path)


# ss://
# Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo1NzQ1MDJkMS01Y2FlLTQ0ODMtYTQ1Ny03ZmFkMjRmMjg3Y2M
# @v1abc123.sched.sma-dk.hfifx.xin:40060
# #%F0%9F%87%AF%F0%9F%87%B5%20JP%20%20%20%20Cappuccino    
def parse_ss_link(ss_link):
    # 去掉前缀 ss://
    ss_link = ss_link[5:]

    # 分割备注
    parts = ss_link.split("#")
    main_part = parts[0]
    remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

    # 分割 server 和加密信息
    if "@" in main_part:
        method_pass_enc, server_part = main_part.split("@")
    else:
        # 部分 ss 链接会整体 base64 编码，需要额外处理（这里不展开）
        return None

    # base64 decode method:password
    method_pass = base64.urlsafe_b64decode(method_pass_enc + "=" * (-len(method_pass_enc) % 4)).decode()
    method, password = method_pass.split(":", 1)

    # 分割 host 和 port
    if ":" in server_part:
        host, port = server_part.split(":")
    else:
        host, port = server_part, ""

    return {
        "method": method,
        "password": password,
        "host": host,
        "port": port,
        "remark": remark
    }
def singleton(cls):
    _instance = {}
    _lock = threading.Lock()
    def wrapper(*args, **kwargs):
        with _lock:
            if cls not in _instance:
                _instance[cls] = cls(*args, **kwargs)
        return _instance[cls]
    return wrapper

