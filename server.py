from logger import GlobalLogger
from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal, QMutex
from tools import parse_ss_link, singleton
import subprocess
import re
import requests
from config import get_config, get_config_path
import threading
import asyncio
import time
@singleton
class SSLocalLogReader(QObject):

    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        GlobalLogger().log(f'ss local log reader thread start: {threading.get_ident()}')
        while self._running:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+): (.*)$"

            m = re.match(pattern, line)
            if m:
                timestamp, level, message = m.groups()
                GlobalLogger().log('[ss-local] '+message , level, timestamp)  # 发给全局日志

            else:
                GlobalLogger().log(f"[ss-local] logreader err: 格式不匹配")

class SS(QObject):
    def __init__(self, ss_host = '127.0.0.1', ss_port = 1080):
        super().__init__()
        self.proc = None
        self.thread = None
        self.running = False
        self.proxy_host = ss_host
        self.proxy_port = ss_port
        self.proxies = {
           "http": f"socks5h://{self.proxy_host}:{self.proxy_port}",
            "https": f"socks5h://{self.proxy_host}:{self.proxy_port}"
        }

    def connect_ss(self, ss_link):
        ss_info = parse_ss_link(ss_link)

        cmd = [
            "ss-local",
            "-s", ss_info['host'],          # 服务器 IP
            "-p", str(ss_info['port']),     # 服务器端口
            "-k", ss_info['password'],      # 密码
            "-m", ss_info['method'],        # 加密方式
            "-b", self.proxy_host,              # 本地监听地址
            "-l", str(self.proxy_port),                   # 本地 SOCKS5 端口
            # "-v"                            # verbose
        ]

        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        GlobalLogger().log(f"Shadowsocks 启动中... {cmd}")
        # 创建线程和日志读取器
        self.thread = QThread()
        self.log_worker = SSLocalLogReader(self.proc)
        self.log_worker.moveToThread(self.thread)
        self.thread.started.connect(self.log_worker.run)
        self.thread.start()
        self.running = True

    def close_ss(self):
        self.running = False
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None
            self.log_worker.stop()
            if self.thread and self.thread.isRunning():
                self.thread.quit()    # 让线程退出事件循环
                self.thread.wait()    # 等待线程退出
            GlobalLogger().log("Shadowsocks 已停止")

    def get(self, url):
        try:
            if self.running:
                response = requests.get(url=url, proxies=self.proxies, timeout=5)
            else:
                response = requests.get(url=url, proxies=None, timeout=5)
            if response.status_code == 200:
                return None, response
            else:
                return None, response
        except Exception as e:
            GlobalLogger().log(f"代理测试异常: {e}")
            return e, None

@singleton
class ProxyServer:
    def __init__(self):
        self.ss = SS(get_config().socks_host, get_config().socks_port)
        self.bytes_received = 0
        self.bytes_sent = 0
        self.active_hosts = set()
        self.loop = asyncio.new_event_loop()   # 新线程 loop
    async def get_host_from_data(self, data, writer):
        """
        安全解析 TCP 流中的 HTTP/HTTPS 请求 Host
        data: bytes
        writer: asyncio.StreamWriter，用于在解析失败时关闭连接
        """
        try:
            header = data.decode(errors="ignore")
        except Exception:
            writer.close()
            await writer.wait_closed()
            return None

        host = None
        port = 80
        for line in header.split("\r\n"):  # 或 "\n"
            if not isinstance(line, str):
                continue
            line_lower = line.lower()
            if line_lower.startswith("host:"):
                # partition 更安全，防止 split 报错
                host = line.partition(":")[2].strip()
                # 如果 host 中带端口，例如 host: example.com:8080
                if ":" in host:
                    host, port_str = host.split(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 80
                break
            # CONNECT 方法特殊处理
            if line_lower.startswith("connect "):
                parts = line.split()
                if len(parts) >= 2:
                    host_port = parts[1].strip()
                    if ":" in host_port:
                        host, port_str = host_port.split(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            port = 443
                    else:
                        host = host_port
                        port = 443
                break

        if not host:
            writer.close()
            await writer.wait_closed()
            return None, 80
        return host, port

    async def handle_client(self, reader, writer):
        try:
            data = await reader.read(4096)
            if not data:
                return

            first_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
            if first_line.startswith("CONNECT"):
                # HTTPS 隧道代理
                host_port = first_line.split(" ")[1]   # "baidu.com:443"
                host, port = host_port.split(":")
                port = int(port)

                strategy = get_config().match(host)
                GlobalLogger().log(f"[RULE] {host}:{port} -> {strategy}")

                if strategy.upper() == "PROXY":
                    remote_reader, remote_writer = await self.socks5_connect(
                            self.ss.proxy_host, self.ss.proxy_port, host, port
                        )
                else:  # DIRECT
                    remote_reader, remote_writer = await asyncio.open_connection(
                        host, port
                    )

                # 返回 200 给浏览器，表示隧道建立成功
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

            else:
                # 普通 HTTP 请求
                host, port = await self.get_host_from_data(data, writer)
                if not host:
                    GlobalLogger().log(f'host parse err.{data}', 'ERR')
                    return

                strategy = get_config().match(host)
                GlobalLogger().log(f"[RULE] {host}:{port} -> {strategy}")

                if strategy.upper() == "PROXY":
                   remote_reader, remote_writer = await self.socks5_connect(
                            self.ss.proxy_host, self.ss.proxy_port, host, port
                        )
                else:  # DIRECT
                    remote_reader, remote_writer = await asyncio.open_connection(
                        host, port
                    )

                # 转发首包
                remote_writer.write(data)
                await remote_writer.drain()

            # 隧道转发
            self.active_hosts.add(host)
            asyncio.create_task(self.pipe(reader, remote_writer, count_rx=True))
            asyncio.create_task(self.pipe(remote_reader, writer, count_rx= False))


        except Exception as e:
            GlobalLogger().log(f"{e}", level='ERR')
            writer.close()
    # pipe 双向转发
    async def pipe(self, r, w, count_rx = True):
        try:
            while True:
                buf = await r.read(4096)
                if not buf:
                    break
                w.write(buf)
                await w.drain()
                if count_rx:
                    self.bytes_received += len(buf)
                else:
                    self.bytes_sent += len(buf)
        except Exception:
            pass
        finally:
            w.close()
    async def socks5_connect(self,proxy_host, proxy_port, dest_host, dest_port):
        """
        通过 SOCKS5 代理连接目标 host:port
        返回 (reader, writer)
        """
        import struct
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        # -------------------
        # 1. 握手
        # -------------------
        # 0x05 = SOCKS5, 0x01 = 支持一个认证方法, 0x00 = 不需要认证
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await reader.readexactly(2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise RuntimeError("SOCKS5 handshake failed")

        # -------------------
        # 2. 发送 CONNECT 请求
        # -------------------
        dest_ip_bytes = None
        try:
            # 尝试解析成 IP
            import ipaddress
            ip_obj = ipaddress.ip_address(dest_host)
            dest_ip_bytes = ip_obj.packed
            addr_type = 0x01  # IPv4 或 IPv6
        except:
            addr_type = 0x03  # domain

        if addr_type == 0x01:
            # IPv4 或 IPv6
            writer.write(b"\x05\x01\x00" + bytes([len(dest_ip_bytes)]) + dest_ip_bytes + struct.pack(">H", dest_port))
        else:
            # domain
            host_bytes = dest_host.encode()
            writer.write(b"\x05\x01\x00" + bytes([addr_type]) + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", dest_port))
        await writer.drain()

        # 读取响应
        # resp: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR + BND.PORT
        resp = await reader.read(4)
        if len(resp) < 4 or resp[1] != 0x00:
            raise RuntimeError("SOCKS5 connect failed")
        # 读取剩余 BND.ADDR + BND.PORT
        if resp[3] == 0x01:
            await reader.read(4 + 2)
        elif resp[3] == 0x03:
            l = await reader.read(1)
            await reader.read(l[0] + 2)
        elif resp[3] == 0x04:
            await reader.read(16 + 2)
        else:
            raise RuntimeError("Unknown ATYP")

        return reader, writer

    async def run(self):
        server = await asyncio.start_server(
            self.handle_client, get_config().listen_host, get_config().listen_port
        )
        GlobalLogger().log(f"Proxy running at {get_config().listen_host}:{get_config().listen_port}")
        async with server:
            await server.serve_forever()
    
    async def measure_tcp_latency(self, host, port):
        import time
        start = time.time()
        try:
            reader, writer = await asyncio.open_connection(host, port)  # ✅ 必须 await
            writer.close()
            await writer.wait_closed()
            return int((time.time() - start) * 1000)  # 返回 ms
        except:
            return None

    def check_latency_sync(self, host, port):
        # 提交到 loop，返回 Future
        GlobalLogger().log(f'check latency {host}:{port}')
        return asyncio.run_coroutine_threadsafe(
            self.measure_tcp_latency(host, port),
            self.loop
        )
    def start(self):
        asyncio.set_event_loop(self.loop)        # 设置当前线程的 loop
        self.loop.run_until_complete(self.run())  # 运行协程

def start_server():
    asyncio.run(ProxyServer().run())

    GlobalLogger().log(f'proxy server thread start: {threading.get_ident()}')

