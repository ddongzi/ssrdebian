from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QListWidget,
    QStackedWidget, QLabel, QHBoxLayout, QPushButton, QComboBox, QMessageBox,
    QLineEdit, QFormLayout, QDialogButtonBox, QDialog, QTreeWidget,
    QTreeWidgetItem, QCheckBox, QGroupBox, QMenu, QPlainTextEdit, QTextEdit
)
from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal, QMutex
from PySide6.QtGui import QPixmap, QImage
import qrcode
from io import BytesIO
# from PIL import Image
import threading
import json
import base64
import urllib.parse
import subprocess
import os
import re
import requests
from urllib.parse import urlparse
from datetime import datetime
import asyncio
import yaml
import ipaddress
from queue import Queue
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
class Config:
    def __init__(self, path="resources/config.yml"):
        self.path = resource_path(path)
        print(self.path)
        self.load_config()

    def load_config(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        # server
        server = cfg.get("server", {})
        self.listen_host = server.get("listen_host", '0.0.0.0')
        self.listen_port = server.get("listen_port", 1081)
        self.socks_host = server.get("socks_host", '0.0.0.0')
        self.socks_port = server.get("socks_port", 1080)

        # proxies
        self.proxies = {}
        for p in cfg.get("proxies", []):
            self.proxies[p["name"]] = p

        # proxy groups
        self.proxy_groups = {}
        for g in cfg.get("proxy-groups", []):
            self.proxy_groups[g["name"]] = g
        # rules
        self.rules = []
        for r in cfg.get("rules", []):
            parts = r.split(",")
            if len(parts) == 2:
                self.rules.append((parts[0], parts[1], None))
            elif len(parts) == 3:
                self.rules.append((parts[0], parts[1], parts[2]))

    def match(self, target):
        import ipaddress
        for rule in self.rules:

            rtype = rule[0]
            value = rule[1] if len(rule) > 1 else None
            action = rule[2] if len(rule) > 2 else None

            if rtype == "DOMAIN-SUFFIX" and target.endswith(value):
                return action
            if rtype == "DOMAIN-KEYWORD" and value in target:
                return action
            if rtype == "IP-CIDR":
                try:
                    if ipaddress.ip_address(target) in ipaddress.ip_network(value):
                        return action
                except ValueError:
                    pass
            if rtype == "FINAL":
                return value
        return "DIRECT"  # fallback

    def add_ss_proxy(self, name, ss_url, group_name = 'FREEDOM'):
        if os.path.exists(self.path):
            with open(self.path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
        else:
            cfg = {}

        if "proxies" not in cfg:
            cfg["proxies"] = []

        # 检查是否已存在同名节点
        for p in cfg["proxies"]:
            if p["name"] == name:
                p["url"] = ss_url
                break
        else:
            cfg["proxies"].append({"name": name, "type": "ss", "url": ss_url})

        # 添加到 proxy-group
        if group_name:
            if "proxy-groups" not in cfg:
                cfg["proxy-groups"] = []

            group = next((g for g in cfg["proxy-groups"] if g["name"] == group_name), None)
            if group:
                if "proxies" not in group:
                    group["proxies"] = []
                if name not in group["proxies"]:
                    group["proxies"].append(name)
            else:
                # 如果组不存在，创建一个 select 类型组
                cfg["proxy-groups"].append({
                    "name": group_name,
                    "type": "select",
                    "proxies": [name]
                })

        # 写回 YAML
        with open(self.path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True)

        GlobalLogger().log(f"Proxy {name} added to {self.path}")

class ProxyServer:
    def __init__(self, config):
        self.config = config
        self.ss = SS(self.config.socks_host, self.config.socks_port)
        
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
            return None, None

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

                strategy = self.config.match(host)
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

                # 隧道转发
                asyncio.create_task(self.pipe(reader, remote_writer))
                asyncio.create_task(self.pipe(remote_reader, writer))

            else:
                # 普通 HTTP 请求
                host, port = await self.get_host_from_data(data, writer)
                if not host:
                    GlobalLogger().log(f'host parse err.{data}', 'ERR')
                    return

                strategy = self.config.match(host)
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

                # pipe 双向转发
                asyncio.create_task(self.pipe(reader, remote_writer))
                asyncio.create_task(self.pipe(remote_reader, writer))

        except Exception as e:
            GlobalLogger().log(f"{e}", level='ERR')
            writer.close()
    # pipe 双向转发
    async def pipe(self, r, w):
        try:
            while True:
                buf = await r.read(4096)
                if not buf:
                    break
                w.write(buf)
                await w.drain()
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
            self.handle_client, self.config.listen_host, self.config.listen_port
        )
        GlobalLogger().log(f"Proxy running at {self.config.listen_host}:{self.config.listen_port}")
        async with server:
            await server.serve_forever()


class GlobalLogger(QObject):
    new_log = Signal(str, str, str)  # timestamp, level, message

    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        super().__init__()
        self._initialized = True

        # 线程安全队列
        self._queue = Queue()

        # 定时器刷新队列
        self._timer = QTimer()
        self._timer.timeout.connect(self._flush)
        self._timer.start(200)  # 200ms 刷新一次

    def log(self, message, level='INFO', timestamp=None):
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 直接放入队列，不发信号
        self._queue.put((timestamp, level, message))

    def _flush(self):
        while not self._queue.empty():
            timestamp, level, message = self._queue.get()
            self.new_log.emit(timestamp, level, message)


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
                GlobalLogger().log('ss-local:'+message , level, timestamp)  # 发给全局日志

            else:
                GlobalLogger().log(f"sslocal logreader err: 格式不匹配")
  
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
            "-v"                            # verbose
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

class SubscribeInputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("输入subscribe, https:// or ss://")
        self.resize(400, 100)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("粘贴你的订阅 URL:"))

        self.url_edit = QLineEdit()
        layout.addWidget(self.url_edit)

        btn_layout = QHBoxLayout()
        self.btn_ok = QPushButton("确定")
        self.btn_cancel = QPushButton("取消")
        btn_layout.addWidget(self.btn_ok)
        btn_layout.addWidget(self.btn_cancel)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

        self.btn_ok.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

    def get_url(self):
        return self.url_edit.text().strip()
class QRCodeDialog(QDialog):
    def __init__(self, data):
        super().__init__()
        self.setWindowTitle("Share Node QR Code")
        layout = QVBoxLayout()
        self.label = QLabel()
        layout.addWidget(self.label)
        self.setLayout(layout)

        pixmap = self.generate_qrcode_pixmap(data)
        self.label.setPixmap(pixmap)

    def generate_qrcode_pixmap(self, data):
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')  # 转PIL Image
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qimg = QImage.fromData(buffer.getvalue())
        return QPixmap.fromImage(qimg)
class NodeTree(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Node"])
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
    def show_context_menu(self, pos):
        item = self.itemAt(pos)
        if item:
            menu = QMenu(self)
            delete_action = menu.addAction("Delete Node")
            delete_action.triggered.connect(lambda: self.delete_node(item))
            share_action = menu.addAction('Share')
            share_action.triggered.connect(lambda: self.share_node(item))
            menu.exec(self.viewport().mapToGlobal(pos))
    
    def share_node(self, item):
        ss_link = item.data(0, Qt.UserRole)
        if not ss_link:
            ss_link = "No ss:// link to share"
        dlg = QRCodeDialog(ss_link)
        dlg.exec()

    def add_node(self, node_name, sub_nodes):
            # 先找有没有同名顶层父节点
            parent_items = self.findItems(node_name, Qt.MatchExactly)
            if parent_items:
                parent = parent_items[0]
                self._add_subnodes(parent, sub_nodes)
            else:
                parent = QTreeWidgetItem(self, [node_name])
                self.addTopLevelItem(parent)
                self._add_subnodes(parent, sub_nodes)
            parent.setExpanded(True)

    def _add_subnodes(self, parent_node, sub_nodes):
        for name, ss_url in sub_nodes:
            # 可以判断避免重复添加
            exists = False
            for i in range(parent_node.childCount()):
                if parent_node.child(i).text(0) == name:
                    exists = True
                    break
            if not exists:
                child = QTreeWidgetItem(parent_node, [name])
                child.setData(0, Qt.UserRole, ss_url)
                parent_node.addChild(child)

    def delete_node(self, item):
        parent = item.parent()
        if parent is None:
            index = self.indexOfTopLevelItem(item)
            if index != -1:
                self.takeTopLevelItem(index)
        else:
            parent.removeChild(item)

class HomePage(QWidget):
    def __init__(self, server):
        super().__init__()
        layout = QVBoxLayout()
        self.server = server
        #        
        self.btn_add_subscribe = QPushButton("+ add subscribe url")
        layout.addWidget(self.btn_add_subscribe)
        self.btn_add_subscribe.clicked.connect(self.show_subscribe_dialog)

        # SSR 开关
        self.btn_ssr_toggle = QPushButton("Start SSR")
        self.btn_ssr_toggle.setCheckable(True)
        self.btn_ssr_toggle.clicked.connect(self.toggle_ssr)
        layout.addWidget(self.btn_ssr_toggle)

        # 订阅节点树
        layout.addWidget(QLabel("Subscribed Nodes:"))
        self.tree = NodeTree()
        layout.addWidget(self.tree)

        self.setLayout(layout)

        # 
        self.load_proxies_to_tree()
    def load_proxies_to_tree(self):
        # 先加载 proxy-groups
        proxy_groups = self.server.config.proxy_groups
        proxies = self.server.config.proxies
        for name, group in proxy_groups.items():
            for proxy_name in group['proxies']:
                p = proxies.get(proxy_name)
                self.tree.add_node(name, [(p['name'], p['url'])])

    def show_subscribe_dialog(self):
        dialog = SubscribeInputDialog(self)
        if dialog.exec() == QDialog.Accepted:
            url = dialog.get_url()
            if url.startswith("http"):
                GlobalLogger().log(f'will subscribe {url}')
                if not url:
                    QMessageBox.warning(self, "警告", "订阅 URL 不能为空")
                e, res = self.server.ss.get(url)
                sslinks = base64.b64decode(res.text.strip()).decode('utf-8').split('\n')
                for sslink in sslinks:
                    ss_info = parse_ss_link(sslink)
                    print(ss_info)
                    if ss_info:
                        self.server.config.add_ss_proxy(ss_info['remark'], sslink)            
                self.tree.clear()
                self.load_proxies_to_tree()

            elif url.startswith('ss://'):
                self.server.config.add_ss_proxy(parse_ss_link(url)['remark'], url)            
                self.tree.clear()
                self.load_proxies_to_tree()


    def toggle_ssr(self, checked):
        if checked:
            self.btn_ssr_toggle.setText("Stop SSR")
            QMessageBox.information(self, "SSR", "SSR started")
            # 这里启动 SSR 逻辑
            selected_item = self.tree.currentItem()
            if selected_item:
                node_name = selected_item.text(0)                # 节点名称
                ss_url = selected_item.data(0, Qt.UserRole)      # 绑定的 ss:// 数据（如果有）
                self.server.ss.connect_ss(ss_url)
            else:
                GlobalLogger().log("没有选中节点", 'ERR')

        else:
            self.btn_ssr_toggle.setText("Start SSR")
            QMessageBox.information(self, "SSR", "SSR stopped")
            # 这里关闭 SSR 逻辑
            self.server.ss.close_ss()
            
class ConfPage(QWidget):
    def __init__(self, config):
        super().__init__()
        self.config = config

        layout = QVBoxLayout()
        self.setLayout(layout)
        self.label = QLabel(f'R/W: {self.config.path}')
        layout.addWidget(self.label)

        self.editor = QPlainTextEdit()
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)  # 禁止自动换行
        self.editor.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # 出现水平滚动条
        layout.addWidget(self.editor)

        save_btn = QPushButton("Save Config")
        save_btn.clicked.connect(self.save_conf)
        layout.addWidget(save_btn)

        self.load_conf()

    def load_conf(self):
        try:
            with open(self.config.path, "r", encoding="utf-8") as f:
                content = f.read()
            self.editor.setPlainText(content)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load config: {e}")

    def save_conf(self):
        try:
            content = self.editor.toPlainText()
            with open(self.config.path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Saved", "Configuration saved successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save config: {e}")
class LogProxyOptionsWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout()

        self.isopen_cb = QCheckBox("DNS Logging Enabled")
        layout.addWidget(self.isopen_cb)

        # 这里可以扩展更多DNS选项，比如日志过滤、刷新按钮等
        self.refresh_btn = QPushButton("Refresh DNS Logs")
        layout.addWidget(self.refresh_btn)

        self.setLayout(layout)


class LogWidget(QWidget):
    new_log = Signal(str, str, str)
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)      # 只读
        layout.addWidget(self.log_text)

        self.logs = []  # [(timestamp, level, message), ...]

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_logs)
        self.timer.start(5000)  # 每秒刷新

        # 假设你有全局日志信号
        GlobalLogger().new_log.connect(self.add_log)

    def add_log(self, timestamp, level, message):
        self.logs.append((timestamp, level, message))

    def refresh_logs(self):
        # 清空并重新显示（如果日志太多，也可以改为只追加最新几条）
        self.log_text.clear()
        for t, lvl, msg in self.logs:
            self.log_text.appendPlainText(f"[{t}] [{lvl}] {msg}")

class NodeStatsWidget(QWidget):
    def __init__(self, server):
        super().__init__()
        self.server = server  # 你的 SSR/SS 服务对象
        layout = QVBoxLayout()
        self.text = QTextEdit()
        self.text.setReadOnly(True)  # 只读，不允许编辑
        layout.addWidget(self.text)
        self.setLayout(layout)

        # 定时刷新
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000)  # 每2秒刷新一次

        self.update_stats()

    def update_stats(self):
        self.text.clear()
        nodes = self.server.get_all_nodes_stats()  # 你需要在 server 提供方法返回 list/dict
        for node in nodes:
            up = node.get('up_bytes', 0)/1024
            down = node.get('down_bytes', 0)/1024
            total = node.get('total_bytes', 0)/1024
            self.text.append(
                f"{node['name']}: Up {up:.1f} KB, Down {down:.1f} KB, Total {total:.1f} KB"
            )

class DataPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        # 统计项
        stats_label = QLabel("Statistics: TODO")  # 这里你可以换成具体统计控件
        layout.addWidget(stats_label)

        # 日志组
        logs_label = QLabel("log:")
        layout.addWidget(LogWidget())

        self.setLayout(layout)
class ThemeManager:
    def __init__(self, app):
        self.app = app
        self.dark_mode = False  # 默认浅色主题

    def apply_dark_theme(self):
        qss = """
        QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
            font-size: 14px;
        }
        QLineEdit, QComboBox, QTreeWidget, QTableWidget {
            background-color: #3c3f41;
            border: 1px solid #555;
            padding: 4px;
            color: white;
        }
        QPushButton {
            background-color: #555;
            border: 1px solid #666;
            padding: 5px 10px;
            border-radius: 3px;
        }
        QPushButton:hover {
            background-color: #666;
        }
        QHeaderView::section {
            background-color: #444;
            padding: 4px;
            border: 1px solid #666;
        }
        """
        self.app.setStyleSheet(qss)

    def apply_light_theme(self):
        qss = """
        QWidget {
            background-color: #f5f5f5;
            color: #000000;
            font-size: 14px;
        }
        QLineEdit, QComboBox, QTreeWidget, QTableWidget {
            background-color: #ffffff;
            border: 1px solid #ccc;
            padding: 4px;
            color: black;
        }
        QPushButton {
            background-color: #ddd;
            border: 1px solid #aaa;
            padding: 5px 10px;
            border-radius: 3px;
        }
        QPushButton:hover {
            background-color: #ccc;
        }
        QHeaderView::section {
            background-color: #eee;
            padding: 4px;
            border: 1px solid #ccc;
        }
        """
        self.app.setStyleSheet(qss)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

class SettingPage(QWidget):
    def __init__(self, theme_manager, version="1.0.1"):
        super().__init__()
        self.theme_manager = theme_manager
        layout = QVBoxLayout()

        # 主题选择
        self.btn_toggle_theme = QPushButton("Toggle Theme")
        self.btn_toggle_theme.clicked.connect(self.theme_manager.toggle_theme)
        layout.addWidget(self.btn_toggle_theme)

        # 版本信息
        version_label = QLabel(f"版本: {version}")
        layout.addWidget(version_label)

        self.setLayout(layout)

class MainWindow(QMainWindow):
    def __init__(self, theme_manager, config, server):
        super().__init__()
        self.theme_manager = theme_manager
        self.config = config
        self.server = server

        self.setWindowTitle("SSR-like Client")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QHBoxLayout(central_widget)

        # 导航列表
        self.nav_list = QListWidget()
        self.nav_list.addItems(["Home", "Conf", "Data", "Setting"])
        self.nav_list.setFixedWidth(100)
        self.nav_list.currentRowChanged.connect(self.display_page)

        # 堆栈页面
        self.pages = QStackedWidget()
        self.pages.addWidget(HomePage(self.server))
        self.pages.addWidget(ConfPage(self.config))
        self.pages.addWidget(DataPage())
        self.pages.addWidget(SettingPage(theme_manager))

        layout.addWidget(self.nav_list)
        layout.addWidget(self.pages)

        self.nav_list.setCurrentRow(0)  # 默认选中首页


    def display_page(self, index):
        self.pages.setCurrentIndex(index)

    def closeEvent(self, event):
        # 优雅终止子进程
        self.server.ss.close_ss()
        # 关闭其他资源，如打开的socket、文件等

        event.accept()  # 允许窗口关闭

def start_server():
    GlobalLogger().log(f'proxy server thread start: {threading.get_ident()}')
    asyncio.run(server.run())

if __name__ == "__main__":
    app = QApplication([])
    theme_manager = ThemeManager(app)
    theme_manager.apply_light_theme()  # 初始浅色
    config = Config()
    server = ProxyServer(config)
    window = MainWindow(theme_manager, config, server)

    threading.Thread(target=start_server, daemon=True).start()
    window.resize(800, 600)
    window.show()
    app.exec()
