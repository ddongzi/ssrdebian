from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QListWidget,
    QStackedWidget, QLabel, QHBoxLayout, QPushButton, QComboBox, QMessageBox,
    QLineEdit, QFormLayout, QDialogButtonBox, QDialog, QTreeWidget,
    QTreeWidgetItem, QCheckBox, QGroupBox, QMenu
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

class GlobalLogger(QObject):
    new_log = Signal(str, str, str)  # timestamp, level, message

    _instance = None
    _mutex = QMutex()
    _initialized = False
    def __new__(cls):
        if not cls._instance:
            cls._mutex.lock()
            try:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
            finally:
                cls._mutex.unlock()
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        super().__init__()
        self._initialized = True
        # 这里放初始化代码

    def log(self, timestamp, level, message):
        # 线程安全写入（可加锁或用线程安全队列）
        self.new_log.emit(timestamp, level, message)

class SSLocalLogReader(QObject):
    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            line = self.proc.stdout.readline()

            if not line:
                break
            line = line.strip()
            pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+): (.*)$"

            m = re.match(pattern, line)
            if m:
                timestamp, level, message = m.groups()
                GlobalLogger().log(timestamp, level, message)  # 发给全局日志

            else:
                print("格式不匹配")
  
class SS(QObject):
    def __init__(self):
        super().__init__()
        self.proc = None
        self.thread = None
        self.running = False
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 1080
        self.proxies = {
           "http": f"socks5h://{self.proxy_host}:{self.proxy_port}",
            "https": f"socks5h://{self.proxy_host}:{self.proxy_port}"
        }

    def start_ss(self, ss_link):
        ss_info = parse_ss_link(ss_link)

        cmd = [
            "ss-local",
            "-s", ss_info['host'],          # 服务器 IP
            "-p", str(ss_info['port']),     # 服务器端口
            "-k", ss_info['password'],      # 密码
            "-m", ss_info['method'],        # 加密方式
            "-b", "127.0.0.1",              # 本地监听地址
            "-l", "1080",                   # 本地 SOCKS5 端口
            "-v"                            # verbose
        ]

        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"Shadowsocks 启动中... {cmd}")
        # 创建线程和日志读取器
        self.thread = QThread()
        self.log_worker = SSLocalLogReader(self.proc)
        self.log_worker.moveToThread(self.thread)
        self.thread.started.connect(self.log_worker.run)
        self.thread.start()
        self.running = True

    def stop_ss(self):
        self.running = False
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None
            self.log_worker.stop()
            if self.thread and self.thread.isRunning():
                self.thread.quit()    # 让线程退出事件循环
                self.thread.wait()    # 等待线程退出
            print("Shadowsocks 已停止")

    def test_shadowsocks_proxy(self, test_url="https://www.google.com"):
        
        e, res = self.get(test_url)
        print('test proxy', e, res)
        if  e:
            return False
        if res.status_code == 200:
            return True
        else:
            return False
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
            print(f"代理测试异常: {e}")
            return e, None
    
    def add_node_2json(self, newnode):
        # 读取 JSON 文件
        with open(resource_path('resources/config.json'), "r", encoding="utf-8") as f:
            data = json.load(f)  # data 是一个 list

        # 追加到数组
        data.append(newnode)

        # 写回文件
        with open(resource_path('resources/config.json'), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

class EditParentNodeDialog(QDialog):
    def __init__(self, node_data=None):
        super().__init__()
        self.setWindowTitle("Edit Parent Node Info")

        self.node_data = node_data or {
            "type": "subscribe",
            "url": "",
            "nickname": ""
        }

        self.type_combo = QComboBox()
        self.type_combo.addItems(["subscribe", "socks5", "vmess", "https", "trojan"])
        self.type_combo.setCurrentText(self.node_data.get("type", "subscribe"))

        self.url_edit = QLineEdit(self.node_data.get("url", ""))
        self.nickname_edit = QLineEdit(self.node_data.get("nickname", ""))

        form = QFormLayout()
        form.addRow("Type:", self.type_combo)
        form.addRow("URL:", self.url_edit)
        form.addRow("Nickname:", self.nickname_edit)

        self.share_btn = QPushButton("Share Node (JSON)")
        self.share_btn.clicked.connect(self.share_node)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(self.share_btn)
        layout.addWidget(QLabel("（二维码分享功能可用第三方库如 qrcode 实现）"))
        layout.addWidget(buttons)
        self.setLayout(layout)

    def share_node(self):
        data = {
            "type": self.type_combo.currentText(),
            "url": self.url_edit.text(),
            "nickname": self.nickname_edit.text()
        }
        json_str = json.dumps(data, indent=2)
        # 简单弹窗展示 JSON，后续可以做复制到剪贴板或生成二维码
        QMessageBox.information(self, "Share Node JSON", json_str)

    def get_data(self):
        return {
            "type": self.type_combo.currentText(),
            "url": self.url_edit.text(),
            "nickname": self.nickname_edit.text()
        }
class EditSubNodeDialog(QDialog):
    def __init__(self, node_data=None):
        super().__init__()
        self.setWindowTitle("Edit Sub-Node Info")

        self.node_data = node_data or {"type": "socks5"}

        self.type_combo = QComboBox()
        self.type_combo.addItems(["socks5", "vmess", "trojan"])
        self.type_combo.setCurrentText(self.node_data.get("type", "socks5"))
        self.type_combo.currentIndexChanged.connect(self.update_form_fields)

        self.form_layout = QFormLayout()

        # 通用字段控件
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.passwd_edit = QLineEdit()
        self.alg_edit = QLineEdit()

        # 按类型组织字段，便于动态展示
        self.fields_map = {
            "socks5": [("Host", self.host_edit), ("Port", self.port_edit), ("Password", self.passwd_edit)],
            "vmess": [("Host", self.host_edit), ("Port", self.port_edit), ("Algorithm", self.alg_edit)],
            "trojan": [("Host", self.host_edit), ("Port", self.port_edit), ("Password", self.passwd_edit)],
        }

        # 初始化表单
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self)
        self.main_layout.addWidget(QLabel("Type:"))
        self.main_layout.addWidget(self.type_combo)
        self.main_layout.addLayout(self.form_layout)

        # 按钮区
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.main_layout.addWidget(buttons)

        self.setLayout(self.main_layout)

        # 填充默认值
        self.fill_default_values()
        self.update_form_fields()

    def fill_default_values(self):
        self.host_edit.setText(self.node_data.get("host", ""))
        self.port_edit.setText(str(self.node_data.get("port", "")))
        self.passwd_edit.setText(self.node_data.get("password", ""))
        self.alg_edit.setText(self.node_data.get("algorithm", ""))

    def update_form_fields(self):
        # 清空现有字段
        while self.form_layout.count():
            item = self.form_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        current_type = self.type_combo.currentText()
        fields = self.fields_map.get(current_type, [])

        for label, widget in fields:
            self.form_layout.addRow(label + ":", widget)

    def get_data(self):
        data = {"type": self.type_combo.currentText()}
        current_type = data["type"]
        fields = self.fields_map.get(current_type, [])

        for label, widget in fields:
            key = label.lower().replace(" ", "")
            data[key] = widget.text()

        return data
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
    def __init__(self, ss):
        super().__init__()
        layout = QVBoxLayout()
        self.ss = ss

        #        
        self.btn_add_subscribe = QPushButton("+ add subscribe url")
        layout.addWidget(self.btn_add_subscribe)
        self.btn_add_subscribe.clicked.connect(self.show_subscribe_dialog)

        # SSR 开关
        self.btn_ssr_toggle = QPushButton("Start SSR")
        self.btn_ssr_toggle.setCheckable(True)
        self.btn_ssr_toggle.clicked.connect(self.toggle_ssr)
        layout.addWidget(self.btn_ssr_toggle)

        # test
        self.btn_test_proxy = QPushButton("测试 Shadowsocks 代理")
        layout.addWidget(self.btn_test_proxy)
        self.btn_test_proxy.clicked.connect(self.on_test_proxy_clicked)

        # 订阅节点树
        layout.addWidget(QLabel("Subscribed Nodes:"))
        self.tree = NodeTree()
        layout.addWidget(self.tree)

        self.setLayout(layout)

        # 
        self.load_from_json(resource_path('resources/config.json'))

    def show_subscribe_dialog(self):
        dialog = SubscribeInputDialog(self)
        if dialog.exec() == QDialog.Accepted:
            url = dialog.get_url()
            if url.startswith("http"):
                print('subscribe: ', url)
                if not url:
                    QMessageBox.warning(self, "警告", "订阅 URL 不能为空")
                e, res = self.ss.get(url)
                sslinks = base64.b64decode(res.text.strip()).decode('utf-8').split('\n')
                subnodes = []
                for ss in sslinks:
                    if not ss.strip():  # 跳过空行
                        continue
                    info = parse_ss_link(ss)
                    if info is None:  # 跳过无法解析的
                        continue
                    subnodes.append((info['remark'], ss))

                self.tree.add_node(urlparse(url).hostname, subnodes)
                # store it into json
                newnode = {
                    'title': urlparse(url).hostname,
                    'host':url,
                    'subs':sslinks
                }
                self.ss.add_node_2json(newnode)
            elif url.startswith('ss://'):
                self.tree.add_node('FREEDOM', [(parse_ss_link(url)['remark'], url)])
                with open(resource_path('resources/config.json'), "r", encoding="utf-8") as f:
                    data = json.load(f)  # data 是一个 list
                    freedom = data[0]
                    freedom['subs'].append(url)
                    # 写回文件
                    with open(resource_path('resources/config.json'), "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)

    def on_test_proxy_clicked(self):
        ok = self.ss.test_shadowsocks_proxy()
        if ok:
            QMessageBox.information(self, "代理测试", "Shadowsocks 代理工作正常！")
        else:
            QMessageBox.warning(self, "代理测试", "代理测试失败，请检查配置或连接。")

    def load_from_json(self, filepath):
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump([{
                    "title": "FREEDOM",
                    "subs": []
                    }], 
                    f, ensure_ascii=False, indent=2
                )

        try:
            with open(filepath, 'r') as f:
                nodes = json.load(f)
        except Exception as e:
            nodes = []

        for node in nodes:
            name = node.get('title','unknown')
            sslinks = node.get('subs', [])
            subnodes = []
            for ss in sslinks:
                if not ss.strip():  # 跳过空行
                    continue
                info = parse_ss_link(ss)
                if info is None:  # 跳过无法解析的
                    continue
                subnodes.append((info['remark'], ss))
            self.tree.add_node(name, subnodes)
       
    def toggle_ssr(self, checked):
        if checked:
            self.btn_ssr_toggle.setText("Stop SSR")
            QMessageBox.information(self, "SSR", "SSR started")
            # 这里启动 SSR 逻辑
            selected_item = self.tree.currentItem()
            if selected_item:
                node_name = selected_item.text(0)                # 节点名称
                ss_url = selected_item.data(0, Qt.UserRole)      # 绑定的 ss:// 数据（如果有）
                print("选中节点名:", node_name)
                print("对应的 ss:// 地址:", ss_url)
                self.ss.start_ss(ss_url)
            else:
                print("没有选中节点")

        else:
            self.btn_ssr_toggle.setText("Start SSR")
            QMessageBox.information(self, "SSR", "SSR stopped")
            # 这里关闭 SSR 逻辑
            self.ss.stop_ss()
            
    def route_changed(self, index):
        route = self.route_combo.currentText()
        QMessageBox.information(self, "Route", f"Route changed to {route}")
        # 这里写路由切换逻辑

    def add_edit_button(self, item):
        btn = QPushButton("Info")
        self.tree.setItemWidget(item, 1, btn)
        btn.clicked.connect(lambda checked, it=item: self.edit_node(it))

    def edit_node(self, item):
        # 这里假设 item.data(0, Qt.UserRole) 存着节点信息字典
        node_data = item.data(0, Qt.UserRole) or {}

        node_type = node_data.get("type", "sub")  # 假设父节点是 "parent" 或 type为订阅相关的

        if node_type == "parent" or node_type == "subscribe":
            dialog = EditParentNodeDialog(node_data)
        else:
            dialog = EditSubNodeDialog(node_data)

        if dialog.exec() == QDialog.Accepted:
            new_data = dialog.get_data()
            item.setText(0, new_data.get("nickname") or new_data.get("name") or item.text(0))
            # 更新 item 存储的数据
            item.setData(0, Qt.UserRole, new_data)


class ConfPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Configuration Page"))
        self.setLayout(layout)
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
    def __init__(self):
        super().__init__()
        self.log_tree = QTreeWidget()
        self.log_tree.setHeaderLabels(["Time", "Level", "Message"])

        layout = QVBoxLayout()
        layout.addWidget(self.log_tree)
        self.setLayout(layout)

        self.logs = []  # [(timestamp, level, message), ...]

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_logs)
        self.timer.start(2000)  # 2秒刷新一次

        GlobalLogger().new_log.connect(self.add_log)

    def add_log(self, timestamp, level, message):
        self.logs.append((timestamp, level, message))

    def refresh_logs(self):
        # 先清空
        self.log_tree.clear()

        # 按等级分组
        groups = {}
        for t, lvl, msg in self.logs:
            if lvl not in groups:
                groups[lvl] = []
            groups[lvl].append((t, msg))

        # 按等级顺序展示（自定义顺序）
        level_order = ["ERROR", "WARN", "INFO", "DEBUG"]
        for lvl in level_order:
            if lvl in groups:
                parent = QTreeWidgetItem(self.log_tree, [ "", lvl ])
                for t, msg in groups[lvl]:
                    QTreeWidgetItem(parent, [t, "", msg])

        self.log_tree.expandAll()

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
    def __init__(self, theme_manager, version="1.0.0"):
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
    def __init__(self, theme_manager):
        super().__init__()
        self.ss = SS()
        self.theme_manager = theme_manager
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
        self.pages.addWidget(HomePage(self.ss))
        self.pages.addWidget(ConfPage())
        self.pages.addWidget(DataPage())
        self.pages.addWidget(SettingPage(theme_manager))

        layout.addWidget(self.nav_list)
        layout.addWidget(self.pages)

        self.nav_list.setCurrentRow(0)  # 默认选中首页


    def display_page(self, index):
        self.pages.setCurrentIndex(index)

    def closeEvent(self, event):
        # 优雅终止子进程
        self.ss.stop_ss()
        # 关闭其他资源，如打开的socket、文件等

        event.accept()  # 允许窗口关闭

if __name__ == "__main__":
    app = QApplication([])
    theme_manager = ThemeManager(app)
    theme_manager.apply_light_theme()  # 初始浅色
    window = MainWindow(theme_manager)
    window.resize(800, 600)
    window.show()
    app.exec()
