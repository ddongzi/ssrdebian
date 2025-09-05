from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QListWidget,
    QStackedWidget, QLabel, QHBoxLayout, QPushButton, QComboBox, QMessageBox,
    QLineEdit, QFormLayout, QDialogButtonBox, QDialog, QTreeWidget,
    QTreeWidgetItem, QCheckBox, QGroupBox, QMenu, QPlainTextEdit, QTextEdit, QHeaderView
)
from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal, QMutex
from PySide6.QtGui import QPixmap, QImage, QFont
import qrcode
from io import BytesIO
# from PIL import Image
import threading
import json
import base64

from urllib.parse import urlparse
import asyncio
from config import get_config, get_config_path
from logger import GlobalLogger
from tools import resource_path, parse_ss_link
from server import ProxyServer, start_server

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
    
class NodeTreeItemStatusWidget(QWidget):
    COLORS = {"online": "green", "offline": "red", "checking": "orange"}
    latency_changed = Signal(object)
    def __init__(self, status="checking", latency=None):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.light = QLabel()
        self.light.setFixedSize(12, 12)
        layout.addWidget(self.light)

        self.latency_label = QLabel()
        layout.addWidget(self.latency_label)

        self.latency_changed.connect(self.on_latency_changed)

        self.set_status(status, latency)

    def on_latency_changed(self, latency):
        self.set_status("online" if latency is not None else "offline", latency)

    def set_status(self, status, latency=None):
        color = self.COLORS.get(status, "gray")
        self.light.setStyleSheet(f"background-color: {color}; border-radius: 6px;")

        if latency is not None:
            self.latency_label.setText(f"{latency} ms")
        else:
            self.latency_label.setText("-1 ms")

class NodeTree(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Node", 'Status'])
        header = self.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)   # 列 0 占满剩余空间
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # 列 1 宽度随内容
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

    def add_node(self, parent_node_name, sub_node_data):
        # 先找有没有同名顶层父节点
        parent_items = self.findItems(parent_node_name, Qt.MatchExactly)
        if parent_items:
            parent = parent_items[0]
            self._add_subnodes(parent, sub_node_data)
        else:
            parent = QTreeWidgetItem(self)
            parent.setText(0, parent_node_name)
            self.addTopLevelItem(parent)
            self._add_subnodes(parent, sub_node_data)
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
                child = QTreeWidgetItem(parent_node)
                child.setText(0, name)
                child.setData(0, Qt.UserRole, ss_url)
                status = NodeTreeItemStatusWidget('checking')
                self.setItemWidget(child, 1, status)

    def delete_node(self, item):
        parent = item.parent()
        if parent is None:
            index = self.indexOfTopLevelItem(item)
            if index != -1:
                self.takeTopLevelItem(index)
            get_config().remove_ss_proxy(None, item.text(0))            
    
        else:
            parent.removeChild(item)
            get_config().remove_ss_proxy(item.text(0), None) 
    def update_latency(self):
        for i in range(self.topLevelItemCount()):
            parent = self.topLevelItem(i)
            for j in range(parent.childCount()):
                child = parent.child(j)
                status_widget = self.itemWidget(child, 1)
                if isinstance(status_widget, NodeTreeItemStatusWidget):
                    ss_info = parse_ss_link(child.data(0, Qt.UserRole))
                    latency_future = server.check_latency_sync(ss_info['host'], ss_info['port'])  # 用已运行 server

                    def on_latency_done(fut, widget=status_widget):
                        try:
                            latency = fut.result()
                        except Exception:
                            latency = None
                        widget.latency_changed.emit(latency)
                    latency_future.add_done_callback(on_latency_done)



class HomePage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        #        
        self.btn_add_subscribe = QPushButton("+ add subscribe url")
        layout.addWidget(self.btn_add_subscribe)
        self.btn_add_subscribe.clicked.connect(self.show_subscribe_dialog)

        # SSR 开关
        self.btn_ssr_toggle = QPushButton("Start SSR")
        self.btn_ssr_toggle.setCheckable(True)
        self.btn_ssr_toggle.clicked.connect(self.toggle_ssr)
        layout.addWidget(self.btn_ssr_toggle)

        self.btn_check_latency = QPushButton('check latency')
        layout.addWidget(self.btn_check_latency)

        # 订阅节点树
        layout.addWidget(QLabel("Subscribed Nodes:"))
        self.tree = NodeTree()
        layout.addWidget(self.tree)

        self.btn_check_latency.clicked.connect(self.tree.update_latency)

        self.setLayout(layout)

        # 
        self.load_proxies_to_tree()
    def load_proxies_to_tree(self):
        # 先加载 proxy-groups
        proxy_groups = get_config().proxy_groups
        proxies = get_config().proxies
        for name, group in proxy_groups.items():
            self.tree.add_node(name, [])
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
                e, res = ProxyServer().ss.get(url)
                sslinks = base64.b64decode(res.text.strip()).decode('utf-8').split('\n')
                for sslink in sslinks:
                    ss_info = parse_ss_link(sslink)
                    if ss_info:
                        get_config().add_ss_proxy(ss_info['remark'], sslink)            
                self.tree.clear()
                self.load_proxies_to_tree()

            elif url.startswith('ss://'):
                get_config().add_ss_proxy(parse_ss_link(url)['remark'], url)            
                self.tree.clear()
                self.load_proxies_to_tree()
            else:
                GlobalLogger().log(f"subscribe err {url}")

    def toggle_ssr(self, checked):
        if checked:
            self.btn_ssr_toggle.setText("Stop SSR")
            QMessageBox.information(self, "SSR", "SSR started")
            # 这里启动 SSR 逻辑
            selected_item = self.tree.currentItem()
            if selected_item:
                node_name = selected_item.text(0)                # 节点名称
                ss_url = selected_item.data(0, Qt.UserRole)      # 绑定的 ss:// 数据（如果有）
                ProxyServer().ss.connect_ss(ss_url)
            else:
                GlobalLogger().log("没有选中节点", 'ERR')

        else:
            self.btn_ssr_toggle.setText("Start SSR")
            QMessageBox.information(self, "SSR", "SSR stopped")
            # 这里关闭 SSR 逻辑
            ProxyServer().ss.close_ss()
            
class ConfPage(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.setLayout(layout)
        self.label = QLabel(f'R/W: {get_config_path()}')
        layout.addWidget(self.label)

        self.editor = QPlainTextEdit()

        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)  # 禁止自动换行
        self.editor.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # 出现水平滚动条
        layout.addWidget(self.editor)

        save_btn = QPushButton("Save Config")
        save_btn.clicked.connect(self.save_conf)
        layout.addWidget(save_btn)

        self.load_conf()
        get_config().config_changed.connect(self.load_conf)

    def load_conf(self):
        try:
            with open(get_config_path(), "r", encoding="utf-8") as f:
                content = f.read()
            
            # 去掉多余回车或换行符
            content = content.replace("\r", "")
            
            self.editor.setPlainText(content)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load config: {e}")


    def save_conf(self):
        try:
            content = self.editor.toPlainText()
            with open(get_config_path(), "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Saved", "Configuration saved successfully!")
            get_config().config_changed.emit()
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
    def __init__(self, max_logs = 500):
        super().__init__()
        layout = QVBoxLayout(self)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)      # 只读
        layout.addWidget(self.log_text)

        self.logs = []  # [(timestamp, level, message), ...]
        self.max_logs = max_logs
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_logs)
        self.timer.start(5000)  # 每秒刷新

        # 假设你有全局日志信号
        GlobalLogger().new_log.connect(self.add_log)

    def add_log(self, timestamp, level, message):
        self.logs.append((timestamp, level, message))
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-50:]

    def refresh_logs(self):
        # 清空并重新显示（如果日志太多，也可以改为只追加最新几条）
        self.log_text.clear()
        for t, lvl, msg in self.logs:
            self.log_text.appendPlainText(f"[{t}] [{lvl}] {msg}")

class StatsWidget(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self.thread_label = QLabel("Threads: 0")
        self.host_label = QLabel("Active Hosts: 0")
        self.speed_label = QLabel("Speed: 0 KB/s")
        self.total_label = QLabel("Total Traffic: 0 KB")

        layout.addWidget(self.thread_label)
        layout.addWidget(self.host_label)
        layout.addWidget(self.speed_label)
        layout.addWidget(self.total_label)

        # 定时刷新
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)  # 每秒刷新

    def update_stats(self):
        # 线程数
        import threading
        threads = threading.active_count()

        # 主机数
        hosts = len(ProxyServer().active_hosts)

        # 流量统计
        now_rx = ProxyServer().bytes_received
        now_tx = ProxyServer().bytes_sent

        # 计算速度
        if not hasattr(self, "_last_rx"):
            self._last_rx, self._last_tx = now_rx, now_tx
            speed_rx = speed_tx = 0
        else:
            speed_rx = (now_rx - self._last_rx) / 1024  # KB/s
            speed_tx = (now_tx - self._last_tx) / 1024
            self._last_rx, self._last_tx = now_rx, now_tx

        # 更新 UI
        self.thread_label.setText(f"Threads: {threads}")
        self.host_label.setText(f"Active Hosts: {hosts}")
        self.speed_label.setText(f"Speed: {speed_rx:.1f} ↓  {speed_tx:.1f} ↑ KB/s")
        self.total_label.setText(f"Total Traffic: {(now_rx+now_tx)/1024:.1f} KB")

class DataPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        # 统计项
        layout.addWidget(StatsWidget())

        # 日志组
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
    def __init__(self, theme_manager, version="1.0.2"):
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
        self.pages.addWidget(HomePage())
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
        ProxyServer().ss.close_ss()
        # 关闭其他资源，如打开的socket、文件等

        event.accept()  # 允许窗口关闭


if __name__ == "__main__":
    app = QApplication([])
    theme_manager = ThemeManager(app)
    theme_manager.apply_light_theme()  # 初始浅色

    window = MainWindow(theme_manager)
    window.resize(800, 600)
    window.show()

    server = ProxyServer()
    threading.Thread(target=server.start, daemon=True).start()

    app.exec()
