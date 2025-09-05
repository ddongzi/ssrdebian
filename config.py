from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal, QMutex
import yaml
from tools import resource_path
from logger import GlobalLogger
import os

# global_config
class Config(QObject):
    _instance = None
    config_changed = Signal()
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, path="resources/config.yml"):
        if hasattr(self, '_initialized') and self._initialized:
            return
        super().__init__()
        self._initialized = True

        self.path = resource_path(path)
        self.load_config()
        GlobalLogger().log(f'load config from: {self.path}')

        self.config_changed.connect(self.load_config)
    
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
    
    def add_ss_proxy(self, name, ss_url, group_name='MY-GROUP'):
        # 添加或更新节点
        self.proxies[name] = {"name": name, "type": "ss", "url": ss_url}

        # 添加到组
        if group_name not in self.proxy_groups:
            self.proxy_groups[group_name] = {"name": group_name, "type": "select", "proxies": []}
        if name not in self.proxy_groups[group_name]["proxies"]:
            self.proxy_groups[group_name]["proxies"].append(name)

        self.config_changed.emit()  # UI 通知

    def remove_ss_proxy(self, name=None, group_name=None):
        # 删除节点
        if name and name in self.proxies:
            del self.proxies[name]
            # 同时从所有组移除
            for g in self.proxy_groups.values():
                if "proxies" in g and name in g["proxies"]:
                    g["proxies"].remove(name)

        # 删除组
        if group_name and group_name in self.proxy_groups:
            del self.proxy_groups[group_name]
        self.save()
        self.config_changed.emit()  # UI 通知

    def save(self):
        cfg = {
            "server": {
                "listen_host": self.listen_host,
                "listen_port": self.listen_port,
                "socks_host": self.socks_host,
                "socks_port": self.socks_port
            },
            "proxies": list(self.proxies.values()),
            "proxy-groups": list(self.proxy_groups.values()),
            "rules": [",".join([r[0], r[1]] if r[2] is None else r) for r in self.rules]
        }
        with open(self.path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True)
_global_instance = None
def get_config():
    global _global_instance
    if _global_instance is None:
        _global_instance = Config()
    return _global_instance

def get_config_path():
    return get_config().path