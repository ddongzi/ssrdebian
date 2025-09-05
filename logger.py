import threading
from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal, QMutex
from datetime import datetime
from queue import Queue
from tools import singleton

@singleton
class GlobalLogger(QObject):
    new_log = Signal(str, str, str)  # timestamp, level, message

    def __init__(self):
        super().__init__()

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