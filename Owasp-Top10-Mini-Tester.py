import sys
import validators
import requests
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QGroupBox, QMessageBox
)

# List of basic OWASP checks
OWASP_CHECKS = [
    'SQL Injection (basic payload check)',
    'Reflected XSS test',
    'Insecure cookies (HttpOnly, Secure)',
    'Insecure headers (missing CSP, X-Frame-Options)',
    'Directory listing check',
    'Open redirect pattern test',
    'Sensitive info in response headers',
    'Verbose error messages',
    'HTTP methods allowed (PUT/DELETE)',
    'Weak password form check (common names)'
]

class CheckWorker(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        results = {}
        # simple dummy implementations
        for check in OWASP_CHECKS:
            if check == 'SQL Injection (basic payload check)':
                try:
                    resp = requests.get(self.url + "'?" , timeout=5)
                    results[check] = 'Vulnerable?' if 'sql' in resp.text.lower() else 'Not detected'
                except: results[check] = 'Error'
            elif check == 'Reflected XSS test':
                try:
                    resp = requests.get(self.url + '"<script>alert(1)</script>"', timeout=5)
                    results[check] = 'Vulnerable?' if '<script>alert(1)</script>' in resp.text else 'Not detected'
                except: results[check] = 'Error'
            elif check == 'Insecure cookies (HttpOnly, Secure)':
                try:
                    resp = requests.get(self.url, timeout=5)
                    cookies = resp.cookies
                    results[check] = 'Insecure' if any(not c._rest.get('httponly') or not c._rest.get('secure') for c in cookies) else 'Secure'
                except: results[check] = 'Error'
            elif check == 'Insecure headers (missing CSP, X-Frame-Options)':
                try:
                    resp = requests.get(self.url, timeout=5)
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    missing = []
                    for h in ['content-security-policy','x-frame-options']:
                        if h not in headers:
                            missing.append(h)
                    results[check] = ', '.join(missing) if missing else 'All present'
                except: results[check] = 'Error'
            else:
                results[check] = 'Skipped (demo)'
        self.result_ready.emit(results)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('OWASP Top 10 Mini Tester')
        self.setWindowIcon(QIcon("web4.ico"))
        self.setMinimumSize(700, 550)
        self._worker: CheckWorker | None = None

        self._build_ui()
        self._apply_styles()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        # --- Input group ---
        input_group = QGroupBox('Target URL')
        input_layout = QHBoxLayout()
        input_group.setLayout(input_layout)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('https://example.com or example.com')
        input_layout.addWidget(self.url_input)

        self.check_btn = QPushButton('Run Checks')
        self.check_btn.clicked.connect(self.on_check)
        input_layout.addWidget(self.check_btn)

        layout.addWidget(input_group)

        # Results
        results_group = QGroupBox('Results')
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)

        self.results_table = QTableWidget(len(OWASP_CHECKS), 2)
        self.results_table.setHorizontalHeaderLabels(['Check', 'Result'])
        for i, check in enumerate(OWASP_CHECKS):
            self.results_table.setItem(i, 0, QTableWidgetItem(check))
        self.results_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.results_table)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFixedHeight(120)
        results_layout.addWidget(QLabel('Log'))
        results_layout.addWidget(self.log_box)

        layout.addWidget(results_group)

    def _apply_styles(self):
        self.setStyleSheet('''
        QMainWindow { background: #0f1720; color: #e6eef6; }
        QGroupBox { border: 1px solid #233241; margin-top: 6px; font-weight: 600; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px 0 3px; }
        QLabel { color: #d7e3f2; }
        QLineEdit, QTextEdit { background: #0b1220; border: 1px solid #2b3a4a; padding: 6px; color: #dbeafe; }
        QPushButton { background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #06b6d4); color: white; padding: 8px 12px; border-radius: 8px; }
        QPushButton:disabled { background: #415564; color: #a9b6c3; }
        QTableWidget { background: #06121a; gridline-color: #1e2b36; color: #e6eef6; }
        QHeaderView::section { background: #123548; padding: 4px; }
        QTextEdit { font-family: "Consolas", monospace; }
        ''')

    def on_check(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, 'Input required', 'Please enter a URL to check.')
            return
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        if not validators.url(url):
            QMessageBox.critical(self, 'Invalid URL', 'Enter a valid URL (e.g., https://example.com).')
            return

        self.check_btn.setEnabled(False)
        self.log_box.clear()

        self._worker = CheckWorker(url)
        self._worker.result_ready.connect(self.on_result)
        self._worker.finished.connect(lambda: self.check_btn.setEnabled(True))
        self._worker.start()

    def on_result(self, results: dict):
        for i, check in enumerate(OWASP_CHECKS):
            self.results_table.setItem(i, 1, QTableWidgetItem(results.get(check, 'Skipped')))
            self.log_box.append(f'{check}: {results.get(check)}')

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()