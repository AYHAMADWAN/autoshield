import sys
import os
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QPushButton,
    QCheckBox, QTextEdit, QFileDialog, QLineEdit, QHBoxLayout, QGroupBox
)
from PyQt6.QtGui import QPixmap, QPalette, QColor
from PyQt6.QtCore import Qt
from fileScans import PAMConfScan, FileConfScan, PermissionScan
from networkScans import PortScan
# from perms import main as perm_main
# from ports import main as port_main

class AutoShieldGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux AutoShield")
        self.setGeometry(200, 100, 1000, 700)
        self.setStyleSheet("background-color: #121212; color: #ffffff;")

        self.layout = QVBoxLayout()

        # Background Image
        self.bg_label = QLabel(self)
        pixmap = QPixmap("Logo 1.png")
        pixmap = pixmap.scaledToWidth(180)
        self.bg_label.setPixmap(pixmap)
        self.bg_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.layout.addWidget(self.bg_label)

        # Checkboxes
        self.check_passwords = QCheckBox("Password Scan")
        self.check_config = QCheckBox("Config Scan")
        self.check_permissions = QCheckBox("Permission Scan")
        self.check_ports = QCheckBox("Port Scan")
        self.check_remote = QCheckBox("Remote Scan")

        for cb in [self.check_passwords, self.check_config, self.check_permissions, self.check_ports, self.check_remote]:
            cb.setStyleSheet("QCheckBox { color: #ffffff; font-size: 14px; }")
            self.layout.addWidget(cb)

        # Input Fields (Optional/Advanced)
        self.input_group = QGroupBox("Advanced Options")
        self.input_group.setStyleSheet("QGroupBox { border: 1px solid #555; margin-top: 10px; }")
        self.input_layout = QVBoxLayout()

        self.port_ip = QLineEdit()
        self.port_ip.setPlaceholderText("Target IP (default: 127.0.0.1)")
        self.port_ip.setStyleSheet("background-color: #1e1e1e; color: #00ffff;")
        self.input_layout.addWidget(self.port_ip)

        self.root_dir = QLineEdit()
        self.root_dir.setPlaceholderText("Permission Scan Root Dir (default: /)")
        self.root_dir.setStyleSheet("background-color: #1e1e1e; color: #00ffff;")
        self.input_layout.addWidget(self.root_dir)

        self.input_group.setLayout(self.input_layout)
        self.layout.addWidget(self.input_group)

        # Run button
        self.run_button = QPushButton("Run Selected Scans")
        self.run_button.setStyleSheet("QPushButton { background-color: #00bcd4; color: white; padding: 10px; font-size: 14px; }")
        self.run_button.clicked.connect(self.run_scans)
        self.layout.addWidget(self.run_button)

        # Output Area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        self.layout.addWidget(self.output)

        self.setLayout(self.layout)

    def run_scans(self):
        self.output.clear()
        self.output.append("[+] Starting scans...\n")
        shutdown_event = threading.Event() # <----- use to handle signals later

        def run():
            if self.check_passwords.isChecked():
                self.output.append("\n[🔍] Running Password Scan...")
                PAMConfScan()

            if self.check_config.isChecked():
                self.output.append("\n[🔍] Running Config Scan...")
                FileConfScan()

            if self.check_permissions.isChecked():
                self.output.append("\n[🔍] Running Permission Scan...")
                root = self.root_dir.text() if self.root_dir.text() else "/"
                PermissionScan(shutdown_event, root_dir=root)

            if self.check_ports.isChecked():
                self.output.append("\n[🔍] Running Port Scan...")
                target = self.port_ip.text() if self.port_ip.text() else "127.0.0.1"
                PortScan(shutdown_event, target=target)

            if self.check_remote.isChecked():
                self.output.append("\n[🔍] Running Remote Scan (using defaults)...")
                PAMConfScan(True)
                FileConfScan(True)

            self.output.append("\n✅ Scan complete.")

        run()
        # thread = threading.Thread(target=run) # <--------causes segmentation fault
        # thread.start()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AutoShieldGUI()
    window.show()
    sys.exit(app.exec())