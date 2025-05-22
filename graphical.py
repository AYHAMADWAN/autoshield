import sys
import os
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QPushButton,
    QCheckBox, QTextEdit, QLineEdit, QStackedWidget, QHBoxLayout, QGroupBox,
    QScrollArea, QFrame
)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt

from fileScans import PAMConfScan, FileConfScan, PermissionScan
from networkScans import PortScan

class PageOne(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        layout = QVBoxLayout()

        self.banner = QLabel(self)
        pixmap = QPixmap("Logo 1.png").scaledToWidth(180)
        self.banner.setPixmap(pixmap)
        self.banner.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self.banner)

        self.check_passwords = QPushButton("Password Scan")
        self.check_config = QPushButton("Config Scan")
        self.check_permissions = QPushButton("Permission Scan")
        self.check_ports = QPushButton("Port Scan")
        self.check_remote = QPushButton("Remote Scan")
        self.check_firewall = QPushButton("Firewall Rules Scan")
        self.check_outdated = QPushButton("Outdated Software Scan")

        self.checks = [self.check_passwords, self.check_config, self.check_permissions, self.check_ports, self.check_remote, self.check_firewall, self.check_outdated]
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        row3 = QHBoxLayout()
        for i, cb in enumerate(self.checks):
            cb.setStyleSheet("QPushButton { color: #ffffff; font-size: 20px} QPushButton:checked {background-color: white; color: black;}")
            cb.setCheckable(True)
            if i < 3:
                row1.addWidget(cb)
            elif i < 6:
                row2.addWidget(cb)
            else:
                row3.addWidget(cb)
        
        
        self.dynamic_button = QPushButton("Dynamic Scan")
        self.dynamic_button.setCheckable(True)
        self.dynamic_button.clicked.connect(lambda: self.function()) # <------------ do this
        self.dynamic_button.setStyleSheet("QPushButton { font-size: 20px; } QPushButton:checked {background-color: white; color: black;}")
        spacer_button = QPushButton()
        spacer_button.setStyleSheet("QPushButton { font-size: 20px; } QPushButton:checked {background-color: white; color: black;}")
        row3.addWidget(spacer_button)
        row3.addWidget(self.dynamic_button)

        layout.addLayout(row1)
        layout.addLayout(row2)
        layout.addLayout(row3)
        

        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self.go_to_next)
        self.next_button.setStyleSheet("QPushButton { font-size: 20px; }")
        layout.addWidget(self.next_button)

        self.setLayout(layout)
        self.setStyleSheet("background-color: #121212; color: #ffffff;")

    def go_to_next(self):
        selected = []
        for cb in self.checks:
            if cb.isChecked():
                selected.append(cb.text())
                cb.setChecked(False)
        
        # reset page two
        old_widget = self.stacked_widget.widget(1)
        self.stacked_widget.removeWidget(old_widget)
        old_widget.deleteLater()  

        new_page_two = PageTwo(self.stacked_widget)
        self.stacked_widget.insertWidget(1, new_page_two)
        self.stacked_widget.widget(1).update_selected_checks(selected)
        self.stacked_widget.setCurrentIndex(1)





class PageTwo(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.selected = []
        self.stacked_widget = stacked_widget
        self.layout = QVBoxLayout()
        
        self.sections = []

        nav_layout = QHBoxLayout()
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        self.back_button.setStyleSheet("QPushButton {font-size: 20px;}")
        self.run_button = QPushButton("Run Scans")
        self.run_button.clicked.connect(self.next_page)
        self.run_button.setStyleSheet("QPushButton {font-size: 20px;}")

        nav_layout.addWidget(self.back_button)
        nav_layout.addWidget(self.run_button)
        self.layout.addLayout(nav_layout) 
        self.setLayout(self.layout)
        self.setStyleSheet("background-color: #121212; color: #ffffff;")
        


    def check_selected(self):
        if "Password Scan" in self.selected:
            password_title = QLabel("PAM Config Inputs:")
            password_section = QHBoxLayout()

            pam_dir_text = QLabel("PAM Directory")
            pam_dir_input = QLineEdit("/etc/pam.d")

            pam_file_text = QLabel("PAM File")
            pam_file_input = QLineEdit("/etc/pam.conf")

            password_section.addWidget(pam_dir_text)
            password_section.addWidget(pam_dir_input)
            password_section.addWidget(pam_file_text)
            password_section.addWidget(pam_file_input)

            self.sections.append({
                'title': password_title,
                'texts': [pam_dir_text, pam_file_text],
                'inputs': [pam_dir_input, pam_file_input], 
                'rows': [password_section]
                })

        if "Config Scan" in self.selected:
            config_title = QLabel("File Config Inputs:")
            config_section = QHBoxLayout()

            ssh_file_text = QLabel("SSH Config File")
            ssh_file_input = QLineEdit("/etc/ssh/sshd_config")

            apache_file_text = QLabel("Apache Config File")
            apache_file_input = QLineEdit("/etc/apache2/apache2.conf")
            
            config_section.addWidget(ssh_file_text)
            config_section.addWidget(ssh_file_input)
            config_section.addWidget(apache_file_text)
            config_section.addWidget(apache_file_input)

            self.sections.append({
                'title': config_title,
                'texts': [ssh_file_text, apache_file_text],
                'inputs': [ssh_file_input, apache_file_input],
                'rows': [config_section]
            })         

        if "Permission Scan" in self.selected:
            permission_title = QLabel("Permission Scan Inputs:")
            permission_section = QHBoxLayout()

            root_dir_text = QLabel("Root Directory")
            root_dir_input = QLineEdit("/home")
            spacer_text1 = QLabel("", self, styleSheet = "background: transparent;")
            spacer_text2 = QLineEdit("", self, styleSheet = "background: transparent;")
            spacer_text1.setFixedSize(150, 30)
            spacer_text2.setReadOnly(True)

            permission_section.addWidget(root_dir_text)
            permission_section.addWidget(root_dir_input)
            permission_section.addWidget(spacer_text1)
            permission_section.addWidget(spacer_text2)
            self.sections.append({
                'title': permission_title,
                'texts': [root_dir_text],
                'inputs': [root_dir_input],
                'rows': [permission_section]
            }) 

        if "Port Scan" in self.selected:
            port_title = QLabel("Port Scan Inputs:")
            port_row1 = QHBoxLayout()
            port_row2 = QHBoxLayout()
            port_row3 = QHBoxLayout()

            target_text = QLabel("Target")
            target_input = QLineEdit("127.0.0.1")

            user_text = QLabel("Username")
            user_input = QLineEdit()
            user_input.setPlaceholderText("If Not on the localhost")

            start_port_text = QLabel("Start Port")
            start_port_input = QLineEdit("1")
            
            end_port_text = QLabel("End Port")
            end_port_input = QLineEdit("1024")

            pass_text = QLabel("Password")
            pass_input = QLineEdit()
            pass_input.setPlaceholderText("If Not on the localhost")

            key_text = QLabel("Key Path")
            key_input = QLineEdit()
            key_input.setPlaceholderText("If Not on the localhost")


            port_row1.addWidget(target_text)
            port_row1.addWidget(target_input)
            port_row1.addWidget(user_text)
            port_row1.addWidget(user_input)

            port_row2.addWidget(start_port_text)
            port_row2.addWidget(start_port_input)
            port_row2.addWidget(end_port_text)
            port_row2.addWidget(end_port_input)

            port_row3.addWidget(pass_text)
            port_row3.addWidget(pass_input)
            port_row3.addWidget(key_text)
            port_row3.addWidget(key_input)

            self.sections.append({
                'title': port_title,
                'texts': [target_text, start_port_text, end_port_text, user_text, pass_text, key_text],
                'inputs': [target_input, start_port_input, end_port_input, user_input, pass_input, key_input],
                'rows': [port_row1, port_row2, port_row3]
            }) 

        if "Remote Scan" in self.selected:
            remote_title = QLabel("Remote Scan Inputs:")
            remote_row1 = QHBoxLayout()
            remote_row2 = QHBoxLayout()
            remote_row3 = QHBoxLayout()
            remote_row4 = QHBoxLayout()

            remote_ip_text = QLabel("Remote IP")
            remote_ip_input = QLineEdit()

            remote_user_text = QLabel("Username")
            remote_user_input = QLineEdit()

            remote_pass_text = QLabel("Password")
            remote_pass_input = QLineEdit()

            remote_key_text = QLabel("Key Path")
            remote_key_input = QLineEdit()

            remote_pam_dir_text = QLabel("PAM Directory")
            remote_pam_dir_input = QLineEdit("/etc/pam.d")

            remote_pam_file_text = QLabel("PAM Config File")
            remote_pam_file_input = QLineEdit("/etc/pam.conf")

            remote_apache_text = QLabel("Apache File")
            remote_apache_input = QLineEdit("/etc/apache2/apache2.conf")

            remote_ssh_text = QLabel("SSH File")
            remote_ssh_input = QLineEdit("/etc/ssh/sshd_config")

            remote_row1.addWidget(remote_ip_text)
            remote_row1.addWidget(remote_ip_input)
            remote_row1.addWidget(remote_user_text)
            remote_row1.addWidget(remote_user_input)

            remote_row2.addWidget(remote_pass_text)
            remote_row2.addWidget(remote_pass_input)
            remote_row2.addWidget(remote_key_text)
            remote_row2.addWidget(remote_key_input)

            remote_row3.addWidget(remote_pam_dir_text)
            remote_row3.addWidget(remote_pam_dir_input)
            remote_row3.addWidget(remote_pam_file_text)
            remote_row3.addWidget(remote_pam_file_input)

            remote_row4.addWidget(remote_apache_text)
            remote_row4.addWidget(remote_apache_input)
            remote_row4.addWidget(remote_ssh_text)
            remote_row4.addWidget(remote_ssh_input)

            self.sections.append({
                'title': remote_title,
                'texts': [remote_ip_text, remote_user_text, remote_pass_text, remote_key_text, remote_pam_dir_text, remote_pam_file_text, remote_apache_text, remote_ssh_text],
                'inputs': [remote_ip_input, remote_user_input, remote_pass_input, remote_key_input, remote_pam_dir_input, remote_pam_file_input, remote_apache_input, remote_ssh_input],
                'rows': [remote_row1, remote_row2, remote_row3, remote_row4]
            }) 

        if "Firewall Rules Scan" in self.selected:
            firewall_title = QLabel("Firewall Scan Inputs:")
            firewall_section = QHBoxLayout()

            firewall_tool_text = QLabel("Firewall Tool")
            firewall_tool_input = QLineEdit()
            firewall_tool_input.setPlaceholderText("[iptables | ufw | firewall-cmd]")
            
            spacer_text1 = QLabel("", self, styleSheet = "background: transparent;")
            spacer_text2 = QLineEdit("", self, styleSheet = "background: transparent;")
            spacer_text1.setFixedSize(150, 30)
            spacer_text2.setReadOnly(True)

            firewall_section.addWidget(firewall_tool_text)
            firewall_section.addWidget(firewall_tool_input)
            firewall_section.addWidget(spacer_text1)
            firewall_section.addWidget(spacer_text2)

            self.sections.append({
                'title': firewall_title,
                'texts': [firewall_tool_text],
                'inputs': [firewall_tool_input], 
                'rows': [firewall_section]
                })

        if "Outdated Software Scan" in self.selected:
            outdated_title = QLabel("Outdated Software Scan Inputs:")
            outdated_section = QHBoxLayout()

            outdated_tool_text = QLabel("Package Tool")
            outdated_tool_input = QLineEdit()
            outdated_tool_input.setPlaceholderText("[apt | yum | dnf | pacman]")
            
            spacer_text1 = QLabel("", self, styleSheet = "background: transparent;")
            spacer_text2 = QLineEdit("", self, styleSheet = "background: transparent;")
            spacer_text1.setFixedSize(150, 30)
            spacer_text2.setReadOnly(True)

            outdated_section.addWidget(outdated_tool_text)
            outdated_section.addWidget(outdated_tool_input)
            outdated_section.addWidget(spacer_text1)
            outdated_section.addWidget(spacer_text2)

            self.sections.append({
                'title': outdated_title,
                'texts': [outdated_tool_text],
                'inputs': [outdated_tool_input], 
                'rows': [outdated_section]
                })
    
    def update_selected_checks(self, selected):
        self.selected = selected
        self.check_selected()
        for section in self.sections:
            section['title'].setStyleSheet("QLabel {font-size: 25px; font-weight: bold; color: black; background: transparent}")
            section['title'].setFixedSize(500, 35)
            self.layout.addWidget(section['title'])

            for text in section['texts']:
                text.setStyleSheet("QLabel {font-size: 20px; background: transparent; color: black;}")
                text.setFixedSize(150, 30)
            for field in section['inputs']:
                field.setStyleSheet("QLineEdit {font-size: 20px}")
            for row in section['rows']:
                self.layout.addLayout(row)

        self.layout.addStretch()

    def next_page(self):
        inputs = {}

        # LOGIC TO HANDLE EMPTY INPUTS
        skip_list = []
        for section in self.sections:
            inputs[section['title'].text()] = []
            if section['title'].text() == 'Remote Scan Inputs:':
                password = section['inputs'][2].text()
                key_path = section['inputs'][3].text()
                if (password and key_path) or (not password and not key_path):
                    # print(f"true, pass: {password}, key_path: {key_path}")
                    return
                else:
                    skip_list.append(2 if password == '' else 3)
            
            if section['title'].text() == 'Port Scan Inputs:':
                if section['inputs'][0].text() == '127.0.0.1':
                    skip_list.extend([3, 4, 5])
                    # print("true", section['inputs'][1].text(), section['inputs'][4].text(), section['inputs'][5].text())
                else:
                    password = section['inputs'][4].text()
                    key_path = section['inputs'][5].text()
                    if (password and key_path) or (not password and not key_path):
                        # print(f"true, pass: {password}, key_path: {key_path}")
                        return
                    else:
                        skip_list.append(4 if password == '' else 5)

            for i, field in enumerate(section['inputs']):
                inputs[section['title'].text()].append(field.text())
                if field.text() == '' and i not in skip_list:
                    return
                    
            skip_list = []

        # SWITCH TO NEXT PAGE
        output_page = self.stacked_widget.widget(2)
        self.stacked_widget.setCurrentIndex(2)
        output_page.run_scans(self.selected, inputs)



class PageThree(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.results = {}
        self.stacked_widget = stacked_widget
        layout = QVBoxLayout()

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        content_widget = QWidget()
        self.content_layout = QVBoxLayout(content_widget)

        # Add buttons to content layout
        # for num in range(1, 100):
        #     button = QPushButton(f"Number {num}")
        #     button.clicked.connect(lambda _, n=num: self.openWindow(f"Number {n}"))
        #     content_layout.addWidget(button)


        self.back_home = QPushButton("Back to Home")
        self.back_home.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))

        # layout.addWidget(self.output)
        layout.addWidget(self.back_home)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #121212; color: #ffffff;")
        self.output = QTextEdit() # ignore
        self.new_window = None
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

    def run_scans(self, selected, inputs):
        self.selected = selected

        shutdown_event = threading.Event()

        def run():
            if "Password Scan" in self.selected:
                pam_dir = inputs['PAM Config Inputs:'][0]
                pam_file = inputs['PAM Config Inputs:'][1]
                pam_obj = PAMConfScan(pam_dir = pam_dir, pam_conf_file = pam_file)
                self.results.update(pam_obj.run_scan())
            if "Config Scan" in self.selected:
                ssh_file = inputs['File Config Inputs:'][0]
                apache_file = inputs['File Config Inputs:'][1]
                config_obj = FileConfScan(ssh_config_file = ssh_file, apache_config_file = apache_file)
                self.results.update(config_obj.run_scan())
            if "Permission Scan" in self.selected:
                root_dir = inputs['Permission Scan Inputs:'][0]
                perm_obj = PermissionScan(shutdown_event, root_dir=root_dir)
                self.results.update(perm_obj.run_scan())
            if "Port Scan" in self.selected:
                target = inputs['Port Scan Inputs:'][0]
                start_port = inputs['Port Scan Inputs:'][1]
                end_port = inputs['Port Scan Inputs:'][2]
                username = inputs['Port Scan Inputs:'][3]
                password = inputs['Port Scan Inputs:'][4]
                key_path = inputs['Port Scan Inputs:'][5]
                port_obj = PortScan(shutdown_event, target=target, start_port = int(start_port), end_port = int(end_port), user = username, password = password, key_path = key_path)
                self.results.update(port_obj.run_scan())
            if "Remote Scan" in self.selected:
                # print(inputs)
                target = inputs['Remote Scan Inputs:'][0]
                user = inputs['Remote Scan Inputs:'][1]
                password = inputs['Remote Scan Inputs:'][2]
                key_path = inputs['Remote Scan Inputs:'][3]
                pam_dir = inputs['Remote Scan Inputs:'][4]
                pam_file = inputs['Remote Scan Inputs:'][5]
                apache_file = inputs['Remote Scan Inputs:'][6]
                ssh_file = inputs['Remote Scan Inputs:'][7]
                PAMConfScan(True, target = target, user = user, password = password, key_path = key_path, pam_dir = pam_dir, pam_conf_file = pam_file)
                FileConfScan(True, target = target, user = user, password = password, key_path = key_path, ssh_config_file = ssh_file, apache_config_file = apache_file)
            
            if "Firewall Rules Scan" in self.selected:
                tool = inputs['Firewall Scan Inputs:'][0]
                pass # <---- call firewall scan

            if "Outdated Software Scan" in self.selected:
                tool = inputs['Outdated Software Scan Inputs:']
                pass # <---- call outdated software scan scan

        run()
        self.store_output()

    def store_output(self):
        for title, outputs in self.results.items():
            title_label = QLabel(title)
            title_label.setStyleSheet("QLabel {font-size: 25px; font-weight: bold; color: white; background: transparent}")
            self.content_layout.addWidget(title_label)

            # main is the text that appears on the button
            main = outputs[-1]['main']
            if main == 'No issues found.':
                issues_label = QLabel(main)
                issues_label.setStyleSheet("QLabel {font-size: 20px; color: white; background: transparent}")
                self.content_layout.addWidget(issues_label)
            elif main == 'error':
                error = outputs[0]['error']
                error_label = QLabel(str(error))
                error_label.setStyleSheet("QLabel {font-size: 20px; color: white; background: transparent}")
                self.content_layout.addWidget(error_label)
            else:
                for output in outputs[0:-1]:
                    button = QPushButton(output[main])
                    button.clicked.connect(lambda _, t=title, n=output: self.openWindow(title, n))
                    button.setStyleSheet('QPushButton{font-size: 20px}')
                    self.content_layout.addWidget(button)

            # if "Password Scan" in self.selected:
            # if "Config Scan" in self.selected:
            #     pass
            # if "Permission Scan" in self.selected:
            #     pass
            # if "Port Scan" in self.selected:
            #     pass
            # if "Remote Scan" in self.selected:
            #     pass
            # if "Firewall Rules Scan" in self.selected:
            #     pass
            # if "Outdated Software Scan" in self.selected:
            #     pass

        self.content_layout.addStretch()

    def openWindow(self, title, data):
        self.new_window = DetailsWindow(title, data)
        self.new_window.show()
        
    def append_output(self, text):
        self.output.append(text)

    def clear_output(self):
        self.output.clear()

class DetailsWindow(QWidget):
    def __init__(self, title, data):
        super().__init__()
        self.setWindowTitle(title)
        self.setGeometry(100, 100, 400, 300)
        self.layout = QVBoxLayout()
        for key, value in data.items():
            section = QHBoxLayout()
            text1 = QLabel(key + ':')
            text2 = QLabel(str(value))

            section.addWidget(text1)
            section.addWidget(text2)
            self.layout.addLayout(section)
        self.setLayout(self.layout)
        self.layout.addStretch()



class AutoShieldApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux AutoShield")
        self.setGeometry(200, 100, 1000, 700)

        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(PageOne(self.stacked_widget))
        self.stacked_widget.addWidget(PageTwo(self.stacked_widget))
        self.stacked_widget.addWidget(PageThree(self.stacked_widget))

        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AutoShieldApp()
    window.show()
    sys.exit(app.exec())