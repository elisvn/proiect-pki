import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QLineEdit,
    QFileDialog, QMessageBox, QDialog, QFormLayout, QCheckBox, QScrollArea, QGroupBox, QTextEdit, QGridLayout, QFrame,
    QDialogButtonBox, QStackedWidget, QToolButton, QSizePolicy, QStyle, QListWidget, QListWidgetItem, QInputDialog
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
import os
import shutil
import main
import client_cert
from revoke import revoke_client_cert, verify_cert_with_crl
from datetime import datetime
from OpenSSL import crypto
import pexpect
import getpass
import time


class PasswordDialog(QDialog):
    def __init__(self, parent, title, message, confirm_password=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumSize(350, 180)
        self.setFont(QFont("Roboto", 13))
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(message))
        self.password1 = QLineEdit()
        self.password1.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password1)
        if confirm_password:
            layout.addWidget(QLabel("Confirmare parolă:"))
            self.password2 = QLineEdit()
            self.password2.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password2)
        else:
            self.password2 = None
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setFont(QFont("Roboto", 13))
        buttons.button(QDialogButtonBox.Cancel).setFont(QFont("Roboto", 13))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_password(self):
        if self.exec_() == QDialog.Accepted:
            if self.password2 and self.password1.text() != self.password2.text():
                QMessageBox.warning(self, "Eroare", "Parolele nu coincid!")
                return None
            return self.password1.text()
        return None


class PKIAppQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PKI Desktop App (PyQt5)")
        self.setFont(QFont("Roboto", 13))
        self.resize(1200, 700)
        self.setMinimumSize(900, 600)
        self.center()
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QHBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.app_start_time = datetime.now()


        app = QApplication.instance()
        app.setStyle('Fusion')
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(24, 28, 36))
        dark_palette.setColor(QPalette.WindowText, QColor(224, 230, 237))
        dark_palette.setColor(QPalette.Base, QColor(35, 42, 52))
        dark_palette.setColor(QPalette.AlternateBase, QColor(35, 42, 52))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(35, 42, 52))
        dark_palette.setColor(QPalette.ToolTipText, QColor(224, 230, 237))
        dark_palette.setColor(QPalette.Text, QColor(224, 230, 237))
        dark_palette.setColor(QPalette.Button, QColor(35, 42, 52))
        dark_palette.setColor(QPalette.ButtonText, QColor(224, 230, 237))
        dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.Highlight, QColor(36, 157, 107))
        dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        app.setPalette(dark_palette)


        self.sidebar_widget = QWidget()
        self.sidebar_widget.setFixedWidth(240)
        self.sidebar_widget.setObjectName("Sidebar")
        self.sidebar_layout = QVBoxLayout(self.sidebar_widget)
        self.sidebar_layout.setContentsMargins(0, 0, 0, 0)
        self.sidebar_layout.setSpacing(0)
        self.sidebar_layout.setAlignment(Qt.AlignTop)
        self.layout.addWidget(self.sidebar_widget)


        logo = QLabel("<b>PKI Admin</b>")
        logo.setAlignment(Qt.AlignCenter)
        logo.setObjectName("Logo")
        self.sidebar_layout.addWidget(logo)

        pki_icon = QLabel()
        pki_icon.setAlignment(Qt.AlignCenter)
        pki_icon.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(40, 40))
        self.sidebar_layout.addWidget(pki_icon)


        self.sidebar_layout.addSpacing(10)
        self.sidebar_buttons = []
        self.add_sidebar_button("Dashboard", self.show_dashboard, "SP_ComputerIcon")
        self.add_sidebar_button("Clienți", self.show_clients, "SP_DirIcon")
        self.add_sidebar_button("Certificare", self.show_cert, "SP_FileDialogContentsView")
        self.add_sidebar_button("Export", self.show_export, "SP_DriveFDIcon")
        self.add_sidebar_button("Setări", self.show_settings, "SP_FileDialogDetailedView")
        self.sidebar_layout.addStretch(1)
        self.add_sidebar_button("Log", self.show_log_page, "SP_MessageBoxInformation")

        # Zona principală
        self.pages = QStackedWidget()
        self.layout.addWidget(self.pages, 1)

        # Pagina Dashboard
        self.dashboard_page = QWidget()
        dash_layout = QVBoxLayout(self.dashboard_page)
        dash_layout.setContentsMargins(30, 30, 30, 30)
        dash_layout.setSpacing(20)

        cards = QHBoxLayout()
        cards.setSpacing(20)
        self.dashboard_cards = []

        def make_card_btn(card, slot):
            card.mousePressEvent = lambda e: slot()
            card.setCursor(Qt.PointingHandCursor)

        card_clients = self.make_status_card("Total Clienți", self.get_total_clients(), "SP_DirIcon", "#249d6b")
        make_card_btn(card_clients, self.show_clients)
        cards.addWidget(card_clients)
        self.dashboard_cards.append(card_clients)
        card_certs = self.make_status_card("Total Certificate", self.get_total_certs(), "SP_FileDialogContentsView",
                                           "#236fa1")
        make_card_btn(card_certs, self.show_all_certs_dialog)
        cards.addWidget(card_certs)
        self.dashboard_cards.append(card_certs)
        card_revoked = self.make_status_card("Certificate Revocate", self.get_total_revoked(), "SP_MessageBoxWarning",
                                             "#b36a1c")
        make_card_btn(card_revoked, self.show_revoked_certs_dialog)
        cards.addWidget(card_revoked)
        self.dashboard_cards.append(card_revoked)
        dash_layout.addLayout(cards)
        # Activity feed
        self.activity_feed = QListWidget()
        self.activity_feed.setMinimumHeight(300)
        dash_layout.addWidget(QLabel("Activity Feed (ultimele 10 acțiuni):"))
        dash_layout.addWidget(self.activity_feed)
        self.update_activity_feed()
        self.pages.addWidget(self.dashboard_page)


        # Pagina Clienți
        self.clients_page = QWidget()
        clients_layout = QVBoxLayout(self.clients_page)
        clients_layout.setContentsMargins(30, 30, 30, 30)
        clients_layout.setSpacing(15)
        btns = QHBoxLayout()
        btns.addWidget(
            self.make_action_button("Generează certificat client", self.gen_client_dialog, "SP_FileDialogNewFolder"))
        btns.addWidget(self.make_action_button("Revocă certificat", self.revoke_client_dialog, "SP_TrashIcon"))
        btns.addWidget(self.make_action_button("Șterge client", self.delete_client_dialog, "SP_TrashIcon"))
        clients_layout.addLayout(btns)
        clients_layout.addStretch(1)

        search_layout = QHBoxLayout()
        search_label = QLabel("Caută client:")
        self.client_search = QLineEdit()
        self.client_search.setPlaceholderText("Introdu nume client...")
        self.client_search.textChanged.connect(self.filter_clients_list)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.client_search)
        clients_layout.addLayout(search_layout)
        clients_layout.addWidget(QLabel("Clienți existenți:"))
        self.clients_list = QListWidget()
        clients_layout.addWidget(self.clients_list)

        self.clients_log = QTextEdit()
        self.clients_log.setReadOnly(True)
        self.clients_log.setMaximumHeight(80)
        clients_layout.addWidget(self.clients_log)
        self.pages.addWidget(self.clients_page)

        # Pagina Certificare
        self.cert_page = QWidget()
        cert_layout = QVBoxLayout(self.cert_page)
        cert_layout.setContentsMargins(30, 30, 30, 30)
        cert_layout.setSpacing(15)
        cert_layout.addWidget(self.make_action_button("Inițializează SubCA", self.init_subca_dialog, "SP_DriveHDIcon"))
        cert_layout.addWidget(self.make_action_button("Semnează SubCA", self.sign_subca_dialog, "SP_DialogApplyButton"))
        cert_layout.addWidget(self.make_action_button("Semnează CSR extern", self.sign_csr_dialog, "SP_FileDialogListView"))
        cert_layout.addWidget(self.make_action_button("Verificare simplă certificat", self.verify_simple_cert_dialog, "SP_DialogYesButton"))
        cert_layout.addWidget(self.make_action_button("Verificare CRL", self.verify_crl_dialog, "SP_DialogNoButton"))
        cert_layout.addWidget(self.make_action_button("Verifică integritatea CA", self.show_ca_integrity_dialog, "SP_DialogHelpButton"))
        cert_layout.addStretch(1)

        self.cert_log = QTextEdit()
        self.cert_log.setReadOnly(True)
        self.cert_log.setMaximumHeight(80)
        cert_layout.addWidget(self.cert_log)
        self.pages.addWidget(self.cert_page)

        # Pagina Setări
        self.settings_page = QWidget()
        settings_layout = QVBoxLayout(self.settings_page)
        settings_layout.setContentsMargins(30, 30, 30, 30)
        settings_layout.setSpacing(15)
        settings_layout.addWidget(self.make_action_button("Vezi openssl.cnf", self.show_conf_dialog, "SP_FileDialogInfoView"))
        settings_layout.addWidget(self.make_action_button("Editează openssl.cnf", self.edit_conf_dialog, "SP_FileDialogDetailedView"))
        settings_layout.addWidget(self.make_action_button("Schimbă fontul interfeței", self.change_font_dialog, "SP_DialogOkButton"))
        settings_layout.addWidget(self.make_action_button("Deschide folderul de lucru", self.open_workspace_folder, "SP_DirHomeIcon"))
        settings_layout.addWidget(self.make_action_button("Resetează logul", self.reset_log, "SP_TrashIcon"))
        settings_layout.addWidget(self.make_action_button("Despre aplicație", self.about_dialog, "SP_MessageBoxInformation"))
        settings_layout.addWidget(self.make_action_button("Actualizează fișiere RootCA din NFS", self.update_rootca_files_from_nfs, "SP_BrowserReload"))
        settings_layout.addWidget(self.make_action_button("Configurează NFS RootCA", self.configure_nfs_dialog, "SP_DirLinkIcon"))
        settings_layout.addStretch(1)
        self.pages.addWidget(self.settings_page)

        # Pagina Log
        self.log_page = QWidget()
        log_layout = QVBoxLayout(self.log_page)
        log_layout.setContentsMargins(30, 30, 30, 30)
        log_layout.setSpacing(15)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Roboto", 12))
        log_layout.addWidget(self.log)
        export_log_btn = QPushButton("Exportă logul ca .txt")
        export_log_btn.clicked.connect(self.export_log_dialog)
        log_layout.addWidget(export_log_btn)
        self.pages.addWidget(self.log_page)


        self.pages.setCurrentWidget(self.dashboard_page)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #181c24;
            }
            #Sidebar {
                background-color: #1a1f27;
                border-right: 1px solid #232a34;
            }
            #Logo {
                color: #249d6b;
                font-size: 22px;
                padding: 24px 0 8px 0;
            }
            #UserInfo {
                color: #e0e6ed;
                font-size: 15px;
                padding-bottom: 18px;
            }
            QToolButton, QPushButton {
                background: #232a34;
                color: #e0e6ed;
                border: 1px solid #232a34;
                border-radius: 8px;
                padding: 12px 0px;
                margin: 0 16px 8px 16px;
                font-family: Roboto;
                font-size: 15px;
                font-weight: 600;
                min-width: 180px;
                min-height: 38px;
                text-align: center;
                align-items: center;
                transition: background 0.2s;
            }
            QToolButton:hover, QPushButton:hover {
                background-color: #249d6b;
                color: #fff;
                border: 1px solid #249d6b;
            }
            QToolButton:checked, QPushButton:checked {
                background-color: #249d6b;
                color: #fff;
                border: 1px solid #249d6b;
            }
            QLabel {
                color: #e0e6ed;
                font-family: Roboto;
                font-size: 14px;
                font-weight: 500;
            }
            QLineEdit, QTextEdit {
                background-color: #232a34;
                color: #e0e6ed;
                border: 1px solid #23405c;
                border-radius: 6px;
                font-family: Roboto;
                font-size: 15px;
                padding: 7px 12px;
            }
            QDialog {
                background-color: #181c24;
            }
            QScrollArea {
                background: #181c24;
                border: none;
            }
            QCheckBox {
                color: #e0e6ed;
                font-size: 15px;
                padding: 4px;
                background: #232a34;
                border-radius: 6px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
                border-radius: 4px;
                background: #2d3542;
                border: 2px solid #249d6b;
            }
            QCheckBox::indicator:checked {
                background: #249d6b;
                border: 2px solid #249d6b;
            }
            QListWidget {
                background: #232a34;
                color: #e0e6ed;
                border-radius: 8px;
                font-size: 15px;
            }
        """)

        self.sudo_password = None
        self.sudo_password_time = 0

    def center(self):

        screen = QApplication.desktop().screenGeometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )

    def center_dialog(self, dialog):

        dialog.move(
            self.frameGeometry().center() - dialog.frameGeometry().center()
        )

    def add_sidebar_button(self, text, slot, icon_name):
        btn = QToolButton()
        btn.setText(text)
        btn.setIcon(self.style().standardIcon(getattr(QStyle, icon_name)))
        btn.setIconSize(QSize(22, 22))
        btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        btn.setCheckable(True)
        btn.clicked.connect(lambda: self.select_sidebar_button(btn, slot))
        self.sidebar_layout.addWidget(btn)
        self.sidebar_buttons.append(btn)

    def select_sidebar_button(self, btn, slot):
        for b in self.sidebar_buttons:
            b.setChecked(False)
        btn.setChecked(True)
        slot()

    def make_status_card(self, title, value, icon_name, accent):
        card = QFrame()
        card.setObjectName("StatusCard")
        card.setStyleSheet(f"""
            QFrame#StatusCard {{
                background: #232a34;
                border-radius: 16px;
                padding: 24px 18px;
                min-width: 220px;
                max-width: 260px;
                border: 2px solid {accent};
            }}
        """)
        layout = QVBoxLayout(card)
        icon = QLabel()
        icon.setPixmap(self.style().standardIcon(getattr(QStyle, icon_name)).pixmap(32, 32))
        icon.setAlignment(Qt.AlignLeft)
        layout.addWidget(icon)
        label = QLabel(title)
        label.setStyleSheet("font-size: 15px; color: #bfc9d1;")
        layout.addWidget(label)
        val = QLabel(str(value))
        val.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {accent};")
        layout.addWidget(val)
        layout.addStretch(1)
        return card

    def make_action_button(self, text, slot, icon_name):
        btn = QPushButton(text)
        btn.setIcon(self.style().standardIcon(getattr(QStyle, icon_name)))
        btn.setIconSize(QSize(20, 20))
        btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn.clicked.connect(slot)
        btn.setFont(QFont("Segoe UI", 15, QFont.Bold))
        btn.setStyleSheet("text-align: center; font-weight: bold;")
        return btn


    def show_dashboard(self):
        self.pages.setCurrentWidget(self.dashboard_page)

    def show_clients(self):
        self.pages.setCurrentWidget(self.clients_page)
        self.update_clients_list()

    def show_cert(self):
        self.pages.setCurrentWidget(self.cert_page)

    def show_export(self):
        self.export_client_dialog()

    def show_settings(self):
        self.pages.setCurrentWidget(self.settings_page)

    def show_log_page(self):
        self.pages.setCurrentWidget(self.log_page)

    def get_total_clients(self):
        try:
            client_dir = os.path.join(main.CLIENT_DIR)
            return len([d for d in os.listdir(client_dir) if os.path.isdir(os.path.join(client_dir, d))])
        except FileNotFoundError:
            return 0
        except Exception:
            return 0

    def get_total_certs(self):
        try:
            revoked = set()
            with open(os.path.join(main.SUBCA_DIR, "index.txt")) as f:
                for line in f:
                    if line.startswith("R"):
                        parts = line.split()
                        if len(parts) > 3:
                            revoked.add(parts[3])
            count = 0
            for c in os.listdir(main.CLIENT_DIR):
                crt_path = os.path.join(main.CLIENT_DIR, c, f"{c}.crt")
                if os.path.exists(crt_path):
                    try:
                        serial = os.popen(f"openssl x509 -in '{crt_path}' -noout -serial").read().strip().replace(
                            "serial=",
                            "").upper()
                        if serial not in revoked:
                            count += 1
                    except Exception:
                        # Certificat invalid, nu îl numărăm
                        continue
            return count
        except Exception:
            return 0

    def get_total_revoked(self):
        try:
            with open(os.path.join(main.SUBCA_DIR, "index.txt")) as f:
                return sum(1 for line in f if line.startswith("R"))
        except Exception:
            return 0

    def write_log(self, text):
        timestamp = datetime.now().strftime("[%d.%m.%Y %H:%M:%S]")

        msg = text.strip()
        for prefix in ["✔", "⚠", "❌", "Succes", "Eroare", "Certificatul", "Clientul", "Exportat", "Revocat", "Șters",
                       "Generat", "Semnat", "Inițializat"]:
            if msg.startswith(prefix):
                break
        else:
            return
        log_msg = f"{timestamp} {msg}"
        self.log.append(log_msg)
        self.log.moveCursor(self.log.textCursor().End)

        try:
            with open("pki_app.log", "a") as f:
                f.write(log_msg + "\n")
        except Exception:
            pass
        # Update activity feed
        self.add_activity(log_msg)
        # Loguri pe pagini
        self.clients_log.append(log_msg)
        self.cert_log.append(log_msg)
        self.update_activity_feed()
        self.update_dashboard_cards()

    def add_activity(self, msg):
        if hasattr(self, 'activity_feed'):
            if self.activity_feed.count() == 1 and self.activity_feed.item(0).text().startswith("⚠️ Nicio activitate"):  # elimin mesajul default
                self.activity_feed.clear()
            self.activity_feed.insertItem(0, msg)
            if self.activity_feed.count() > 10:
                self.activity_feed.takeItem(10)

    def update_activity_feed(self):
        if self.activity_feed.count() == 0:
            self.activity_feed.addItem("⚠️ Nicio activitate logată încă.")

    def show_success_message(self, title, message):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Roboto", 13))
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def show_error_message(self, title, message):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Roboto", 13))
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def show_info_message(self, title, message):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Roboto", 13))
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def show_warning_message(self, title, message):
        QMessageBox.warning(self, title, message)

    def file_exists_or_error(self, path, message):
        if not os.path.exists(path):
            self.show_error_message("Eroare", message)
            return False
        return True

    def check_critical_files(self, require_key=False, require_cert=True, require_chain=True, require_conf=True, require_crl=False):
        missing = []
        if require_key and not os.path.exists(os.path.join(main.SUBCA_DIR, "subCA.key")):
            missing.append("subCA.key")
        if require_cert and not os.path.exists(os.path.join(main.SUBCA_DIR, "subCA.pem")):
            missing.append("subCA.pem")
        if require_chain and not os.path.exists(os.path.join(main.SUBCA_DIR, "chain.pem")):
            missing.append("chain.pem")
        if require_conf and not os.path.exists(os.path.join(main.SUBCA_DIR, "openssl.cnf")):
            missing.append("openssl.cnf")
        if require_crl and not os.path.exists(os.path.join(main.SUBCA_DIR, "crl/subca.crl.pem")):
            missing.append("crl/subca.crl.pem")
        if missing:
            msg = f"❌ Lipsesc fișiere critice pentru SubCA: {', '.join(missing)}. Operațiunea nu poate continua."
            self.show_error_message("Eroare fișiere critice", msg)
            self.write_log(msg)
            return False
        return True

    def init_subca_dialog(self):
        # 1. Deschide dialogul pentru personalizare openssl.cnf
        if not self.customize_openssl_cnf_dialog():
            self.show_info_message("Anulat", "Inițializarea SubCA a fost anulată.")
            return

        # 2. Cere parola SubCA (cu confirmare)
        pwd_dialog = PasswordDialog(self, "Setează parola SubCA", "Alege o parolă pentru cheia privată SubCA:",
                                    confirm_password=True)
        parola = pwd_dialog.get_password()
        if not parola:
            self.show_warning_message("Anulat", "Inițializarea SubCA a fost anulată (nu s-a setat nicio parolă).")
            return

        # 3. Generează cheia privată criptată cu parola
        key_result = main.gen_subca_key(parola)
        if "error" in key_result.lower():
            self.show_error_message("Eroare generare cheie", key_result)
            self.write_log(f"❌ Eroare generare cheie SubCA: {key_result}")
            return
        self.write_log("✔ Cheie privată SubCA generată cu parolă.")

        # 4. Generează CSR-ul cu aceeași parolă
        csr_result = main.gen_subca_csr(parola)
        if "error" in csr_result.lower():
            self.show_error_message("Eroare generare CSR", csr_result)
            self.write_log(f"❌ Eroare generare CSR SubCA: {csr_result}")
            return
        self.write_log("✔ CSR SubCA generat cu succes.")
        # Export CSR după generare
        csr_path = os.path.join(main.SUBCA_DIR, "subCA.csr")
        export_ok = False
        if os.path.exists(csr_path):
            nfs_path = "/mnt/pki_shared/subCA.csr"
            try:
                if os.path.ismount("/mnt/pki_shared"):
                    if self.sudo_copy(csr_path, nfs_path):
                        self.show_success_message("Export CSR NFS", f"✔ CSR-ul SubCA a fost exportat automat în NFS la:\n{nfs_path}")
                        self.write_log(f"✔ CSR-ul SubCA exportat automat în NFS la {nfs_path}")
                        export_ok = True
                    else:
                        self.show_warning_message("NFS nemontat", "Exportul automat nu a fost efectuat.")
                        self.write_log("⚠ Exportul automat CSR în NFS nu a fost efectuat: NFS nemontat.")
                else:
                    self.show_warning_message("NFS nemontat", "Exportul automat nu a fost efectuat.")
                    self.write_log("⚠ Exportul automat CSR în NFS nu a fost efectuat: NFS nemontat.")
            except Exception as e:
                self.show_error_message("Eroare export CSR NFS", f"Nu s-a putut exporta CSR-ul în NFS: {str(e)}")
                self.write_log(f"❌ Eroare la exportul CSR în NFS: {str(e)}")
            if not export_ok:
                # Export manual
                dest, _ = QFileDialog.getSaveFileName(self, "Exportă CSR SubCA", "subCA.csr", "CSR files (*.csr)")
                if dest:
                    if self.sudo_copy(csr_path, dest):
                        self.show_success_message("Export CSR", f"✔ CSR-ul SubCA a fost exportat la:\n{dest}")
                        export_ok = True
                    else:
                        self.show_error_message("Eroare export CSR", f"Nu s-a putut exporta CSR-ul: permisiuni insuficiente.")
                if not export_ok:
                    self.show_error_message("Eroare", "Exportul CSR-ului a eșuat. Inițializarea SubCA a fost anulată.")
                    self.write_log("❌ Inițializarea SubCA a fost anulată din cauza eșecului la export CSR.")
                    return
        else:
            self.show_error_message("Eroare", "Fișierul CSR nu a fost generat.")
            self.write_log("❌ Inițializarea SubCA a fost anulată: CSR-ul nu a fost generat.")
            return
        mesaj = (
            "✔ SubCA a fost inițializată cu succes!\n\n"
            "Cheia privată (criptată), fișierul CSR și configurația completă au fost salvate în:\n"
            f"{main.SUBCA_DIR}\n\n"
            "👉 Te rugăm să semnezi acum certificatul SubCA folosind parola RootCA."
        )
        self.show_success_message("Inițializare completă", mesaj)
        self.write_log("✔ SubCA a fost inițializată cu parolă.")
        self.update_dashboard_cards()
        self.update_activity_feed()

    def customize_openssl_cnf_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Personalizare openssl.cnf")
        dialog.setMinimumSize(400, 400)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        fields = [
            ("Țara (C)", "RO"),
            ("Stat/Județ (ST)", "Sibiu"),
            ("Localitate (L)", ""),
            ("Organizație (O)", "Academie"),
            ("Unitate (OU)", "IT"),
            ("Common Name (CN)", "subca.local")
        ]

        entries = {}
        for label, default in fields:
            layout.addWidget(QLabel(label))
            entry = QLineEdit(default)
            layout.addWidget(entry)
            entries[label] = entry

        def apply_changes():
            try:
                country = entries["Țara (C)"].text()
                state = entries["Stat/Județ (ST)"].text()
                locality = entries["Localitate (L)"].text()
                organization = entries["Organizație (O)"].text()
                org_unit = entries["Unitate (OU)"].text()
                common_name = entries["Common Name (CN)"].text()

                main.generate_openssl_cnf(country, state, locality, organization, org_unit, common_name)

                self.show_success_message("Succes", "✔ Fișierul openssl.cnf a fost generat cu succes.")
                self.write_log("✔ Fișier openssl.cnf generat prin GUI.")
                dialog.accept()

            except Exception as e:
                self.show_error_message("Eroare", f"Eroare la generare: {str(e)}")

        apply_btn = QPushButton("Aplică modificările")
        apply_btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        apply_btn.clicked.connect(apply_changes)
        layout.addWidget(apply_btn)

        self.center_dialog(dialog)
        result = dialog.exec_()
        return result == QDialog.Accepted

    def sign_subca_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Semnează SubCA (încarcă certificatele semnate)")
        dialog.setMinimumSize(400, 250)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # SubCA
        layout.addWidget(QLabel("Încarcă fișierul certificat SubCA semnat de RootCA (.crt/.pem):"))
        file_input_subca = QLineEdit()
        layout.addWidget(file_input_subca)
        def browse_file_subca():
            path, _ = QFileDialog.getOpenFileName(dialog, "Selectează certificatul SubCA semnat", "", "Certificate (*.crt *.pem)")
            if path:
                file_input_subca.setText(path)
        browse_btn_subca = QPushButton("Selectează fișierul SubCA")
        browse_btn_subca.clicked.connect(browse_file_subca)
        layout.addWidget(browse_btn_subca)

        # RootCA
        layout.addWidget(QLabel("Încarcă fișierul certificat RootCA (public) (.crt/.pem):"))
        file_input_rootca = QLineEdit()
        layout.addWidget(file_input_rootca)
        def browse_file_rootca():
            path, _ = QFileDialog.getOpenFileName(dialog, "Selectează certificatul RootCA", "", "Certificate (*.crt *.pem)")
            if path:
                file_input_rootca.setText(path)
        browse_btn_rootca = QPushButton("Selectează fișierul RootCA")
        browse_btn_rootca.clicked.connect(browse_file_rootca)
        layout.addWidget(browse_btn_rootca)

        # CRL RootCA
        layout.addWidget(QLabel("Încarcă fișierul CRL RootCA (.crl.pem):"))
        file_input_crl = QLineEdit()
        layout.addWidget(file_input_crl)
        def browse_file_crl():
            path, _ = QFileDialog.getOpenFileName(dialog, "Selectează rootCA.crl.pem", "", "CRL files (*.crl.pem);;All files (*)")
            if path:
                file_input_crl.setText(path)
        browse_btn_crl = QPushButton("Selectează fișierul CRL")
        browse_btn_crl.clicked.connect(browse_file_crl)
        layout.addWidget(browse_btn_crl)

        # Import automat din NFS
        import_nfs_btn = QPushButton("Importă automat din NFS")
        import_nfs_btn.setStyleSheet("""
            QPushButton {
                background-color: #249d6b;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #36a16b;
            }
        """)
        layout.addWidget(import_nfs_btn)
        def import_from_nfs():
            nfs_dir = "/mnt/pki_shared"
            errors = []
            imported = []
            # rootCA.pem
            src_rootca = os.path.join(nfs_dir, "rootCA.pem")
            dest_rootca = os.path.join(main.ROOT_DIR, "rootCA.pem")
            try:
                if os.path.exists(src_rootca):
                    os.makedirs(main.ROOT_DIR, exist_ok=True)
                    shutil.copy(src_rootca, dest_rootca)
                    imported.append("rootCA.pem")
                    self.write_log(f"✔ rootCA.pem importat automat din NFS.")
                else:
                    errors.append("rootCA.pem nu există în NFS.")
            except Exception as e:
                errors.append(f"rootCA.pem: {str(e)}")
            # subCA.pem
            src_subca = os.path.join(nfs_dir, "subCA.pem")
            dest_subca = os.path.join(main.SUBCA_DIR, "subCA.pem")
            try:
                if os.path.exists(src_subca):
                    shutil.copy(src_subca, dest_subca)
                    imported.append("subCA.pem")
                    self.write_log(f"✔ subCA.pem importat automat din NFS.")
                    file_input_subca.setText(src_subca)
                else:
                    errors.append("subCA.pem nu există în NFS.")
            except Exception as e:
                errors.append(f"subCA.pem: {str(e)}")
            # rootCA.crl.pem
            src_crl = os.path.join(nfs_dir, "rootCA.crl.pem")
            dest_crl_dir = os.path.join(main.SUBCA_DIR, "crl")
            dest_crl = os.path.join(dest_crl_dir, "rootCA.crl.pem")
            try:
                if os.path.exists(src_crl):
                    os.makedirs(dest_crl_dir, exist_ok=True)
                    shutil.copy(src_crl, dest_crl)
                    imported.append("rootCA.crl.pem")
                    self.write_log(f"✔ rootCA.crl.pem importat automat din NFS.")
                    file_input_crl.setText(src_crl)
                else:
                    errors.append("rootCA.crl.pem nu există în NFS.")
            except Exception as e:
                errors.append(f"rootCA.crl.pem: {str(e)}")
            # Mesaje
            if imported:
                self.show_success_message("Import NFS", f"✔ Import automat din NFS pentru: {', '.join(imported)}")
                dialog.accept()
            if errors:
                self.show_warning_message("Import NFS - probleme", "\n".join(errors))
                self.write_log(f"⚠ Probleme la importul automat din NFS: {'; '.join(errors)}")
        import_nfs_btn.clicked.connect(import_from_nfs)

        btn = QPushButton("Importă și activează SubCA")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def do_import():
            import shutil
            from PyQt5.QtWidgets import QInputDialog, QLineEdit

            src_subca = file_input_subca.text().strip()
            src_rootca = file_input_rootca.text().strip()
            src_crl = file_input_crl.text().strip()
            if not src_subca or not os.path.isfile(src_subca):
                self.show_error_message("Eroare", "Selectează un fișier certificat SubCA valid.")
                return
            if not src_rootca or not os.path.isfile(src_rootca):
                self.show_error_message("Eroare", "Selectează un fișier certificat RootCA valid.")
                return
            if not src_crl or not os.path.isfile(src_crl):
                self.show_error_message("Eroare", "Selectează un fișier CRL RootCA valid.")
                return
            try:
                # Copiază certificatul SubCA
                dest_subca = os.path.join(main.SUBCA_DIR, "subCA.pem")
                shutil.copy(src_subca, dest_subca)
                # Copiază certificatul RootCA
                dest_rootca = os.path.join(main.ROOT_DIR, "rootCA.pem")
                os.makedirs(main.ROOT_DIR, exist_ok=True)
                shutil.copy(src_rootca, dest_rootca)
                # Copiază CRL RootCA
                dest_crl_dir = os.path.join(main.SUBCA_DIR, "crl")
                os.makedirs(dest_crl_dir, exist_ok=True)
                dest_crl = os.path.join(dest_crl_dir, "rootCA.crl.pem")
                shutil.copy(src_crl, dest_crl)
                # Creează chain.pem
                chain_path, msg = main.create_chain_file()

                # Cere parola SubCA pentru generarea CRL
                password, ok = QInputDialog.getText(
                    self, "Parolă SubCA", "Introduceți parola pentru cheia SubCA:", QLineEdit.Password
                )
                if not ok or not password:
                    self.show_error_message("Eroare",
                                            "Nu s-a introdus parola pentru cheia SubCA. CRL nu va fi generat.")
                    crl_path, crl_msg = None, "❌ CRL nu a fost generat (fără parolă)."
                else:
                    crl_path, crl_msg = main.generate_crl_if_missing(password)

                # Marchează SubCA ca activă
                self.show_success_message(
                    "Succes",
                    "✔ Certificatul SubCA, RootCA și CRL au fost importate și activate!\n\nChain-ul de încredere a fost creat.\n\n" + crl_msg
                )
                self.write_log("✔ Certificatul SubCA, RootCA și CRL importate. Chain.pem creat.")
                self.update_dashboard_cards()
                self.update_activity_feed()
                dialog.accept()
            except Exception as e:
                self.show_error_message("Eroare", f"Eroare la import: {str(e)}")

        btn.clicked.connect(do_import)
        self.center_dialog(dialog)

        dialog.exec_()

    def gen_client_dialog(self):
        if not self.check_critical_files(require_key=True, require_cert=True, require_chain=True, require_conf=True):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Generare certificat client")
        dialog.setMinimumSize(400, 700)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Nume client:"))
        client_name = QLineEdit()
        client_name.setMinimumWidth(250)
        client_name.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(client_name)

        layout.addWidget(QLabel("Țara (C):"))
        c_field = QLineEdit("RO")
        c_field.setMinimumWidth(250)
        c_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(c_field)

        layout.addWidget(QLabel("Stat/Județ (ST):"))
        st_field = QLineEdit("Sibiu")
        st_field.setMinimumWidth(250)
        st_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(st_field)

        layout.addWidget(QLabel("Localitate (L):"))
        l_field = QLineEdit()
        l_field.setMinimumWidth(250)
        l_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(l_field)

        layout.addWidget(QLabel("Organizație (O):"))
        o_field = QLineEdit("Academie")
        o_field.setMinimumWidth(250)
        o_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(o_field)

        layout.addWidget(QLabel("Unitate (OU):"))
        ou_field = QLineEdit("IT")
        ou_field.setMinimumWidth(250)
        ou_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(ou_field)

        layout.addWidget(QLabel("Common Name (CN):"))
        cn_field = QLineEdit()
        cn_field.setMinimumWidth(250)
        cn_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(cn_field)

        layout.addWidget(QLabel("Tip certificat:"))
        client_type = QComboBox()
        client_type.addItems(["client", "server", "router", "email", "codesign"])
        client_type.setFixedHeight(30)
        client_type.setStyleSheet("font-size: 13px; padding: 5px;")
        layout.addWidget(client_type)

        layout.addWidget(QLabel("IP NFS client (obligatoriu):"))
        ip_field = QLineEdit()
        ip_field.setMinimumWidth(250)
        ip_field.setStyleSheet("padding: 5px; font-size: 13px;")
        layout.addWidget(ip_field)

        btn = QPushButton("Generează")
        btn.setFixedHeight(40)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)

        layout.addWidget(btn)

        def generate():
            client = client_name.text().strip()
            ip_nfs = ip_field.text().strip()

            if not client:
                self.show_error_message("Eroare", "Introduceți un nume pentru client.")
                return
            if not ip_nfs:
                self.show_error_message("Eroare", "Introduceți IP-ul NFS pentru client (obligatoriu).")
                return

            fields = [c_field, st_field, l_field, o_field, ou_field, cn_field]
            if any(not field.text().strip() for field in fields):
                self.show_error_message("Eroare", "Toate câmpurile din subiectul certificatului sunt obligatorii.")
                return

            ctype = client_type.currentText().strip()
            subject = (
                f"/C={c_field.text().strip()}"
                f"/ST={st_field.text().strip()}"
                f"/L={l_field.text().strip()}"
                f"/O={o_field.text().strip()}"
                f"/OU={ou_field.text().strip()}"
                f"/CN={cn_field.text().strip()}"
            )

            # Verificare parolă SubCA înainte de generare
            pwd, ok = QInputDialog.getText(self, "Parolă SubCA", "Introduceți parola SubCA:", QLineEdit.Password)
            if not ok or not pwd:
                return

            # Generează certificatul
            result = client_cert.gen_client_cert(client, subject, pwd, ctype)

            self.show_success_message("Succes", f"✔ Certificatul pentru '{client}' a fost generat cu succes.")
            self.write_log(f"✔ Certificatul pentru '{client}' a fost generat cu succes.")
            self.update_dashboard_cards()
            self.update_activity_feed()
            self.update_clients_list()
            dialog.accept()

            # Export automat în NFS (scenariu real)
            nfs_client_dir = f"/mnt/pki_shared/{client}"
            try:
                if os.path.ismount("/mnt/pki_shared"):
                    self.sudo_makedirs(nfs_client_dir)
                    exported = []
                    errors = []
                    # .crt
                    crt_path = os.path.join(main.CLIENT_DIR, client, f"{client}.crt")
                    if os.path.exists(crt_path):
                        if self.sudo_copy(crt_path, os.path.join(nfs_client_dir, f"{client}.crt")):
                            exported.append(f"{client}.crt")
                            self.write_log(f"✔ {client}.crt exportat automat în NFS.")
                            # Setează permisiuni corecte pe fișier
                            crt_nfs_path = os.path.join(nfs_client_dir, f"{client}.crt")
                            import pexpect
                            sudo_pass = self.get_sudo_password()
                            child = pexpect.spawn(f"sudo chown nobody:nogroup '{crt_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                            child = pexpect.spawn(f"sudo chmod 644 '{crt_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                        else:
                            errors.append(f"{client}.crt nu a putut fi exportat în NFS.")
                    else:
                        errors.append(f"{client}.crt nu există.")
                    # .key
                    key_path = os.path.join(main.CLIENT_DIR, client, f"{client}.key")
                    if os.path.exists(key_path):
                        if self.sudo_copy(key_path, os.path.join(nfs_client_dir, f"{client}.key")):
                            exported.append(f"{client}.key")
                            self.write_log(f"✔ {client}.key exportat automat în NFS.")
                            # Setează permisiuni corecte pe fișier
                            key_nfs_path = os.path.join(nfs_client_dir, f"{client}.key")
                            import pexpect
                            sudo_pass = self.get_sudo_password()
                            child = pexpect.spawn(f"sudo chown nobody:nogroup '{key_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                            child = pexpect.spawn(f"sudo chmod 644 '{key_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                        else:
                            errors.append(f"{client}.key nu a putut fi exportat în NFS.")
                    else:
                        errors.append(f"{client}.key nu există.")
                    # .p12
                    p12_path = os.path.join(main.CLIENT_DIR, client, f"{client}.p12")
                    if os.path.exists(p12_path):
                        if self.sudo_copy(p12_path, os.path.join(nfs_client_dir, f"{client}.p12")):
                            exported.append(f"{client}.p12")
                            self.write_log(f"✔ {client}.p12 exportat automat în NFS.")
                            # Setează permisiuni corecte pe fișier
                            p12_nfs_path = os.path.join(nfs_client_dir, f"{client}.p12")
                            import pexpect
                            sudo_pass = self.get_sudo_password()
                            child = pexpect.spawn(f"sudo chown nobody:nogroup '{p12_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                            child = pexpect.spawn(f"sudo chmod 644 '{p12_nfs_path}'")
                            child.expect('password for')
                            child.sendline(sudo_pass)
                            child.sendeof()
                            child.close()
                        else:
                            errors.append(f"{client}.p12 nu a putut fi exportat în NFS.")
                    # fullchain.pem pentru server/webserver
                    if ctype.lower() in ["server", "webserver"]:
                        chain_path = os.path.join(main.SUBCA_DIR, "chain.pem")
                        fullchain_path = os.path.join(nfs_client_dir, f"{client}_fullchain.pem")
                        try:
                            if os.path.exists(crt_path) and os.path.exists(chain_path):
                                with open(f"/tmp/{client}_fullchain.pem", "w") as fout, open(crt_path,
                                                                                             "r") as fcrt, open(
                                        chain_path, "r") as fchain:
                                    fout.write(fcrt.read())
                                    fout.write("\n")
                                    fout.write(fchain.read())
                                if self.sudo_copy(f"/tmp/{client}_fullchain.pem", fullchain_path):
                                    exported.append(f"{client}_fullchain.pem")
                                    self.write_log(f"✔ {client}_fullchain.pem exportat automat în NFS.")
                                    self.show_success_message("Export NFS",
                                                              f"✔ fullchain.pem generat pentru server/webserver: {fullchain_path}")
                                    # Setează permisiuni pe fișier
                                    import pexpect
                                    sudo_pass = self.get_sudo_password()
                                    child = pexpect.spawn(f"sudo chown nobody:nogroup '{fullchain_path}'")
                                    child.expect('password for')
                                    child.sendline(sudo_pass)
                                    child.sendeof()
                                    child.close()
                                    child = pexpect.spawn(f"sudo chmod 644 '{fullchain_path}'")
                                    child.expect('password for')
                                    child.sendline(sudo_pass)
                                    child.sendeof()
                                    child.close()
                                    # Copiere CRL automat
                                    crl_src = os.path.join(main.SUBCA_DIR, "crl", "subca.crl.pem")
                                    crl_dst = os.path.join(nfs_client_dir, "subCA.crl")
                                    if os.path.exists(crl_src):
                                        if self.sudo_copy(crl_src, crl_dst):
                                            exported.append("subCA.crl")
                                            self.write_log(f"✔ subCA.crl exportat automat în NFS.")
                                            child = pexpect.spawn(f"sudo chown nobody:nogroup '{crl_dst}'")
                                            child.expect('password for')
                                            child.sendline(sudo_pass)
                                            child.sendeof()
                                            child.close()
                                            child = pexpect.spawn(f"sudo chmod 644 '{crl_dst}'")
                                            child.expect('password for')
                                            child.sendline(sudo_pass)
                                            child.sendeof()
                                            child.close()
                                        else:
                                            errors.append("subCA.crl nu a putut fi exportat în NFS.")
                                    else:
                                        errors.append("subca.crl.pem nu există pentru export CRL.")
                                else:
                                    errors.append(f"{client}_fullchain.pem nu a putut fi exportat în NFS.")
                            else:
                                errors.append(f"Nu există crt sau chain.pem pentru fullchain.")
                        except Exception as e:
                            errors.append(f"Eroare fullchain.pem: {str(e)}")
                            self.write_log(f"❌ Eroare la generarea fullchain.pem: {str(e)}")
                    if exported:
                        self.show_success_message("Export NFS", f"✔ Export automat în NFS pentru: {', '.join(exported)}")
                    if errors:
                        self.show_warning_message("Export NFS - probleme", "\n".join(errors))
                        self.write_log(f"⚠ Probleme la exportul automat în NFS: {'; '.join(errors)}")
                else:
                    self.show_warning_message("NFS nemontat", "Folderul NFS (/mnt/pki_shared) nu este montat. Exportul automat nu a fost efectuat.")
                    self.write_log("⚠ Exportul automat client în NFS nu a fost efectuat: NFS nemontat.")
            except Exception as e:
                self.show_error_message("Eroare export NFS", f"Nu s-a putut exporta automat în NFS: {str(e)}")
                self.write_log(f"❌ Eroare la exportul automat client în NFS: {str(e)}")
            # Creează subfolderul NFS cu permisiuni corecte înainte de export
            try:
                nfs_dir = f"/srv/pki_shared/{client}"
                import pexpect
                sudo_pass = self.get_sudo_password()
                if not sudo_pass:
                    self.show_error_message("Eroare", "Nu s-a introdus parola sudo. Nu pot crea folderul NFS.")
                    return
                # mkdir -p
                child = pexpect.spawn(f'sudo mkdir -p {nfs_dir}')
                child.expect('password for')
                child.sendline(sudo_pass)
                child.sendeof()
                child.close()
                # chown nobody:nogroup
                child = pexpect.spawn(f'sudo chown nobody:nogroup {nfs_dir}')
                child.expect('password for')
                child.sendline(sudo_pass)
                child.sendeof()
                child.close()
                # chmod 755
                child = pexpect.spawn(f'sudo chmod 755 {nfs_dir}')
                child.expect('password for')
                child.sendline(sudo_pass)
                child.sendeof()
                child.close()
                self.write_log(f"✔ Creat folder NFS {nfs_dir} cu permisiuni nobody:nogroup 755.")
            except Exception as e:
                self.write_log(f"❌ Eroare la crearea folderului NFS pentru {client}: {str(e)}")
            # Adaugă acces NFS pentru client
            try:
                nfs_export_line = f"/srv/pki_shared/{client} {ip_nfs}(rw,sync,no_subtree_check)\n"
                child = pexpect.spawn('sudo tee -a /etc/exports')
                child.expect('password for')
                child.sendline(sudo_pass)
                child.sendline(nfs_export_line)
                child.sendeof()
                child.close()
                os.system('sudo exportfs -ra')
                os.system('sudo systemctl restart nfs-kernel-server')
                self.write_log(f"✔ Adăugat acces NFS pentru {client} ({ip_nfs}) în /etc/exports.")
            except Exception as e:
                self.write_log(f"❌ Eroare la adăugarea accesului NFS pentru {client}: {str(e)}")

        btn.clicked.connect(generate)

        self.center_dialog(dialog)
        dialog.exec_()


    def sign_csr_dialog(self):
        if not self.check_critical_files(require_key=True, require_cert=True, require_chain=True, require_conf=True):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Semnează CSR extern")
        dialog.setMinimumSize(400, 400)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Selectare fișier CSR
        layout.addWidget(QLabel("Selectează fișierul CSR:"))
        csr_path = QLineEdit()
        layout.addWidget(csr_path)

        def browse_file():
            path, _ = QFileDialog.getOpenFileName(dialog, "Selectează fișierul CSR", "", "CSR files (*.csr)")
            if path:
                csr_path.setText(path)

        browse_btn = QPushButton("Selectează fișierul")
        browse_btn.clicked.connect(browse_file)
        layout.addWidget(browse_btn)

        # Import automat CSR din NFS
        import_csr_nfs_btn = QPushButton("Importă CSR din NFS")
        import_csr_nfs_btn.setStyleSheet("""
            QPushButton {
                background-color: #249d6b;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #36a16b;
            }
        """)
        layout.addWidget(import_csr_nfs_btn)
        def import_csr_from_nfs():
            client = client_name.text().strip()
            if not client:
                self.show_error_message("Eroare", "Introduceți numele clientului pentru a importa CSR-ul din NFS.")
                return
            nfs_csr_path = f"/mnt/pki_shared/{client}/{client}.csr"
            if os.path.exists(nfs_csr_path):
                csr_path.setText(nfs_csr_path)
                self.show_success_message("Import CSR NFS", f"✔ CSR-ul pentru '{client}' a fost importat automat din NFS.")
                self.write_log(f"✔ CSR-ul pentru '{client}' importat automat din NFS.")
            else:
                self.show_error_message("Eroare", f"CSR-ul nu există în NFS la: {nfs_csr_path}")
                self.write_log(f"❌ CSR-ul pentru '{client}' nu există în NFS ({nfs_csr_path})")
        import_csr_nfs_btn.clicked.connect(import_csr_from_nfs)

        # Previzualizare CSR
        def preview_csr():
            path = csr_path.text().strip()
            if not path or not os.path.isfile(path):
                self.show_error_message("Eroare", "Selectează un fișier CSR valid.")
                return

            text = main.preview_csr(path)

            preview_dialog = QDialog(self)
            preview_dialog.setWindowTitle("Previzualizare CSR")
            preview_dialog.resize(800, 500)

            preview_layout = QVBoxLayout(preview_dialog)
            text_edit = QTextEdit()
            text_edit.setPlainText(text)
            text_edit.setReadOnly(True)
            preview_layout.addWidget(text_edit)

            preview_dialog.exec_()

        preview_btn = QPushButton("Previzualizează CSR")
        preview_btn.clicked.connect(preview_csr)
        layout.addWidget(preview_btn)

        # Nume client
        layout.addWidget(QLabel("Nume pentru client:"))
        client_name = QLineEdit()
        layout.addWidget(client_name)

        # Tip certificat
        layout.addWidget(QLabel("Tip certificat (extensie):"))
        ext_type = QComboBox()
        ext_type.addItems([
            "v3_req_client", "v3_req_server", "v3_req_router",
            "v3_req_email", "v3_req_codesign", "v3_req_default"
        ])

        layout.addWidget(ext_type)

        # Parolă SubCA
        layout.addWidget(QLabel("Parolă SubCA:"))
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(password)

        btn = QPushButton("Semnează CSR")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def do_sign():
            csr_path_text = csr_path.text().strip()
            client = client_name.text().strip()
            pwd = password.text().strip()

            if not csr_path_text or not client or not pwd:
                self.show_error_message("Eroare", "Toate câmpurile sunt obligatorii.")
                return

            if not os.path.isfile(csr_path_text):
                self.show_error_message("Eroare", "Fișierul CSR nu există.")
                return

            client_dir = os.path.join(main.CLIENT_DIR, client)
            if os.path.exists(client_dir):
                reply = QMessageBox.question(
                    self, "Client existent",
                    f"Clientul '{client}' există deja.\nVrei să continui și să suprascrii certificatul?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            def ensure_extension_exists(ext_name):
                conf_path = os.path.join(main.SUBCA_DIR, "openssl.cnf")
                if not os.path.exists(conf_path):
                    return "❌ Fișierul openssl.cnf nu există."

                with open(conf_path, "r") as f:
                    content = f.read()

                if f"[ {ext_name} ]" not in content:
                    extra = f"\n\n[{ext_name}]\n"
                    extra += "basicConstraints = CA:FALSE\n"
                    extra += "keyUsage = digitalSignature, keyEncipherment\n"
                    if "server" in ext_name or "router" in ext_name:
                        extra += "extendedKeyUsage = serverAuth\n"
                    else:
                        extra += "extendedKeyUsage = clientAuth\n"

                    with open(conf_path, "a") as f:
                        f.write(extra)
                    return f"✔ Extensia {ext_name} a fost adăugată în openssl.cnf."
                return f"✔ Extensia {ext_name} există deja."

            msg = ensure_extension_exists(ext_type.currentText())
            self.write_log(msg)

            # Semnează CSR-ul
            result = main.sign_external_csr(csr_path_text, client, ext_type.currentText(), pwd)

            if "error" in result.lower():
                self.show_error_message("Eroare", result)
            else:
                self.show_success_message("Succes", f"✔ CSR-ul pentru '{client}' a fost semnat cu succes.")

            # Log și actualizări
            self.write_log(result)
            self.update_dashboard_cards()
            self.update_activity_feed()
            dialog.accept()

        btn.clicked.connect(do_sign)
        self.center_dialog(dialog)
        dialog.exec_()

    def verify_simple_cert_dialog(self):
        if not self.check_critical_files(require_cert=True, require_chain=True):
            return
        clients = sorted(os.listdir(main.CLIENT_DIR))
        if not clients:
            self.show_error_message("Eroare", "Nu există clienți.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Verificare certificat client")
        dialog.setMinimumSize(300, 150)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Selectează clientul:"))

        client_combo = QComboBox()
        client_combo.addItems(clients)
        layout.addWidget(client_combo)

        btn = QPushButton("Verifică")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def verify():
            client = client_combo.currentText()
            crl_result = client_cert.verify_cert_simple(client)
            days_left = self.get_cert_expiry_days(client)
            if days_left is not None and days_left < 30:
                msg_exp = f"⚠ Certificatul '{client}' expiră în {days_left} zile!"
                self.show_warning_message("Avertisment expirare", msg_exp)
                self.write_log(msg_exp)
            if "OK" in crl_result:
                msg = f"✔ Certificatul '{client}' este valid (verificat cu chain.pem)."
                self.show_success_message("Certificat valid", msg)
                self.write_log(f"✔ Certificatul clientului {client} este valid.")
            elif "revocat" in crl_result.lower():
                msg = f"⚠ Certificatul '{client}' este revocat conform CRL."
                self.show_error_message("Certificat revocat", msg)
                self.write_log(f"⚠ Certificatul '{client}' este revocat conform CRL.")
            else:
                msg = f"❌ Certificatul '{client}' NU este valid (verificare eșuată)."
                self.show_error_message("Certificat invalid", msg)
                self.write_log(f"❌ Certificatul '{client}' NU este valid (verificare eșuată).")
            self.update_dashboard_cards()
            self.update_activity_feed()
            dialog.accept()

        btn.clicked.connect(verify)
        self.center_dialog(dialog)
        dialog.exec_()

    def verify_crl_dialog(self):
        if not self.check_critical_files(require_cert=True, require_chain=True, require_crl=True):
            return
        clients = sorted(os.listdir(main.CLIENT_DIR))
        if not clients:
            self.show_error_message("Eroare", "Nu există clienți.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Verificare CRL")
        dialog.setMinimumSize(300, 150)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Selectează clientul:"))

        client_combo = QComboBox()
        client_combo.addItems(clients)
        layout.addWidget(client_combo)

        btn = QPushButton("Verifică")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def verify():
            client = client_combo.currentText()
            result = verify_cert_with_crl(client)

            if "revocat" in result.lower():
                msg = f"⚠️ Certificatul '{client}' este revocat conform CRL."
                self.show_warning_message("Certificat revocat", msg)
                self.write_log(msg)
            elif "NU este în CRL" in result:
                msg = f"✔ Certificatul '{client}' NU este în CRL."
                self.show_success_message("Certificat valid", msg)
                self.write_log(msg)
            else:
                msg = f"❌ Verificarea CRL a certificatului '{client}' a eșuat:\n{result}"
                self.show_error_message("Eroare verificare CRL", msg)
                self.write_log(msg)


            self.update_dashboard_cards()
            self.update_activity_feed()
            dialog.accept()

        btn.clicked.connect(verify)
        self.center_dialog(dialog)
        dialog.exec_()

    def revoke_client_dialog(self):
        if not self.check_critical_files(require_key=True, require_cert=True, require_chain=True, require_conf=True, require_crl=True):
            return
        all_clients = sorted(os.listdir(main.CLIENT_DIR))
        if not all_clients:
            self.show_error_message("Eroare", "Nu există clienți pentru revocare.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Revocă certificate client")
        dialog.setMinimumSize(450, 500)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        # Căutare
        search_input = QLineEdit()
        search_input.setPlaceholderText("Caută client...")
        layout.addWidget(QLabel("Caută client:"))
        layout.addWidget(search_input)
        # Scroll cu checkboxes
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        checkbox_container = QWidget()
        checkbox_layout = QVBoxLayout(checkbox_container)
        checkboxes = []

        for client in all_clients:
            cb = QCheckBox(client)
            checkboxes.append(cb)
            checkbox_layout.addWidget(cb)

        checkbox_layout.addStretch()
        scroll_area.setWidget(checkbox_container)
        layout.addWidget(scroll_area)


        toggle_all_btn = QPushButton("Selectează toți clienții vizibili")
        layout.addWidget(toggle_all_btn)

        # Checkbox pentru ștergere automată după revocare
        delete_checkbox = QCheckBox("Șterge automat clienții după revocare")
        layout.addWidget(delete_checkbox)

        # Parolă SubCA
        layout.addWidget(QLabel("Parolă SubCA:"))
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(password)

        # Buton principal
        btn = QPushButton("Revocă certificatele selectate")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        # Căutare
        def filter_clients():
            text = search_input.text().lower()
            for cb in checkboxes:
                is_match = text in cb.text().lower()
                cb.setVisible(is_match)

        # Selectează toți
        def toggle_all():
            any_unchecked = any(cb.isVisible() and not cb.isChecked() for cb in checkboxes)
            for cb in checkboxes:
                if cb.isVisible():
                    cb.setChecked(any_unchecked)

        # Revocă selecția
        def do_revoke():
            selected_items = [cb.text() for cb in checkboxes if cb.isChecked() and cb.isVisible()]
            pwd = password.text().strip()

            if not selected_items:
                self.show_error_message("Eroare", "Selectează cel puțin un client.")
                return

            if not pwd:
                self.show_error_message("Eroare", "Parola este obligatorie.")
                return


            confirm_dialog = QDialog(self)
            confirm_dialog.setWindowTitle("Confirmare revocare")
            confirm_dialog.setModal(True)
            confirm_dialog.setMinimumSize(400, 200)
            confirm_layout = QVBoxLayout(confirm_dialog)
            confirm_layout.addWidget(QLabel("Sigur dorești să revoci certificatele pentru:"))
            from PyQt5.QtWidgets import QTextEdit
            clients_text = QTextEdit(", ".join(selected_items))
            clients_text.setReadOnly(True)
            clients_text.setMaximumHeight(60)
            clients_text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
            confirm_layout.addWidget(clients_text)
            btns = QHBoxLayout()
            no_btn = QPushButton("No")
            no_btn.setStyleSheet("background-color:#444; color:white;")
            yes_btn = QPushButton("Yes")
            yes_btn.setStyleSheet("background-color:#388e3c; color:white; font-weight:bold;")
            btns.addWidget(no_btn)
            btns.addWidget(yes_btn)
            confirm_layout.addLayout(btns)
            confirmed = {"ok": False}
            def confirm_yes():
                confirmed["ok"] = True
                confirm_dialog.accept()
            def confirm_no():
                confirm_dialog.reject()
            yes_btn.clicked.connect(confirm_yes)
            no_btn.clicked.connect(confirm_no)
            self.center_dialog(confirm_dialog)
            confirm_dialog.exec_()
            if not confirmed["ok"]:
                return

            revoked_ok = []
            already_revoked = []
            failed = []
            no_cert = []

            for client in selected_items:
                crt_path = os.path.join(main.CLIENT_DIR, client, f"{client}.crt")
                if not os.path.exists(crt_path):
                    no_cert.append(client)
                    self.show_warning_message(
                        "Revocare fără efect",
                        f"Atenție: clientul '{client}' nu are certificat semnat. Revocarea nu va avea efect."
                    )
                    self.write_log(f"⚠ Revocare fără efect: clientul '{client}' nu are certificat semnat.")
                    continue  # NU apela revoke_client_cert!
                result = revoke_client_cert(client, pwd)
                if "already revoked" in result.lower():
                    already_revoked.append(client)
                    self.write_log(f"⚠ Certificatul pentru {client} era deja revocat anterior.")
                elif "revoked" in result.lower():
                    revoked_ok.append(client)
                    self.write_log(f"✔ Certificatul pentru {client} a fost revocat și lista CRL a fost actualizată.")
                    if delete_checkbox.isChecked():
                        # Ștergere automată folder NFS
                        nfs_client_dir = f"/mnt/pki_shared/{client}"
                        import subprocess
                        sudo_pwd = self.get_sudo_password()
                        if not sudo_pwd:
                            self.write_log(
                                f"❌ Ștergerea folderului NFS {nfs_client_dir} anulată: nu s-a introdus parola sudo.")
                        else:
                            proc = subprocess.run(
                                ["sudo", "-S", "rm", "-rf", nfs_client_dir],
                                input=sudo_pwd + "\n",
                                capture_output=True,
                                text=True
                            )
                            if proc.returncode == 0:
                                self.write_log(f"✔ Folderul NFS {nfs_client_dir} a fost șters automat.")
                            else:
                                self.write_log(
                                    f"❌ Eroare la ștergerea folderului NFS {nfs_client_dir}: {proc.stderr.strip()}")

                    else:
                        failed.append(client)
                        self.write_log(f"❌ Eroare la revocarea certificatului pentru {client}: {result}")
                else:
                    failed.append(client)
                    self.write_log(f"❌ Eroare la revocarea certificatului pentru {client}: {result}")

            if revoked_ok or already_revoked or no_cert:
                msg = ""
                if revoked_ok:
                    msg += "✔ Certificate revocate cu succes:\n" + ", ".join(revoked_ok) + "\n"
                if already_revoked:
                    msg += "⚠ Certificate deja revocate:\n" + ", ".join(already_revoked) + "\n"
                if no_cert:
                    msg += "⚠ Clienți fără certificat semnat (revocare fără efect):\n" + ", ".join(no_cert) + "\n"

                result_dialog = QDialog(self)
                result_dialog.setWindowTitle("Revocare finalizată")
                result_dialog.setModal(True)
                result_dialog.setMinimumSize(400, 200)
                layout = QVBoxLayout(result_dialog)
                layout.addWidget(QLabel("Rezultat revocare:"))
                text = QTextEdit(msg.strip())
                text.setReadOnly(True)
                text.setMaximumHeight(80)
                text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
                layout.addWidget(text)
                ok_btn = QPushButton("OK")
                ok_btn.setStyleSheet("background-color:#388e3c; color:white; font-weight:bold;")
                ok_btn.clicked.connect(result_dialog.accept)
                layout.addWidget(ok_btn)
                self.center_dialog(result_dialog)
                result_dialog.exec_()

            if failed:
                msg = "❌ Nu s-a putut revoca certificatul pentru:\n" + ", ".join(failed)
                fail_dialog = QDialog(self)
                fail_dialog.setWindowTitle("Revocare eșuată")
                fail_dialog.setModal(True)
                fail_dialog.setMinimumSize(400, 200)
                layout = QVBoxLayout(fail_dialog)
                layout.addWidget(QLabel("Eroare la revocare:"))
                text = QTextEdit(msg)
                text.setReadOnly(True)
                text.setMaximumHeight(80)
                text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
                layout.addWidget(text)
                ok_btn = QPushButton("OK")
                ok_btn.setStyleSheet("background-color:#d32f2f; color:white; font-weight:bold;")
                ok_btn.clicked.connect(fail_dialog.accept)
                layout.addWidget(ok_btn)
                self.center_dialog(fail_dialog)
                fail_dialog.exec_()

            self.update_dashboard_cards()
            self.update_activity_feed()
            self.filter_clients_list()
            self.update_clients_list()
            dialog.accept()

        # Conectări
        search_input.textChanged.connect(filter_clients)
        toggle_all_btn.clicked.connect(toggle_all)
        btn.clicked.connect(do_revoke)

        self.center_dialog(dialog)
        dialog.exec_()

    def delete_client_dialog(self):
        clients = sorted(os.listdir(main.CLIENT_DIR))
        if not clients:
            self.show_error_message("Eroare", "Nu există clienți de șters.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Ștergere clienți")
        dialog.setMinimumSize(400, 400)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Căutare
        search_input = QLineEdit()
        search_input.setPlaceholderText("Caută client...")
        layout.addWidget(QLabel("Caută client:"))
        layout.addWidget(search_input)

        # Scroll cu checkboxes
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        checkbox_container = QWidget()
        checkbox_layout = QVBoxLayout(checkbox_container)
        checkboxes = []

        for client in clients:
            cb = QCheckBox(client)
            checkboxes.append(cb)
            checkbox_layout.addWidget(cb)


        checkbox_layout.addStretch()

        scroll_area.setWidget(checkbox_container)
        layout.addWidget(scroll_area)


        toggle_all_btn = QPushButton("Selectează toți clienții vizibili")
        layout.addWidget(toggle_all_btn)

        # Buton de ștergere
        delete_btn = QPushButton("Șterge clienții selectați")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
        """)
        layout.addWidget(delete_btn)

        def filter_clients():
            text = search_input.text().lower()
            for cb in checkboxes:
                cb.setVisible(text in cb.text().lower())

        def toggle_all():
            any_unchecked = any(cb.isVisible() and not cb.isChecked() for cb in checkboxes)
            for cb in checkboxes:
                if cb.isVisible():
                    cb.setChecked(any_unchecked)

        def delete_selected():
            selected_items = [cb.text() for cb in checkboxes if cb.isChecked()]

            if not selected_items:
                self.show_error_message("Eroare", "Selectează cel puțin un client.")
                return

            selected_clients = selected_items
            not_revoked = []
            can_delete = []

            # Verificăm pentru fiecare client dacă poate fi șters
            for client in selected_clients:
                crt_path = os.path.join(main.CLIENT_DIR, client, f"{client}.crt")
                self.write_log(f"DEBUG: crt_path={crt_path}, exists={os.path.exists(crt_path)}")
                if not os.path.exists(crt_path):
                    can_delete.append(client)  # client nesemnat, poate fi șters direct
                    continue
                result = main.verify_cert_with_crl(client)
                self.write_log(f"DEBUG: verify_cert_with_crl({client}) => {result}")
                # Permite ștergerea dacă rezultatul conține orice variantă de revocare sau certificat invalid/inexistent
                if any(x in result.lower() for x in [
                    "revocat", "already revoked", "deja revocat", "nu există", "invalid",
                    "verification failed", "mismatch", "error"
                ]):
                    can_delete.append(client)
                else:
                    not_revoked.append(client)

            if not_revoked:
                msg = "⚠️ Nu poți șterge acești clienți deoarece certificatul lor nu este revocat:\n\n"
                msg += ", ".join(not_revoked)
                self.show_error_message("Ștergere blocată", msg)
                self.write_log(msg)
                return


            extra_dialog = QDialog(self)
            extra_dialog.setWindowTitle("Avertisment: Ștergere ireversibilă")
            extra_dialog.setModal(True)
            extra_dialog.setMinimumSize(400, 200)
            extra_layout = QVBoxLayout(extra_dialog)
            extra_layout.addWidget(QLabel("<b style='color:#d32f2f'>❗ Această acțiune este ireversibilă!</b>"))
            extra_layout.addWidget(QLabel("Clienții și toate certificatele/folderele asociate vor fi șterse definitiv.\nClienți selectați:"))
            from PyQt5.QtWidgets import QTextEdit
            clients_text = QTextEdit(", ".join(can_delete))
            clients_text.setReadOnly(True)
            clients_text.setMaximumHeight(60)
            clients_text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
            extra_layout.addWidget(clients_text)
            btns = QHBoxLayout()
            ok_btn = QPushButton("Șterge DEFINITIV")
            ok_btn.setStyleSheet("background-color:#d32f2f; color:white; font-weight:bold;")
            cancel_btn = QPushButton("Renunță")
            btns.addWidget(ok_btn)
            btns.addWidget(cancel_btn)
            extra_layout.addLayout(btns)
            confirmed = {"ok": False}
            def confirm():
                confirmed["ok"] = True
                extra_dialog.accept()
            def cancel():
                extra_dialog.reject()
            ok_btn.clicked.connect(confirm)
            cancel_btn.clicked.connect(cancel)
            self.center_dialog(extra_dialog)
            extra_dialog.exec_()
            if not confirmed["ok"]:
                self.show_info_message("Anulat", "Ștergerea a fost anulată.")
                return

            deleted_ok = []
            info = []
            failed = []

            for client in can_delete:
                result = main.delete_client_folder(client)
                if isinstance(result, str):
                    if result.startswith("[✓]"):
                        clean_msg = result.replace("[✓]", "✔")
                        deleted_ok.append(client)
                        self.write_log(clean_msg)
                        # --- Ștergere automată folder NFS ---
                        nfs_client_dir = f"/mnt/pki_shared/{client}"
                        import subprocess
                        try:
                            proc = subprocess.run([
                                "sudo", "rm", "-rf", nfs_client_dir
                            ], capture_output=True, text=True)
                            if proc.returncode == 0:
                                self.write_log(f"✔ Folderul NFS {nfs_client_dir} a fost șters automat.")
                            else:
                                self.write_log(f"❌ Eroare la ștergerea folderului NFS {nfs_client_dir}: {proc.stderr.strip()}")
                        except Exception as e:
                            self.write_log(f"❌ Eroare la execuția sudo rm -rf pentru {nfs_client_dir}: {str(e)}")
                        # --- Sfârșit ștergere automată NFS ---
                    elif result.startswith("[!]"):
                        clean_msg = result.replace("[!]", "ℹ")
                        info.append(f"{client}: {clean_msg}")
                        self.write_log(clean_msg)
                    else:
                        err_msg = f"❌ Eroare la ștergerea clientului {client}: {result}"
                        failed.append(client)
                        self.write_log(err_msg)
                else:
                    err_msg = f"❌ Eroare necunoscută la ștergerea clientului {client}."
                    failed.append(client)
                    self.write_log(err_msg)


            if deleted_ok or info:
                msg = ""
                if deleted_ok:
                    msg += "✔ Clienți șterși cu succes:\n" + ", ".join(deleted_ok) + "\n"
                if info:
                    msg += "ℹ Informații suplimentare:\n" + "\n".join(info) + "\n"
                # Dialog modern scrollabil
                result_dialog = QDialog(self)
                result_dialog.setWindowTitle("Ștergere finalizată")
                result_dialog.setModal(True)
                result_dialog.setMinimumSize(400, 200)
                layout = QVBoxLayout(result_dialog)
                layout.addWidget(QLabel("Rezultat ștergere:"))
                text = QTextEdit(msg.strip())
                text.setReadOnly(True)
                text.setMaximumHeight(80)
                text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
                layout.addWidget(text)
                ok_btn = QPushButton("OK")
                ok_btn.setStyleSheet("background-color:#388e3c; color:white; font-weight:bold;")
                ok_btn.clicked.connect(result_dialog.accept)
                layout.addWidget(ok_btn)
                self.center_dialog(result_dialog)
                result_dialog.exec_()

            if failed:
                msg = "❌ Nu s-a putut șterge clientul:\n" + ", ".join(failed)
                fail_dialog = QDialog(self)
                fail_dialog.setWindowTitle("Ștergere eșuată")
                fail_dialog.setModal(True)
                fail_dialog.setMinimumSize(400, 200)
                layout = QVBoxLayout(fail_dialog)
                layout.addWidget(QLabel("Eroare la ștergere:"))
                text = QTextEdit(msg)
                text.setReadOnly(True)
                text.setMaximumHeight(80)
                text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
                layout.addWidget(text)
                ok_btn = QPushButton("OK")
                ok_btn.setStyleSheet("background-color:#d32f2f; color:white; font-weight:bold;")
                ok_btn.clicked.connect(fail_dialog.accept)
                layout.addWidget(ok_btn)
                self.center_dialog(fail_dialog)
                fail_dialog.exec_()

            self.update_dashboard_cards()
            self.update_activity_feed()
            self.filter_clients_list()
            self.update_clients_list()
            dialog.accept()

        search_input.textChanged.connect(filter_clients)
        toggle_all_btn.clicked.connect(toggle_all)
        delete_btn.clicked.connect(delete_selected)

        self.center_dialog(dialog)
        dialog.exec_()

    def export_client_dialog(self):
        if not self.check_critical_files(require_cert=True, require_chain=True):
            return
        clients = sorted(os.listdir(main.CLIENT_DIR))
        if not clients:
            self.show_error_message("Eroare", "Nu există clienți pentru export.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Export certificat – selecție multiplă")
        dialog.resize(400, 500)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Selectează clienții pentru export:"))


        select_all_btn = QPushButton("Selectează toți")
        layout.addWidget(select_all_btn)

        search_box = QLineEdit()
        search_box.setPlaceholderText("Caută client...")
        layout.addWidget(search_box)


        scroll = QScrollArea()
        scroll.setMinimumHeight(180)
        scroll.setMaximumHeight(250)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        client_vars = {}

        for client in clients:
            checkbox = QCheckBox(client)
            checkbox.setStyleSheet("padding: 4px; font-size: 13px;")
            scroll_layout.addWidget(checkbox)
            client_vars[client] = checkbox

        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        # Funcție de filtrare
        def filter_clients():
            text = search_box.text().lower()
            for client, checkbox in client_vars.items():
                checkbox.setVisible(text in client.lower())

        search_box.textChanged.connect(filter_clients)


        def select_all():
            all_checked = all(var.isChecked() for var in client_vars.values())
            for var in client_vars.values():
                var.setChecked(not all_checked)

        select_all_btn.clicked.connect(select_all)

        layout.addWidget(QLabel("Formate de export:"))
        formats = {"p12": QCheckBox("P12"), "der": QCheckBox("DER"), "crt": QCheckBox("CRT")}
        for fmt in formats.values():
            layout.addWidget(fmt)

        layout.addWidget(QLabel("Parolă globală pentru .p12 (opțional):"))
        p12_pass = QLineEdit()
        p12_pass.setEchoMode(QLineEdit.Password)
        layout.addWidget(p12_pass)

        layout.addWidget(QLabel("Confirmă parola:"))
        p12_confirm = QLineEdit()
        p12_confirm.setEchoMode(QLineEdit.Password)
        layout.addWidget(p12_confirm)

        layout.addWidget(QLabel("Alege directorul de export (opțional):"))
        export_folder = QLineEdit()
        layout.addWidget(export_folder)

        def browse_folder():
            folder = QFileDialog.getExistingDirectory(dialog, "Selectează folderul de export")
            if folder:
                export_folder.setText(folder)

        browse_btn = QPushButton("Selectează folder")
        browse_btn.clicked.connect(browse_folder)
        layout.addWidget(browse_btn)

        btn = QPushButton("Exportă selecția")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def do_export_all():
            if formats["p12"].isChecked():
                if p12_pass.text() != p12_confirm.text():
                    self.show_error_message("Eroare", "Parolele globale nu coincid.")
                    return

            export_base = export_folder.text().strip()
            if not export_base:
                export_base = None

            result = ""
            any_exported = False

            for client, selected in client_vars.items():
                if not selected.isChecked():
                    continue

                client_path = os.path.join(main.CLIENT_DIR, client)
                key_path = os.path.join(client_path, f"{client}.key")
                cert_path = os.path.join(client_path, f"{client}.crt")

                if export_base:
                    export_path = os.path.join(export_base, client)
                else:
                    export_path = os.path.join(client_path, "exports")

                if "/mnt/pki_shared" in export_path:
                    self.sudo_makedirs(export_path)
                else:
                    os.makedirs(export_path, exist_ok=True)

                # Export .p12
                if formats["p12"].isChecked():
                    chain_path = os.path.join(main.SUBCA_DIR, "chain.pem")
                    # 1. Generează .p12 local (ex: /tmp/client.p12)
                    local_p12_path = f"/tmp/{client}.p12"
                    if p12_pass.text():
                        final_password = p12_pass.text()
                    else:
                        final_password = self.ask_dual_password(client)
                        if final_password is None:
                            msg = f"⛔ Export omis pentru {client} – parolă anulată"
                            result += msg + "\n"
                            self.write_log(msg)
                            continue
                    cmd = (
                        f"openssl pkcs12 -export -inkey {key_path} -in {cert_path} "
                        f"-certfile {chain_path} -out {local_p12_path} -passout pass:{final_password}"
                    )
                    export_result = main.run(cmd)
                    dest_p12_path = os.path.join(export_path, f"{client}.p12")
                    if "/mnt/pki_shared" in export_path:
                        if self.sudo_copy(local_p12_path, dest_p12_path):
                            msg = f"✔ Exportat .p12: {dest_p12_path}"
                            result += msg + "\n"
                            self.write_log(msg)
                            any_exported = True
                        else:
                            msg = f"❌ Eroare la copierea .p12 în NFS (permisiuni)"
                            result += msg + "\n"
                            self.write_log(msg)
                    else:
                        shutil.copy(local_p12_path, dest_p12_path)
                        msg = f"✔ Exportat .p12: {dest_p12_path}"
                        result += msg + "\n"
                        self.write_log(msg)
                        any_exported = True

                # Export .der
                if formats["der"].isChecked():
                    der_path = os.path.join(export_path, f"{client}.der")
                    export_result = main.run(f"openssl x509 -in {cert_path} -outform DER -out {der_path}")
                    result += export_result + f"✔ Exportat .der: {der_path}\n"
                    self.write_log(f"✔ Exportat .der pentru {client} în {der_path}")
                    any_exported = True

                # Export .crt
                if formats["crt"].isChecked():
                    crt_copy = os.path.join(export_path, f"{client}_copy.crt")
                    if "/mnt/pki_shared" in crt_copy:
                        if self.sudo_copy(cert_path, crt_copy):
                            msg = f"✔ Copiat: {crt_copy}"
                            result += msg + "\n"
                            self.write_log(msg)
                            any_exported = True
                        else:
                            msg = f"❌ Eroare la copierea: {crt_copy} (permisiuni)"
                            result += msg + "\n"
                            self.write_log(msg)
                    else:
                        shutil.copy(cert_path, crt_copy)
                        msg = f"✔ Copiat: {crt_copy}"
                        result += msg + "\n"
                        self.write_log(msg)
                        any_exported = True

            if not any_exported:
                result = "❌ Niciun certificat nu a fost exportat."
                self.write_log(result)

            result_dialog = QDialog(self)
            result_dialog.setWindowTitle("Export finalizat")
            result_dialog.setModal(True)
            result_dialog.setMinimumSize(400, 200)
            layout = QVBoxLayout(result_dialog)
            layout.addWidget(QLabel("Rezultat export:"))
            text = QTextEdit(result.strip())
            text.setReadOnly(True)
            text.setMaximumHeight(120)
            text.setStyleSheet("background: #232a34; color: #fff; border: 1px solid #444; font-size: 13px;")
            layout.addWidget(text)
            ok_btn = QPushButton("OK")
            ok_btn.setStyleSheet("background-color:#388e3c; color:white; font-weight:bold;")
            ok_btn.clicked.connect(result_dialog.accept)
            layout.addWidget(ok_btn)
            self.center_dialog(result_dialog)
            result_dialog.exec_()

            self.update_dashboard_cards()
            self.update_activity_feed()
            dialog.accept()

        btn.clicked.connect(do_export_all)
        self.center_dialog(dialog)
        dialog.exec_()

    def cert_details_dialog(self):
        clients = sorted(os.listdir(main.CLIENT_DIR))
        if not clients:
            self.show_error_message("Eroare", "Nu există clienți.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Detalii certificat client")
        dialog.setMinimumSize(300, 150)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Selectează clientul:"))

        client_combo = QComboBox()
        client_combo.addItems(clients)
        layout.addWidget(client_combo)

        btn = QPushButton("Afișează detalii")
        layout.addWidget(btn)

        def show_details():
            client = client_combo.currentText()
            crt_path = os.path.join(main.CLIENT_DIR, client, f"{client}.crt")
            if not os.path.exists(crt_path):
                self.show_error_message("Eroare", "Certificatul nu există.")
                return
            days_left = self.get_cert_expiry_days(client)
            if days_left is not None and days_left < 30:
                msg_exp = f"⚠ Certificatul '{client}' expiră în {days_left} zile!"
                self.show_warning_message("Avertisment expirare", msg_exp)
                self.write_log(msg_exp)
            output = main.run(f"openssl x509 -in {crt_path} -text -noout")
            preview_dialog = QDialog(self)
            preview_dialog.setWindowTitle(f"Detalii certificat - {client}")
            preview_dialog.resize(800, 500)
            preview_layout = QVBoxLayout(preview_dialog)
            text_edit = QTextEdit()
            text_edit.setPlainText(output)
            text_edit.setReadOnly(True)
            preview_layout.addWidget(text_edit)
            preview_dialog.exec_()

        btn.clicked.connect(show_details)
        self.center_dialog(dialog)
        dialog.exec_()

    def show_conf_dialog(self):
        try:
            with open(os.path.join(main.SUBCA_DIR, "openssl.cnf"), "r") as f:
                content = f.read()
        except FileNotFoundError:
            self.show_error_message("Eroare", "Fișierul openssl.cnf nu a fost găsit.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Vizualizare openssl.cnf")
        dialog.resize(700, 500)

        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        self.center_dialog(dialog)
        dialog.exec_()

    def edit_conf_dialog(self):
        try:
            path = os.path.join(main.SUBCA_DIR, "openssl.cnf")
            with open(path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            self.show_error_message("Eroare", "Fișierul openssl.cnf nu a fost găsit.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Editare openssl.cnf")
        dialog.resize(700, 500)

        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        layout.addWidget(text_edit)

        btn = QPushButton("Salvează modificările")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)

        def save_conf():
            new_content = text_edit.toPlainText().strip()
            with open(path, "w") as f:
                f.write(new_content)
            self.show_success_message("Salvare completă", "Modificările au fost salvate.")
            self.write_log("✔ Personalizare openssl.cnf aplicată.")
            dialog.accept()

        btn.clicked.connect(save_conf)
        self.center_dialog(dialog)
        dialog.exec_()

    def show_log_dialog(self):
        path = "pki_app.log"
        if not os.path.exists(path):
            self.show_error_message("Eroare", "Fișierul log nu există.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Log aplicație")
        dialog.resize(800, 500)

        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        with open(path) as f:
            text_edit.setPlainText(f.read())
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        def export_log():
            dest, _ = QFileDialog.getSaveFileName(dialog, "Salvează logul", "", "Text files (*.txt)")
            if dest:
                shutil.copy(path, dest)
                self.show_success_message("Export reușit", "Logul a fost exportat.")
                self.update_activity_feed()

        btn = QPushButton("Exportă logul ca .txt")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        btn.clicked.connect(export_log)
        layout.addWidget(btn)

        dialog.exec_()
        self.center_dialog(dialog)

    def ask_dual_password(self, client_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Parolă pentru {client_name}")
        dialog.setMinimumSize(320, 180)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"Introdu parola pentru {client_name}:"))

        pwd1 = QLineEdit()
        pwd1.setEchoMode(QLineEdit.Password)
        layout.addWidget(pwd1)

        layout.addWidget(QLabel("Confirmare parolă:"))
        pwd2 = QLineEdit()
        pwd2.setEchoMode(QLineEdit.Password)
        layout.addWidget(pwd2)

        btn = QPushButton("Confirmă")
        layout.addWidget(btn)

        result = {"password": None}

        def confirm():
            if pwd1.text() != pwd2.text():
                self.show_error_message("Eroare", "Parolele nu coincid!")
                return
            result["password"] = pwd1.text()
            dialog.accept()

        btn.clicked.connect(confirm)
        self.center_dialog(dialog)
        dialog.exec_()
        return result["password"]

    def get_last_action(self):
        try:
            with open("pki_app.log") as f:
                return f.readlines()[-1].strip()
        except Exception:
            return "-"

    def update_clients_list(self):
        self.clients_list.clear()
        try:
            filter_text = self.client_search.text().lower() if hasattr(self, 'client_search') else ''
            for c in sorted(os.listdir(main.CLIENT_DIR)):
                if filter_text and filter_text not in c.lower():
                    continue

                days_left = self.get_cert_expiry_days(c)
                if days_left is not None and days_left < 30:
                    item = QListWidgetItem(QIcon(self.style().standardIcon(QStyle.SP_MessageBoxWarning)), f"{c}  ⚠ expiră curând")
                else:
                    item = QListWidgetItem(QIcon(self.style().standardIcon(QStyle.SP_DirIcon)), c)
                self.clients_list.addItem(item)
        except Exception:
            pass

    def filter_clients_list(self):
        self.update_clients_list()


    def show_all_certs_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Toate certificatele emise")
        dialog.resize(500, 400)
        layout = QVBoxLayout(dialog)
        list_widget = QListWidget()
        try:
            # Construiește set cu seriale revocate
            revoked_serials = set()
            with open(os.path.join(main.SUBCA_DIR, "index.txt")) as f:
                for line in f:
                    if line.startswith("R"):
                        parts = line.split()
                        if len(parts) > 3:
                            revoked_serials.add(parts[3])

            for c in sorted(os.listdir(main.CLIENT_DIR)):
                crt_path = os.path.join(main.CLIENT_DIR, c, f"{c}.crt")
                if os.path.exists(crt_path):
                    # Extrage serialul certificatului
                    serial = os.popen(f"openssl x509 -in '{crt_path}' -noout -serial").read().strip().replace("serial=",
                                                                                                              "").upper()
                    if serial not in revoked_serials:
                        list_widget.addItem(f"{c} - {crt_path}")
        except Exception:
            pass
        layout.addWidget(list_widget)
        dialog.exec_()


    def show_revoked_certs_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Certificate revocate")
        dialog.resize(500, 400)
        layout = QVBoxLayout(dialog)
        list_widget = QListWidget()
        try:
            with open(os.path.join(main.SUBCA_DIR, "index.txt")) as f:
                for line in f:
                    if line.startswith("R"):
                        parts = line.split()
                        if len(parts) > 4:
                            list_widget.addItem(f"{parts[4]} - {parts[3]}")
        except Exception:
            pass
        layout.addWidget(list_widget)
        dialog.exec_()

    def change_font_dialog(self):
        from PyQt5.QtWidgets import QFontDialog
        font, ok = QFontDialog.getFont()
        if ok:
            self.setFont(font)

    def open_workspace_folder(self):
        import subprocess
        folder = os.path.abspath(".")
        try:
            subprocess.Popen(["xdg-open", folder])
        except Exception:
            QMessageBox.information(self, "Info", f"Folderul: {folder}")

    def reset_log(self):
        with open("pki_app.log", "w") as f:
            f.write("")
        self.log.clear()
        self.activity_feed.clear()
        self.activity_feed.addItem("⚠️ Nicio activitate logată încă.")
        self.update_activity_feed()
        QMessageBox.information(self, "Resetare log", "Logul a fost resetat.")

    def about_dialog(self):
        QMessageBox.information(self, "Despre aplicație",
                                "PKI Desktop App\nLicență 2025")

    def update_dashboard_cards(self):
        # Actualizează valorile dashboard-ului
        if hasattr(self, 'dashboard_cards') and len(self.dashboard_cards) >= 3:
            self.dashboard_cards[0].layout().itemAt(2).widget().setText(str(self.get_total_clients()))
            self.dashboard_cards[1].layout().itemAt(2).widget().setText(str(self.get_total_certs()))
            self.dashboard_cards[2].layout().itemAt(2).widget().setText(str(self.get_total_revoked()))
        self.update_activity_feed()

    def export_log_dialog(self):
        path = "pki_app.log"
        dest, _ = QFileDialog.getSaveFileName(self, "Salvează logul", "", "Text files (*.txt)")
        if dest:
            shutil.copy(path, dest)
            self.show_success_message("Export reușit", "Logul a fost exportat.")

    def show_ca_integrity_dialog(self):
        # Verifică fișierele critice
        checks = [
            ("Cheie privată SubCA (subCA.key)", os.path.exists(os.path.join(main.SUBCA_DIR, "subCA.key"))),
            ("Certificat SubCA (subCA.pem)", os.path.exists(os.path.join(main.SUBCA_DIR, "subCA.pem"))),
            ("Chain de încredere (chain.pem)", os.path.exists(os.path.join(main.SUBCA_DIR, "chain.pem"))),
            ("Config OpenSSL (openssl.cnf)", os.path.exists(os.path.join(main.SUBCA_DIR, "openssl.cnf"))),
            ("Lista CRL (crl/subca.crl.pem)", os.path.exists(os.path.join(main.SUBCA_DIR, "crl/subca.crl.pem"))),
        ]
        dialog = QDialog(self)
        dialog.setWindowTitle("Verificare integritate CA")
        dialog.setMinimumSize(400, 300)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Status fișiere critice CA:"))
        for label, ok in checks:
            status = "✔" if ok else "❌"
            color = "#249d6b" if ok else "#b36a1c"
            lbl = QLabel(f"<b style='color:{color}'>{status}</b> {label}")
            layout.addWidget(lbl)
        dialog.setLayout(layout)
        self.center_dialog(dialog)
        dialog.exec_()

    def get_cert_expiry_days(self, client_name):
        try:
            crt_path = os.path.join(main.CLIENT_DIR, client_name, f"{client_name}.crt")
            if not os.path.exists(crt_path):
                return None
            with open(crt_path, "rb") as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            exp_str = cert.get_notAfter().decode("ascii")
            exp_date = datetime.strptime(exp_str, "%Y%m%d%H%M%SZ")
            days_left = (exp_date - datetime.utcnow()).days
            return days_left
        except Exception:
            return None

    def configure_nfs_dialog(self):
        import pexpect
        dialog = QDialog(self)
        dialog.setWindowTitle("Configurare NFS RootCA")
        dialog.setMinimumSize(420, 320)
        dialog.setModal(True)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("IP RootCA (server NFS):"))
        ip_input = QLineEdit()
        ip_input.setPlaceholderText("ex: 192.168.1.10")
        layout.addWidget(ip_input)
        layout.addWidget(QLabel("Cale NFS pe RootCA (ex: /srv/pki_shared):"))
        nfs_path_input = QLineEdit("/srv/pki_shared")
        layout.addWidget(nfs_path_input)
        layout.addWidget(QLabel("Folder local pentru montare (ex: /mnt/pki_shared):"))
        local_path_input = QLineEdit("/mnt/pki_shared")
        layout.addWidget(local_path_input)
        layout.addWidget(QLabel("Parolă sudo (nu se salvează, doar pentru această operație):"))
        sudo_pass_input = QLineEdit()
        sudo_pass_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(sudo_pass_input)
        btn = QPushButton("Montează NFS")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1e90ff;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #3399ff;
            }
        """)
        layout.addWidget(btn)
        def do_mount():
            ip = ip_input.text().strip()
            nfs_path = nfs_path_input.text().strip()
            local_path = local_path_input.text().strip()
            sudo_pass = sudo_pass_input.text()
            if not ip or not nfs_path or not local_path or not sudo_pass:
                self.show_error_message("Eroare", "Toate câmpurile sunt obligatorii.")
                return

            try:
                if not os.path.exists(local_path):
                    import getpass
                    user = getpass.getuser()
                    child = pexpect.spawn(f"sudo mkdir -p {local_path} && sudo chown {user}:{user} {local_path}", encoding='utf-8')
                    i = child.expect(['password for', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
                    if i == 0:
                        child.sendline(sudo_pass)
                        child.expect(pexpect.EOF, timeout=10)
                    elif i == 2:
                        self.show_error_message("Timeout", "Timeout la introducerea parolei sudo pentru mkdir.")
                        return
                    # Verifică dacă folderul a fost creat
                    if not os.path.exists(local_path):
                        self.show_error_message("Eroare", f"Nu s-a putut crea folderul local: {local_path}")
                        return
                    else:
                        self.write_log(f"✔ Folderul local {local_path} a fost creat cu sudo.")
            except Exception as e:
                self.show_error_message("Eroare", f"Nu pot crea folderul local: {str(e)}")
                return

            cmd = f"sudo mount -t nfs {ip}:{nfs_path} {local_path}"
            try:
                child = pexpect.spawn(cmd, encoding='utf-8')
                i = child.expect(['password for', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
                if i == 0:
                    child.sendline(sudo_pass)
                    child.expect(pexpect.EOF, timeout=10)
                elif i == 1:
                    pass
                elif i == 2:
                    self.show_error_message("Timeout", "Timeout la introducerea parolei sudo.")
                    return
                output = child.before
                # Verifică dacă montarea a reușit
                if os.path.ismount(local_path):
                    self.show_success_message("Succes", f"✔ NFS montat cu succes la {local_path}")
                    self.write_log(f"✔ NFS montat la {local_path} (RootCA: {ip})")
                    dialog.accept()
                else:
                    self.show_error_message("Eroare", f"Montarea NFS a eșuat.\nOutput:\n{output}")
            except Exception as e:
                self.show_error_message("Eroare", f"Eroare la montare: {str(e)}")
        btn.clicked.connect(do_mount)
        self.center_dialog(dialog)
        dialog.exec_()

    def update_rootca_files_from_nfs(self):
        nfs_dir = "/mnt/pki_shared"
        errors = []
        imported = []
        # rootCA.pem
        src_rootca = os.path.join(nfs_dir, "rootCA.pem")
        dest_rootca = os.path.join(main.ROOT_DIR, "rootCA.pem")
        try:
            if os.path.exists(src_rootca):
                os.makedirs(main.ROOT_DIR, exist_ok=True)
                shutil.copy(src_rootca, dest_rootca)
                imported.append("rootCA.pem")
                self.write_log(f"✔ rootCA.pem actualizat din NFS.")
            else:
                errors.append("rootCA.pem nu există în NFS.")
        except Exception as e:
            errors.append(f"rootCA.pem: {str(e)}")
        # rootCA.crl.pem
        src_crl = os.path.join(nfs_dir, "rootCA.crl.pem")
        dest_crl_dir = os.path.join(main.SUBCA_DIR, "crl")
        dest_crl = os.path.join(dest_crl_dir, "rootCA.crl.pem")
        try:
            if os.path.exists(src_crl):
                os.makedirs(dest_crl_dir, exist_ok=True)
                shutil.copy(src_crl, dest_crl)
                imported.append("rootCA.crl.pem")
                self.write_log(f"✔ rootCA.crl.pem actualizat din NFS.")
            else:
                errors.append("rootCA.crl.pem nu există în NFS.")
        except Exception as e:
            errors.append(f"rootCA.crl.pem: {str(e)}")
        # chain.pem
        src_chain = os.path.join(nfs_dir, "chain.pem")
        dest_chain = os.path.join(main.SUBCA_DIR, "chain.pem")
        try:
            if os.path.exists(src_chain):
                shutil.copy(src_chain, dest_chain)
                imported.append("chain.pem")
                self.write_log(f"✔ chain.pem actualizat din NFS.")

        except Exception as e:
            errors.append(f"chain.pem: {str(e)}")

        if imported:
            self.show_success_message("Actualizare RootCA NFS", f"✔ Actualizare din NFS pentru: {', '.join(imported)}")
        if errors:
            self.show_warning_message("Actualizare RootCA NFS - probleme", "\n".join(errors))
            self.write_log(f"⚠ Probleme la actualizarea fișierelor RootCA din NFS: {'; '.join(errors)}")

    def get_sudo_password(self):
        now = time.time()
        if self.sudo_password and now - self.sudo_password_time < 300:
            return self.sudo_password
        pwd_dialog = PasswordDialog(self, "Parolă sudo", "Introduceți parola sudo pentru operații privilegiate:")
        pwd = pwd_dialog.get_password()
        if pwd:
            self.sudo_password = pwd
            self.sudo_password_time = now
            return pwd
        return None


    def sudo_copy(self, src, dest):
        sudo_pass = self.get_sudo_password()
        if not sudo_pass:
            self.show_error_message("Eroare", "Operația a fost anulată (nu s-a introdus parola sudo).")
            return False
        import pexpect
        cmd = f"sudo cp '{src}' '{dest}'"
        child = pexpect.spawn(cmd, encoding='utf-8')
        i = child.expect(['password for', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        if i == 0:
            child.sendline(sudo_pass)
            child.expect(pexpect.EOF, timeout=10)
        elif i == 2:
            self.show_error_message("Timeout", "Timeout la introducerea parolei sudo pentru cp.")
            return False
        return True

    def sudo_makedirs(self, path):
        sudo_pass = self.get_sudo_password()
        if not sudo_pass:
            self.show_error_message("Eroare", "Operația a fost anulată (nu s-a introdus parola sudo).")
            return False
        import getpass
        import pexpect
        user = getpass.getuser()
        cmd = f"sudo mkdir -p '{path}' && sudo chown {user}:{user} '{path}'"
        child = pexpect.spawn(cmd, encoding='utf-8')
        i = child.expect(['password for', pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        if i == 0:
            child.sendline(sudo_pass)
            child.expect(pexpect.EOF, timeout=10)
        elif i == 2:
            self.show_error_message("Timeout", "Timeout la introducerea parolei sudo pentru mkdir.")
            return False
        return True


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PKIAppQt()
    window.show()
    sys.exit(app.exec_())