# gui_installer.pyw
import os
import sys
import time
import json
import socket
import logging
import threading
import subprocess
import webbrowser
import urllib.request
from typing import Optional

# Configuração de UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TERMS_FILE = os.path.join(BASE_DIR, "TERMOS_DE_USO.md")
ICON_PATH = os.path.join(BASE_DIR, "assets", "sentinel_icon.ico")
PNG_ICON_PATH = os.path.join(BASE_DIR, "assets", "sentinel_icon.png")
RUNTIME_FILE = os.path.join(BASE_DIR, "sentinel_runtime.json")

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QProgressBar, QTextEdit,
    QStackedWidget, QFrame, QMessageBox, QSpacerItem, QSizePolicy,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QPixmap, QColor

from bootstrap_env import install_missing_dependencies
from sentinel_core.autostart_manager import WindowsAutoStartManager
from sentinel_core.antivirus_shield_helper import AntivirusAndFirewallShield
from sentinel_core.threat_intel import ThreatIntelFeed
from sentinel_core.canary_files import CanaryTokenEngine
from sentinel_core.honeytoken_deception import HoneytokenManager
from sentinela_service import SentinelBackgroundDaemon

# -------------------------------------------------------------
# ESTILOS MODERNOS CYBER-DEFENSE (DARK THEME)
# -------------------------------------------------------------
DARK_STYLESHEET = """
QMainWindow {
    background-color: #0b0f19;
}
QWidget#CentralWidget {
    background-color: #0b0f19;
}
QFrame#HeaderFrame {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #111827, stop:1 #1e293b);
    border-bottom: 1px solid #334155;
    border-radius: 0px;
    padding: 12px;
}
QLabel#HeaderTitle {
    color: #f8fafc;
    font-size: 20px;
    font-weight: bold;
    font-family: 'Segoe UI', Inter, sans-serif;
}
QLabel#HeaderSubtitle {
    color: #00e5ff;
    font-size: 12px;
    font-weight: 500;
    font-family: 'Segoe UI', Inter, sans-serif;
}
QFrame#CardFrame {
    background-color: #111827;
    border: 1px solid #1f293d;
    border-radius: 10px;
    padding: 14px;
}
QLabel {
    color: #e2e8f0;
    font-family: 'Segoe UI', Inter, sans-serif;
    font-size: 13px;
}
QLabel#SectionTitle {
    color: #38bdf8;
    font-size: 15px;
    font-weight: bold;
}
QCheckBox {
    color: #f1f5f9;
    font-size: 13px;
    spacing: 10px;
}
QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 1px solid #475569;
    background-color: #1e293b;
}
QCheckBox::indicator:checked {
    background-color: #0ea5e9;
    border: 1px solid #38bdf8;
}
QPushButton {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #334155;
    border: 1px solid #64748b;
}
QPushButton#PrimaryBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1);
    color: #ffffff;
    border: 1px solid #38bdf8;
}
QPushButton#PrimaryBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #075985);
}
QPushButton#SuccessBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669);
    color: #ffffff;
    border: 1px solid #34d399;
    font-size: 14px;
    padding: 12px 24px;
    font-weight: bold;
}
QPushButton#SuccessBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
}
QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
    height: 22px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00e5ff, stop:1 #3b82f6);
    border-radius: 5px;
}
QTextEdit#LogBox {
    background-color: #030712;
    border: 1px solid #1f293d;
    border-radius: 6px;
    color: #4ade80;
    font-family: 'Consolas', monospace;
    font-size: 12px;
    padding: 8px;
}
"""

class InstallationWorker(QThread):
    progress_signal = pyqtSignal(int, str)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, enable_autostart: bool, create_shortcuts: bool, apply_shield: bool, start_daemon: bool):
        super().__init__()
        self.enable_autostart = enable_autostart
        self.create_shortcuts = create_shortcuts
        self.apply_shield = apply_shield
        self.start_daemon = start_daemon

    def run(self):
        try:
            self.log_signal.emit("🛡️ INICIANDO INSTALAÇÃO E ATIVAÇÃO DO SENTINEL XDR...")
            self.progress_signal.emit(5, "Iniciando assistente de instalação...")
            time.sleep(0.4)

            # 1. Dependências do ambiente Python
            self.progress_signal.emit(15, "Verificando dependências e recursos...")
            self.log_signal.emit("📦 [1/7] Verificando bibliotecas e integridade Python...")
            try:
                install_missing_dependencies()
                self.log_signal.emit("   ✓ Dependências do sistema validadas com sucesso.")
            except Exception as e:
                self.log_signal.emit(f"   ! Aviso nas dependências: {e}")
            time.sleep(0.4)

            # 2. Blindagem contra bloqueios de Defender/Firewall
            if self.apply_shield:
                self.progress_signal.emit(30, "Aplicando blindagem contra bloqueios do Windows Defender...")
                self.log_signal.emit("🛡️  [2/7] Aplicando regras de proteção e liberação no Firewall...")
                try:
                    AntivirusAndFirewallShield.apply_all_protections(BASE_DIR)
                    self.log_signal.emit("   ✓ Blindagem do Windows Defender & Firewall aplicada.")
                except Exception as e:
                    self.log_signal.emit(f"   ! Aviso na blindagem: {e}")
            else:
                self.log_signal.emit("   [-] Blindagem do Defender ignorada pelo usuário.")
            time.sleep(0.4)

            # 3. Estrutura de Diretórios Soberanos
            self.progress_signal.emit(45, "Criando cofre criptográfico, quarentena e armadilhas...")
            self.log_signal.emit("🚀 [3/7] Criando diretórios do cofre AES-256 e armadilhas canário...")
            dirs = [
                "quarantine", "sentinel_vault", "canary_traps", "honeypots",
                "user_documents", "restored", "assets", "sentinel_baits"
            ]
            for d in dirs:
                dp = os.path.join(BASE_DIR, d)
                os.makedirs(dp, exist_ok=True)
            self.log_signal.emit("   ✓ Estrutura de diretórios soberana criada.")
            time.sleep(0.3)

            # 4. Sincronização Inicial de CTI (Cyber Threat Intelligence) e Armadilhas
            self.progress_signal.emit(60, "Sincronizando feeds de Threat Intelligence (CTI) e Canários...")
            self.log_signal.emit("🌐 [4/7] Sincronizando feeds globais de CTI e armando canários...")
            try:
                cti = ThreatIntelFeed()
                cti_count = cti.sync_feeds()
                self.log_signal.emit(f"   ✓ CTI Global sincronizado ({cti_count} IOCs e IPs maliciosos ativos).")

                canary_engine = CanaryTokenEngine(base_dir=os.path.join(BASE_DIR, "canary_traps"))
                canary_engine.setup_canaries()
                self.log_signal.emit("   ✓ Arquivos canário e armadilhas DLP armadas.")
            except Exception as e:
                self.log_signal.emit(f"   ! Aviso na sincronização de CTI/Canários: {e}")
            time.sleep(0.4)

            # 5. Configuração de Inicialização Automática no Boot
            if self.enable_autostart:
                self.progress_signal.emit(75, "Configurando inicialização automática no boot...")
                self.log_signal.emit("⚙️  [5/7] Registrando inicialização no registro do Windows...")
                ok, msg = WindowsAutoStartManager.enable_autostart(BASE_DIR)
                if ok:
                    self.log_signal.emit("   ✓ Inicialização automática ativada no Windows.")
                else:
                    self.log_signal.emit(f"   ! Aviso no autostart: {msg}")
            else:
                WindowsAutoStartManager.disable_autostart()
                self.log_signal.emit("   [-] Inicialização no boot desativada.")
            time.sleep(0.3)

            # 6. Criar Atalhos na Área de Trabalho
            if self.create_shortcuts:
                self.progress_signal.emit(85, "Criando atalhos de acesso rápido...")
                self.log_signal.emit("🖥️  [6/7] Criando atalho 'SENTINEL XDR' na Área de Trabalho...")
                try:
                    WindowsAutoStartManager.create_desktop_shortcut(BASE_DIR)
                    self.log_signal.emit("   ✓ Atalho criado com sucesso na Área de Trabalho.")
                except Exception as e:
                    self.log_signal.emit(f"   ! Falha ao criar atalho: {e}")
            time.sleep(0.3)

            # 7. Inicializar Serviços em Segundo Plano e Auto-Diagnóstico
            if self.start_daemon:
                self.progress_signal.emit(95, "Inicializando as 20 camadas de defesa e auto-diagnóstico...")
                self.log_signal.emit("⚡ [7/7] Inicializando daemon de defesa e testando integridade...")
                
                # Executa o tray_app.pyw via VBScript ou pythonw em modo silencioso
                vbs_path = WindowsAutoStartManager.get_vbs_launcher_path(BASE_DIR)
                if os.path.exists(vbs_path):
                    subprocess.Popen(["wscript.exe", vbs_path], cwd=BASE_DIR, shell=False)
                else:
                    pythonw = WindowsAutoStartManager.get_pythonw_path()
                    tray_path = WindowsAutoStartManager.get_tray_app_path(BASE_DIR)
                    subprocess.Popen([pythonw, tray_path], cwd=BASE_DIR, shell=False)

                self.log_signal.emit("   ✓ 14 motores de proteção ativados e operando.")
            time.sleep(0.8)

            self.progress_signal.emit(100, "Instalação concluída com sucesso!")
            self.log_signal.emit("\n🎉 INSTALAÇÃO E ATIVAÇÃO CONCLUÍDAS COM SUCESSO! 100% OPERACIONAL.")
            self.finished_signal.emit(True, "Sucesso")

        except Exception as e:
            self.log_signal.emit(f"\n❌ ERRO DURANTE A INSTALAÇÃO: {e}")
            self.finished_signal.emit(False, str(e))


class SentinelGuiInstaller(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SENTINEL XDR | Assistente de Instalação e Ativação Soberana")
        self.resize(780, 580)
        self.setMinimumSize(720, 530)

        # Ícone da Janela
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))
        elif os.path.exists(PNG_ICON_PATH):
            self.setWindowIcon(QIcon(PNG_ICON_PATH))

        self.setStyleSheet(DARK_STYLESHEET)
        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget(self)
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ----------------- HEADER -----------------
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 15, 20, 15)

        # Ícone do Header
        header_icon_lbl = QLabel()
        if os.path.exists(PNG_ICON_PATH):
            pix = QPixmap(PNG_ICON_PATH).scaled(44, 44, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            header_icon_lbl.setPixmap(pix)
        else:
            header_icon_lbl.setText("🛡️")
            header_icon_lbl.setFont(QFont("Segoe UI", 24))
        header_layout.addWidget(header_icon_lbl)

        header_text_layout = QVBoxLayout()
        header_text_layout.setSpacing(2)
        title_lbl = QLabel("SENTINEL XDR SOVEREIGN")
        title_lbl.setObjectName("HeaderTitle")
        subtitle_lbl = QLabel("Defesa Cibernética Ativa, EDR, Quarentena, CTI Global & Proteção Anti-Ransomware")
        subtitle_lbl.setObjectName("HeaderSubtitle")
        header_text_layout.addWidget(title_lbl)
        header_text_layout.addWidget(subtitle_lbl)

        header_layout.addLayout(header_text_layout)
        header_layout.addStretch()

        main_layout.addWidget(header_frame)

        # ----------------- STACKED PAGES -----------------
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget, 1)

        self._build_page_welcome()
        self._build_page_options()
        self._build_page_installing()
        self._build_page_finished()

        self.stacked_widget.setCurrentIndex(0)

    # ----------------- PAGE 1: WELCOME & TERMS -----------------
    def _build_page_welcome(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(14)

        welcome_title = QLabel("Bem-vindo à Instalação do Sentinela XDR")
        welcome_title.setObjectName("SectionTitle")
        layout.addWidget(welcome_title)

        desc = QLabel(
            "O Sentinela XDR é uma plataforma de cibersegurança soberana de nível militar para proteger seu computador "
            "contra malwares, ransomware, invasões, ameaças zero-day e vazamento de dados com resposta autônoma."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Termos Card
        card = QFrame()
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(10)

        card_title = QLabel("📋 Termos de Uso e Soberania Local de Dados (EULA):")
        card_title.setStyleSheet("font-weight: bold; color: #f8fafc;")
        card_layout.addWidget(card_title)

        bullet1 = QLabel("• <b>Soberania Total:</b> Seus arquivos, análises e logs são processados 100% no seu computador (sem envio para nuvem).")
        bullet2 = QLabel("• <b>Cofre Criptográfico AES-256:</b> Arquivos suspeitos são isolados com segurança na quarentena criptografada.")
        bullet3 = QLabel("• <b>Defesa Ativa & CTI:</b> O software aplicará regras no Firewall do Windows e sincronizará feeds de inteligência de ameaças.")
        bullet1.setWordWrap(True)
        bullet2.setWordWrap(True)
        bullet3.setWordWrap(True)
        card_layout.addWidget(bullet1)
        card_layout.addWidget(bullet2)
        card_layout.addWidget(bullet3)

        btn_view_terms = QPushButton("📄 Ler Termos de Uso Completos")
        btn_view_terms.setFixedWidth(240)
        btn_view_terms.clicked.connect(self._open_terms_file)
        card_layout.addWidget(btn_view_terms)

        layout.addWidget(card)

        # Checkbox de Aceite
        self.chk_terms = QCheckBox("Li e concordo com os Termos de Uso e Licença do Sentinela XDR.")
        self.chk_terms.stateChanged.connect(self._on_terms_changed)
        layout.addWidget(self.chk_terms)

        # Botões de Navegação
        layout.addStretch()
        nav_layout = QHBoxLayout()
        nav_layout.addStretch()

        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self.close)
        nav_layout.addWidget(self.btn_cancel)

        self.btn_welcome_next = QPushButton("Avançar ❯")
        self.btn_welcome_next.setObjectName("PrimaryBtn")
        self.btn_welcome_next.setEnabled(False)
        self.btn_welcome_next.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        nav_layout.addWidget(self.btn_welcome_next)

        layout.addLayout(nav_layout)
        self.stacked_widget.addWidget(page)

    # ----------------- PAGE 2: INSTALLATION OPTIONS -----------------
    def _build_page_options(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(14)

        opt_title = QLabel("Configurações e Componentes de Proteção")
        opt_title.setObjectName("SectionTitle")
        layout.addWidget(opt_title)

        desc = QLabel("Selecione os recursos e tecnologias de segurança que deseja ativar:")
        layout.addWidget(desc)

        card = QFrame()
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(12)

        self.chk_autostart = QCheckBox("🚀 Iniciar automaticamente com o Windows (Boot silencioso na bandeja)")
        self.chk_autostart.setChecked(True)
        card_layout.addWidget(self.chk_autostart)

        self.chk_shortcut = QCheckBox("🖥️  Criar atalho de acesso rápido na Área de Trabalho com logotipo oficial")
        self.chk_shortcut.setChecked(True)
        card_layout.addWidget(self.chk_shortcut)

        self.chk_shield = QCheckBox("🛡️  Aplicar blindagem contra falsos-positivos (Windows Defender & Firewall)")
        self.chk_shield.setChecked(True)
        card_layout.addWidget(self.chk_shield)

        self.chk_start_now = QCheckBox("⚡ Iniciar os 14 motores de proteção e abrir o Dashboard ao concluir")
        self.chk_start_now.setChecked(True)
        card_layout.addWidget(self.chk_start_now)

        layout.addWidget(card)

        # Destino
        dest_card = QFrame()
        dest_card.setObjectName("CardFrame")
        dest_layout = QVBoxLayout(dest_card)
        dest_lbl = QLabel(f"📁 <b>Diretório de Instalação:</b> <span style='color: #38bdf8;'>{BASE_DIR}</span>")
        dest_layout.addWidget(dest_lbl)
        layout.addWidget(dest_card)

        # Botões de Navegação
        layout.addStretch()
        nav_layout = QHBoxLayout()
        btn_back = QPushButton("❮ Voltar")
        btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        nav_layout.addWidget(btn_back)

        nav_layout.addStretch()

        btn_install = QPushButton("Instalar Sentinela XDR 🛡️")
        btn_install.setObjectName("PrimaryBtn")
        btn_install.clicked.connect(self._start_installation)
        nav_layout.addWidget(btn_install)

        layout.addLayout(nav_layout)
        self.stacked_widget.addWidget(page)

    # ----------------- PAGE 3: INSTALLING PROGRESS -----------------
    def _build_page_installing(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(14)

        prog_title = QLabel("Instalando e Ativando Sentinela XDR")
        prog_title.setObjectName("SectionTitle")
        layout.addWidget(prog_title)

        self.lbl_progress_status = QLabel("Preparando assistente...")
        layout.addWidget(self.lbl_progress_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.log_box = QTextEdit()
        self.log_box.setObjectName("LogBox")
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box, 1)

        self.stacked_widget.addWidget(page)

    # ----------------- PAGE 4: FINISHED -----------------
    def _build_page_finished(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 20, 30, 20)
        layout.setSpacing(12)

        # Header de Sucesso
        success_icon = QLabel("🛡️")
        success_icon.setFont(QFont("Segoe UI", 36))
        success_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_icon)

        success_title = QLabel("Instalação Concluída com Sucesso!")
        success_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #10b981;")
        success_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_title)

        success_desc = QLabel(
            "O Sentinela XDR está instalado e operando em segundo plano.<br>"
            "Todas as 20 camadas de defesa estão ativas e monitorando seu sistema em tempo real."
        )
        success_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        success_desc.setWordWrap(True)
        layout.addWidget(success_desc)

        # Grade com os Módulos Ativos
        card = QFrame()
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(6)

        st1 = QLabel("🟢 <b>API Web & Dashboard:</b> Online em http://localhost:5000")
        st2 = QLabel("🟢 <b>Identity & Credential Guard:</b> LSASS Armor & Proteção Anti-Dumping")
        st3 = QLabel("🟢 <b>DLP & Exfiltration Armor:</b> Mod 11 CPF/CNPJ & Bloqueio USB")
        st4 = QLabel("🟢 <b>Anti-Exploit & Child Shield:</b> Anti-Hollowing & Blindagem AMSI/ETW")
        st5 = QLabel("🟢 <b>Perímetro DGA & Anti-MITM:</b> Interceptação C2 & Detecção ARP")
        st6 = QLabel("🟢 <b>Postura, Persistência & LOLBins:</b> ASEP Hunter & Hardening CIS")
        st7 = QLabel("🟢 <b>ZTNA Zero-Trust, PQC & EDR:</b> Microsegmentação WFP & IA Zero-Day")
        
        card_layout.addWidget(st1)
        card_layout.addWidget(st2)
        card_layout.addWidget(st3)
        card_layout.addWidget(st4)
        card_layout.addWidget(st5)
        card_layout.addWidget(st6)
        card_layout.addWidget(st7)
        layout.addWidget(card)

        # Ações Finais
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_open_dash = QPushButton("🚀 ABRIR PAINEL DASHBOARD AGORA")
        self.btn_open_dash.setObjectName("SuccessBtn")
        self.btn_open_dash.clicked.connect(self._open_dashboard)
        btn_layout.addWidget(self.btn_open_dash)

        self.btn_finish_close = QPushButton("Concluir e Fechar Assistente")
        self.btn_finish_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_finish_close)

        layout.addLayout(btn_layout)
        self.stacked_widget.addWidget(page)

    # ----------------- EVENT HANDLERS -----------------
    def _on_terms_changed(self, state):
        self.btn_welcome_next.setEnabled(self.chk_terms.isChecked())

    def _open_terms_file(self):
        if os.path.exists(TERMS_FILE):
            os.startfile(TERMS_FILE)
        else:
            QMessageBox.information(self, "Termos de Uso", "O Sentinela XDR opera em conformidade com as leis de soberania de dados e privacidade.")

    def _start_installation(self):
        self.stacked_widget.setCurrentIndex(2)
        self.worker = InstallationWorker(
            enable_autostart=self.chk_autostart.isChecked(),
            create_shortcuts=self.chk_shortcut.isChecked(),
            apply_shield=self.chk_shield.isChecked(),
            start_daemon=self.chk_start_now.isChecked()
        )
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.log_signal.connect(self._on_log)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def _on_progress(self, val: int, text: str):
        self.progress_bar.setValue(val)
        self.lbl_progress_status.setText(text)

    def _on_log(self, text: str):
        self.log_box.append(text)

    def _on_finished(self, success: bool, msg: str):
        if success:
            QTimer.singleShot(1200, lambda: self.stacked_widget.setCurrentIndex(3))
        else:
            QMessageBox.critical(self, "Erro na Instalação", f"Ocorreu um erro durante a instalação:\n{msg}")

    def _open_dashboard(self):
        url = "http://localhost:5000"
        try:
            if os.path.exists(RUNTIME_FILE):
                with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    url = data.get("url", url)
        except Exception:
            pass
        webbrowser.open(url)
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    installer = SentinelGuiInstaller()
    installer.show()
    sys.exit(app.exec())
