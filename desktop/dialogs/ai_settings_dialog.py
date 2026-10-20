"""AI Provider Settings and API Key Management Dialog for CyberSecuritySuite.

Allows secure entry, testing, masking, and persistent storage of Google Gemini,
OpenAI, and Local Ollama AI settings using the system credential store or user vault.
"""

from __future__ import annotations

import webbrowser
from typing import Optional

from PySide6.QtCore import Qt, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.ai_copilot import AICopilotEngine, AIProvider
from core.credential_manager import CredentialManager


class AISettingsDialog(QDialog):
    """Dialog for configuring AI providers, models, and managing secure API keys."""

    def __init__(self, engine: Optional[AICopilotEngine] = None, parent=None):
        super().__init__(parent)
        self.engine = engine or AICopilotEngine()
        self.setWindowTitle("⚙️ AI Provider Settings & API Key Management")
        self.setMinimumWidth(680)
        self.setMinimumHeight(520)

        self._init_ui()
        self._load_current_values()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # Header Title
        title = QLabel("🤖 AI Provider Settings & API Key Management")
        title.setStyleSheet("font-size: 15px; font-weight: bold; color: #38bdf8;")
        main_layout.addWidget(title)

        desc = QLabel(
            "Configure cloud intelligence (Google Gemini, OpenAI) or local LLMs (Ollama). "
            "API keys are stored securely using your operating system credential store or machine-bound vault (0600 permissions). "
            "Keys are never logged, committed to git, or sent in terminal commands."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #94a3b8; font-size: 11px;")
        main_layout.addWidget(desc)

        # Storage Backend Indicator Badge
        backend_frame = QFrame()
        backend_frame.setStyleSheet("background-color: #171d2b; border: 1px solid #242d40; border-radius: 4px; padding: 6px;")
        bf_layout = QHBoxLayout(backend_frame)
        bf_layout.setContentsMargins(8, 4, 8, 4)

        lbl_storage_icon = QLabel("🔒")
        bf_layout.addWidget(lbl_storage_icon)

        backend_desc = CredentialManager.get_backend_description()
        self.lbl_storage_status = QLabel(f"Storage Backend: {backend_desc}")
        self.lbl_storage_status.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: 500;")
        bf_layout.addWidget(self.lbl_storage_status)
        bf_layout.addStretch()

        main_layout.addWidget(backend_frame)

        # Provider Tabs
        self.tabs = QTabWidget()

        # -------------------------------------------------------------
        # Tab 1: Google Gemini API
        # -------------------------------------------------------------
        tab_gemini = QWidget()
        g_layout = QVBoxLayout(tab_gemini)
        g_layout.setSpacing(10)

        lbl_g_info = QLabel("Use Google's generative models for deep scan diagnosis and exploit triage.")
        lbl_g_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        g_layout.addWidget(lbl_g_info)

        # Model Selector
        m_row = QHBoxLayout()
        lbl_m = QLabel("Gemini Model:")
        lbl_m.setFixedWidth(110)
        m_row.addWidget(lbl_m)

        self.combo_gemini_model = QComboBox()
        self.combo_gemini_model.setEditable(True)
        self.combo_gemini_model.addItems(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"])
        m_row.addWidget(self.combo_gemini_model, 1)
        g_layout.addLayout(m_row)

        # API Key Input
        k_row = QHBoxLayout()
        lbl_k = QLabel("Gemini API Key:")
        lbl_k.setFixedWidth(110)
        k_row.addWidget(lbl_k)

        self.input_gemini_key = QLineEdit()
        self.input_gemini_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_gemini_key.setPlaceholderText("Enter AIza... key here")
        k_row.addWidget(self.input_gemini_key, 1)

        self.btn_toggle_gemini = QPushButton("👁️ Show")
        self.btn_toggle_gemini.setFixedWidth(75)
        self.btn_toggle_gemini.clicked.connect(lambda: self._toggle_echo(self.input_gemini_key, self.btn_toggle_gemini))
        k_row.addWidget(self.btn_toggle_gemini)
        g_layout.addLayout(k_row)

        # Key Status
        self.lbl_gemini_saved = QLabel("Saved Key: Not Configured")
        self.lbl_gemini_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        g_layout.addWidget(self.lbl_gemini_saved)

        # Buttons
        gb_row = QHBoxLayout()
        self.btn_test_gemini = QPushButton("🔌 Test Connection")
        self.btn_test_gemini.clicked.connect(self._test_gemini)
        gb_row.addWidget(self.btn_test_gemini)

        self.btn_save_gemini = QPushButton("💾 Save Gemini Settings")
        self.btn_save_gemini.setProperty("class", "action-primary")
        self.btn_save_gemini.clicked.connect(self._save_gemini)
        gb_row.addWidget(self.btn_save_gemini)

        self.btn_clear_gemini = QPushButton("🗑️ Clear Key")
        self.btn_clear_gemini.clicked.connect(self._clear_gemini)
        gb_row.addWidget(self.btn_clear_gemini)

        btn_doc_gemini = QPushButton("🔗 Get Gemini API Key")
        btn_doc_gemini.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://aistudio.google.com/app/apikey")))
        gb_row.addWidget(btn_doc_gemini)
        g_layout.addLayout(gb_row)

        self.lbl_gemini_status = QLabel("")
        self.lbl_gemini_status.setWordWrap(True)
        g_layout.addWidget(self.lbl_gemini_status)
        g_layout.addStretch()

        self.tabs.addTab(tab_gemini, "Google Gemini API")

        # -------------------------------------------------------------
        # Tab 2: OpenAI API
        # -------------------------------------------------------------
        tab_openai = QWidget()
        o_layout = QVBoxLayout(tab_openai)
        o_layout.setSpacing(10)

        lbl_o_info = QLabel("Connect to OpenAI GPT-4o models for terminal error analysis and command generation.")
        lbl_o_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        o_layout.addWidget(lbl_o_info)

        # Model Selector
        om_row = QHBoxLayout()
        lbl_om = QLabel("OpenAI Model:")
        lbl_om.setFixedWidth(110)
        om_row.addWidget(lbl_om)

        self.combo_openai_model = QComboBox()
        self.combo_openai_model.setEditable(True)
        self.combo_openai_model.addItems(["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"])
        om_row.addWidget(self.combo_openai_model, 1)
        o_layout.addLayout(om_row)

        # API Key Input
        ok_row = QHBoxLayout()
        lbl_ok = QLabel("OpenAI API Key:")
        lbl_ok.setFixedWidth(110)
        ok_row.addWidget(lbl_ok)

        self.input_openai_key = QLineEdit()
        self.input_openai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_openai_key.setPlaceholderText("Enter sk-... key here")
        ok_row.addWidget(self.input_openai_key, 1)

        self.btn_toggle_openai = QPushButton("👁️ Show")
        self.btn_toggle_openai.setFixedWidth(75)
        self.btn_toggle_openai.clicked.connect(lambda: self._toggle_echo(self.input_openai_key, self.btn_toggle_openai))
        ok_row.addWidget(self.btn_toggle_openai)
        o_layout.addLayout(ok_row)

        # Key Status
        self.lbl_openai_saved = QLabel("Saved Key: Not Configured")
        self.lbl_openai_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        o_layout.addWidget(self.lbl_openai_saved)

        # Buttons
        ob_row = QHBoxLayout()
        self.btn_test_openai = QPushButton("🔌 Test Connection")
        self.btn_test_openai.clicked.connect(self._test_openai)
        ob_row.addWidget(self.btn_test_openai)

        self.btn_save_openai = QPushButton("💾 Save OpenAI Settings")
        self.btn_save_openai.setProperty("class", "action-primary")
        self.btn_save_openai.clicked.connect(self._save_openai)
        ob_row.addWidget(self.btn_save_openai)

        self.btn_clear_openai = QPushButton("🗑️ Clear Key")
        self.btn_clear_openai.clicked.connect(self._clear_openai)
        ob_row.addWidget(self.btn_clear_openai)

        btn_doc_openai = QPushButton("🔗 Get OpenAI API Key")
        btn_doc_openai.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://platform.openai.com/api-keys")))
        ob_row.addWidget(btn_doc_openai)
        o_layout.addLayout(ob_row)

        self.lbl_openai_status = QLabel("")
        self.lbl_openai_status.setWordWrap(True)
        o_layout.addWidget(self.lbl_openai_status)
        o_layout.addStretch()

        self.tabs.addTab(tab_openai, "OpenAI API")

        # -------------------------------------------------------------
        # Tab 3: Local Ollama (Offline)
        # -------------------------------------------------------------
        tab_ollama = QWidget()
        ol_layout = QVBoxLayout(tab_ollama)
        ol_layout.setSpacing(10)

        lbl_ol_info = QLabel("Run local open-weight models (Llama 3, DeepSeek, Mistral) on your machine with zero data leaving your computer.")
        lbl_ol_info.setWordWrap(True)
        lbl_ol_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        ol_layout.addWidget(lbl_ol_info)

        # Server URL
        u_row = QHBoxLayout()
        lbl_u = QLabel("Server URL:")
        lbl_u.setFixedWidth(110)
        u_row.addWidget(lbl_u)

        self.input_ollama_url = QLineEdit()
        self.input_ollama_url.setText("http://127.0.0.1:11434")
        u_row.addWidget(self.input_ollama_url, 1)
        ol_layout.addLayout(u_row)

        # Model Name
        olm_row = QHBoxLayout()
        lbl_olm = QLabel("Ollama Model:")
        lbl_olm.setFixedWidth(110)
        olm_row.addWidget(lbl_olm)

        self.combo_ollama_model = QComboBox()
        self.combo_ollama_model.setEditable(True)
        self.combo_ollama_model.addItems(["llama3", "deepseek-r1", "mistral", "codellama"])
        olm_row.addWidget(self.combo_ollama_model, 1)
        ol_layout.addLayout(olm_row)

        # Buttons
        olb_row = QHBoxLayout()
        self.btn_test_ollama = QPushButton("🔌 Test Ollama Connection")
        self.btn_test_ollama.clicked.connect(self._test_ollama)
        olb_row.addWidget(self.btn_test_ollama)

        self.btn_save_ollama = QPushButton("💾 Save Ollama Settings")
        self.btn_save_ollama.setProperty("class", "action-primary")
        self.btn_save_ollama.clicked.connect(self._save_ollama)
        olb_row.addWidget(self.btn_save_ollama)

        btn_doc_ollama = QPushButton("🔗 Ollama Docs")
        btn_doc_ollama.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://ollama.com")))
        olb_row.addWidget(btn_doc_ollama)
        ol_layout.addLayout(olb_row)

        self.lbl_ollama_status = QLabel("")
        self.lbl_ollama_status.setWordWrap(True)
        ol_layout.addWidget(self.lbl_ollama_status)
        ol_layout.addStretch()

        self.tabs.addTab(tab_ollama, "Local Ollama")

        # -------------------------------------------------------------
        # Tab 4: Built-in Offline Security Engine
        # -------------------------------------------------------------
        tab_builtin = QWidget()
        b_layout = QVBoxLayout(tab_builtin)
        b_layout.setSpacing(10)

        lbl_b_title = QLabel("🛡️ Built-in Cybersecurity Heuristic Engine")
        lbl_b_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #38bdf8;")
        b_layout.addWidget(lbl_b_title)

        lbl_b_desc = QLabel(
            "The Built-in Security Engine operates 100% offline without sending any bytes over the network. "
            "It incorporates expert penetration testing heuristic rules for 25+ security tools (Nmap, SQLMap, Gobuster, "
            "WAFW00F, Bandit, Volatility, etc.), exit code analysis, permission remediation, and automatic finding extraction."
        )
        lbl_b_desc.setWordWrap(True)
        lbl_b_desc.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        b_layout.addWidget(lbl_b_desc)

        btn_set_offline = QPushButton("✓ Set Built-in Offline Engine as Active")
        btn_set_offline.setProperty("class", "action-primary")
        btn_set_offline.clicked.connect(self._set_offline_active)
        b_layout.addWidget(btn_set_offline)
        b_layout.addStretch()

        self.tabs.addTab(tab_builtin, "Built-in Offline Engine")

        main_layout.addWidget(self.tabs)

        # Bottom Close Row
        bot_row = QHBoxLayout()
        bot_row.addStretch()
        btn_close = QPushButton("Done")
        btn_close.clicked.connect(self.accept)
        bot_row.addWidget(btn_close)
        main_layout.addLayout(bot_row)

    def _toggle_echo(self, line_edit: QLineEdit, toggle_btn: QPushButton):
        if line_edit.echoMode() == QLineEdit.EchoMode.Password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            toggle_btn.setText("🔒 Hide")
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            toggle_btn.setText("👁️ Show")

    def _load_current_values(self):
        # Gemini
        self.combo_gemini_model.setCurrentText(self.engine.gemini_model)
        gemini_key = self.engine.get_api_key(AIProvider.GEMINI_API)
        if gemini_key:
            masked = CredentialManager.mask_key(gemini_key)
            self.lbl_gemini_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_gemini_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_gemini_saved.setText("Saved Key: Not Configured")
            self.lbl_gemini_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # OpenAI
        self.combo_openai_model.setCurrentText(self.engine.openai_model)
        openai_key = self.engine.get_api_key(AIProvider.OPENAI_API)
        if openai_key:
            masked = CredentialManager.mask_key(openai_key)
            self.lbl_openai_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_openai_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_openai_saved.setText("Saved Key: Not Configured")
            self.lbl_openai_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # Ollama
        self.input_ollama_url.setText(self.engine.ollama_url)
        self.combo_ollama_model.setCurrentText(self.engine.ollama_model)

    # -------------------------------------------------------------
    # Gemini Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_gemini(self):
        new_key = self.input_gemini_key.text().strip()
        model = self.combo_gemini_model.currentText().strip()
        self.engine.gemini_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.GEMINI_API, new_key)
            self.input_gemini_key.clear()
            self._load_current_values()
            self.lbl_gemini_status.setText("✓ Gemini API key and model saved successfully.")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_gemini_status.setText("✓ Gemini model preference updated.")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_gemini(self):
        self.lbl_gemini_status.setText("Connecting to Google Gemini API...")
        self.lbl_gemini_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_gemini_key.text().strip() or None
        model = self.combo_gemini_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.GEMINI_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_gemini_status.setText(f"✓ {msg}")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_gemini_status.setText(f"✗ {msg}")
            self.lbl_gemini_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_gemini(self):
        self.engine.clear_api_key(AIProvider.GEMINI_API)
        self.input_gemini_key.clear()
        self._load_current_values()
        self.lbl_gemini_status.setText("Gemini API key cleared.")
        self.lbl_gemini_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # OpenAI Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_openai(self):
        new_key = self.input_openai_key.text().strip()
        model = self.combo_openai_model.currentText().strip()
        self.engine.openai_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.OPENAI_API, new_key)
            self.input_openai_key.clear()
            self._load_current_values()
            self.lbl_openai_status.setText("✓ OpenAI API key and model saved successfully.")
            self.lbl_openai_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_openai_status.setText("✓ OpenAI model preference updated.")
            self.lbl_openai_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_openai(self):
        self.lbl_openai_status.setText("Connecting to OpenAI API...")
        self.lbl_openai_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_openai_key.text().strip() or None
        model = self.combo_openai_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.OPENAI_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_openai_status.setText(f"✓ {msg}")
            self.lbl_openai_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_openai_status.setText(f"✗ {msg}")
            self.lbl_openai_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_openai(self):
        self.engine.clear_api_key(AIProvider.OPENAI_API)
        self.input_openai_key.clear()
        self._load_current_values()
        self.lbl_openai_status.setText("OpenAI API key cleared.")
        self.lbl_openai_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # Ollama Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_ollama(self):
        self.engine.ollama_url = self.input_ollama_url.text().strip()
        self.engine.ollama_model = self.combo_ollama_model.currentText().strip()
        self.lbl_ollama_status.setText("✓ Ollama settings saved.")
        self.lbl_ollama_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_ollama(self):
        self.lbl_ollama_status.setText("Connecting to Ollama...")
        self.lbl_ollama_status.setStyleSheet("color: #38bdf8;")
        self.engine.ollama_url = self.input_ollama_url.text().strip()
        self.engine.ollama_model = self.combo_ollama_model.currentText().strip()

        ok, msg = self.engine.test_connection(provider=AIProvider.LOCAL_OLLAMA)
        if ok:
            self.lbl_ollama_status.setText(f"✓ {msg}")
            self.lbl_ollama_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_ollama_status.setText(f"✗ {msg}")
            self.lbl_ollama_status.setStyleSheet("color: #f87171; font-weight: bold;")

    # -------------------------------------------------------------
    # Built-in Offline Action
    # -------------------------------------------------------------
    @Slot()
    def _set_offline_active(self):
        self.engine.provider = AIProvider.BUILTIN_OFFLINE
        QMessageBox.information(
            self,
            "Built-in Engine Active",
            "The Built-in Cybersecurity Heuristic Engine is now selected as your active AI engine.\n\n"
            "All output diagnosis and command generation will operate 100% offline without external network transmission.",
        )
