#!/usr/bin/python3

import os
import re
import shutil
import subprocess
import secrets
import string
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QCheckBox, QSpinBox, QLabel,
    QHBoxLayout, QPushButton, QMessageBox, QStackedWidget, QListWidget,
    QListWidgetItem, QGroupBox, QLineEdit, QComboBox, QApplication
)

import plugins
from my_utils import check_package_installed


class ChangePassword(QWidget):
    def __init__(self, palette=None):
        super().__init__()
        if palette:
            self.setPalette(palette)
        self._build_ui()

    def _build_ui(self) -> None:
        v = QVBoxLayout(self)

        title = QLabel(self.tr("Change password"))
        f = QFont()
        f.setBold(True)
        title.setFont(f)
        v.addWidget(title)

        row = QHBoxLayout()

        self.ed_pass = QLineEdit()
        self.ed_pass.setReadOnly(True)
        self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_pass.setPlaceholderText(self.tr("Click “Generate” to create a password"))
        row.addWidget(self.ed_pass, 1)

        self.btn_copy = QPushButton(self.tr("Copy"))
        self.btn_show = QPushButton(self.tr("Show"))
        self.btn_gen = QPushButton(self.tr("Generate"))

        row.addWidget(self.btn_copy)
        row.addWidget(self.btn_show)
        row.addWidget(self.btn_gen)

        v.addLayout(row)
        v.addStretch(1)

        self.btn_gen.clicked.connect(self._on_generate)
        self.btn_copy.clicked.connect(self._on_copy)
        self.btn_show.clicked.connect(self._on_toggle_show)

    def _random_password_12(self) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(12))

    def _on_generate(self) -> None:
        self.ed_pass.setText(self._random_password_12())
        self.ed_pass.selectAll()

    def _on_copy(self) -> None:
        pwd = self.ed_pass.text()
        if not pwd:
            return
        try:
            QApplication.clipboard().setText(pwd)
        except Exception:
            pass

    def _on_toggle_show(self) -> None:
        if self.ed_pass.echoMode() == QLineEdit.Password:
            self.ed_pass.setEchoMode(QLineEdit.Normal)
            self.btn_show.setText(self.tr("Hide"))
        else:
            self.ed_pass.setEchoMode(QLineEdit.Password)
            self.btn_show.setText(self.tr("Show"))


class ChangePasswordPlugin(plugins.Base):
    def __init__(self, plist=None, pane: QStackedWidget = None):
        super().__init__("change_password", 30, plist, pane)
        if self.plist is not None and self.pane is not None:
            node = QStandardItem(self.tr("Change password"))
            node.setData(self.name)
            self.plist.appendRow([node])
            self.pane.addWidget(QWidget())

    def _do_start(self, idx: int):
        main_palette = self.pane.window().palette()
        self.pane.insertWidget(idx, ChangePassword(main_palette))
