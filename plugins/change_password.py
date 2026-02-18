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
        self._active_user: Optional[str] = None
        self._build_ui()
        self._reload_users()

    def _build_ui(self) -> None:
        v = QVBoxLayout(self)

        title = QLabel(self.tr("Change password"))
        f = QFont()
        f.setBold(True)
        title.setFont(f)
        v.addWidget(title)

        v.addWidget(QLabel(self.tr("Users:")))
        self.list_users = QListWidget()
        self.list_users.setSelectionMode(QListWidget.MultiSelection)
        v.addWidget(self.list_users, 1)

        self.lbl_active = QLabel(self.tr("Active user: —"))
        fb = QFont()
        fb.setBold(True)
        self.lbl_active.setFont(fb)
        v.addWidget(self.lbl_active)

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
        self.list_users.itemSelectionChanged.connect(self._on_users_selection_changed)

    def _uid_min(self) -> int:
        try:
            with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if s.upper().startswith("UID_MIN"):
                        parts = s.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            return int(parts[1])
        except Exception:
            pass
        return 1000

    def _list_users_all(self) -> List[Tuple[str, int]]:
        users: List[Tuple[str, int]] = []
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split(":")
                    if len(parts) < 7:
                        continue
                    name = parts[0]
                    try:
                        uid = int(parts[2])
                    except Exception:
                        continue
                    users.append((name, uid))
        except Exception:
            pass
        return users

    def _reload_users(self):
        self.list_users.clear()
        uid_min = self._uid_min()

        for name, uid in sorted(self._list_users_all(), key=lambda t: (t[1], t[0])):
            if uid < uid_min:
                continue
            it = QListWidgetItem(f"{name} (uid {uid})")
            it.setData(Qt.UserRole, name)
            self.list_users.addItem(it)

        if self.list_users.count() > 0:
            self._active_user = str(self.list_users.item(0).data(Qt.UserRole))
            self.lbl_active.setText(self.tr("Active user: ") + self._active_user)
            self.list_users.item(0).setSelected(True)
        else:
            self._active_user = None
            self.lbl_active.setText(self.tr("Active user: —"))

    def _on_users_selection_changed(self):
        items = self.list_users.selectedItems()
        if not items:
            self._active_user = None
            self.lbl_active.setText(self.tr("Active user: —"))
            return
        last = items[-1]
        self._active_user = str(last.data(Qt.UserRole))
        self.lbl_active.setText(self.tr("Active user: ") + self._active_user)

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
