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


class ChangePasswordPlugin(plugins.Base):
    def __init__(self, plist=None, pane: QStackedWidget = None):
        super().__init__("change_password", 21, plist, pane)
        if self.plist is not None and self.pane is not None:
            node = QStandardItem(self.tr("Change password"))
            node.setData(self.name)
            self.plist.appendRow([node])
            self.pane.addWidget(QWidget())

    def _do_start(self, idx: int):
        main_palette = self.pane.window().palette()
        self.pane.insertWidget(idx, ChangePassword(main_palette))
