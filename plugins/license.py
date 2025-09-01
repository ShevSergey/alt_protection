#!/usr/bin/python3

# Application for configure and maintain ALT operating system
# (c) 2024 Andrey Cherepanov <cas@altlinux.org>

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA  02111-1307, USA.

import plugins
from PyQt5.QtWidgets import QWidget, QTextBrowser, QStackedWidget
from PyQt5.QtGui import QStandardItem, QStandardItemModel, QFont, QTextDocument
from PyQt5.QtCore import QUrl
import locale, os


class PluginLicense(plugins.Base):
    def __init__(self, plist: QStandardItemModel=None, pane: QStackedWidget = None):
        super().__init__("license", 10, plist, pane)

        if self.plist != None and self.pane != None:
            self.node = QStandardItem(self.tr("License"))
            self.node.setData(self.name)
            self.plist.appendRow([self.node])
            self.pane.addWidget(QWidget())


    def _do_start(self, idx: int):
        self.license_info = QTextBrowser()
        self.license_info.setCurrentFont(QFont("monospace", 9))
        self._pane.insertWidget(idx, self.license_info)

        file_path = "/usr/share/alt-notes/license." + locale.getlocale()[0].split( '_' )[0] + ".html"

        if os.path.isfile(file_path):
            url = QUrl(file_path)
            self.license_info.setSource(url, QTextDocument.ResourceType.HtmlResource)
        else:
            file_path = "/usr/share/alt-notes/license.all.html"
            if os.path.isfile(file_path):
                url = QUrl(file_path)
                self.license_info.setSource(url, QTextDocument.ResourceType.HtmlResource)
            else:
                self.license_info.setHtml(f"File '{file_path}' not found.")
