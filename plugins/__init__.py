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

import os
import traceback
from abc import ABCMeta, abstractmethod
from importlib import util
from PyQt5.QtCore import QObject
from PyQt5.QtWidgets import QStackedWidget
from PyQt5.QtGui import QStandardItemModel


plugins_skip_list = []
plugins_skip_file = "/etc/altcenter/skip-plugins"

class MetaQObjectABC(ABCMeta, type(QObject)):
    ...

class Base(QObject, metaclass=MetaQObjectABC):
    """Base skel for plugin"""
    plugins = []

    def __init__(self, name: str, position: int, plist: QStandardItemModel=None, pane: QStackedWidget = None):
        super().__init__()
        self._name = name
        self._position = position
        self._plist = plist
        self._pane = pane
        self._started = False

    # For every class that inherits from the current
    # the class name will be added to plugins
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Base.plugins.append(cls)

    @property
    def name(self) -> str:
        return self._name

    @property
    def position(self) -> int:
        return self._position

    @property
    def plist(self):
        return self._plist

    @property
    def pane(self):
        return self._pane

    @property
    def started(self) -> bool:
        return self._started

    @started.setter
    def started(self, value: bool):
        self._started = value

    @abstractmethod
    def _do_start(self, idx: int):
        """
        Инициализация плагина и формирование его виджета

        Каждый плагин должен реализовать эту функцию, но вызывать её непосредственно нельзя.
        Для этого есть функция run.
        """
        ...

    def run(self, idx: int):
        """
        Вызов этой функции приведет к вызову переопределённой функции _do_start и установке флага started
        """
        self._do_start(idx)
        self.started = True


# Load one module
def load_module(path):
    name = os.path.split(path)[-1]
    spec = util.spec_from_file_location(name, path)
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Read plugins skip list
try:
    with open(plugins_skip_file, "r") as file:
        plugins_skip_list = list(filter(lambda x: x and not x.startswith("#"), [line.strip() for line in file]))
except:
    pass

plugin_path = os.path.dirname(os.path.abspath(__file__))
for fname in os.listdir(plugin_path):
    if not fname.startswith('.') and \
       not fname.startswith('__') and fname.endswith('.py') and not fname[:-3] in plugins_skip_list:
        try:
            load_module(os.path.join(plugin_path, fname))
        except Exception:
            traceback.print_exc()

Base.plugins.sort(key=lambda x: x().position)
