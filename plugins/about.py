#!/usr/bin/python3

from PyQt5.QtWidgets import (QApplication, QWidget,
                             QVBoxLayout, QLabel,
                             QGridLayout, QScrollArea,
                             QSpacerItem, QSizePolicy,
                             QStackedWidget,
                             QMenu, QAction)
from PyQt5.QtGui import QStandardItem, QStandardItemModel, QIcon
from PyQt5.QtCore import Qt

import os

import plugins
import my_utils


class AboutWidget(QWidget):
    def __init__(self, palette):
        super().__init__()
        self.palette = palette
        self.initUI()

    def translate_os_name(self, name:str) -> str:
        dictionary = {
            'ALT' : self.tr("ALT"),
            'ALT Education' : self.tr("ALT Education"),
            'ALT Workstation' : self.tr("ALT Workstation"),
            'ALT Workstation K' : self.tr("ALT Workstation K"),
            'ALT Regular' : self.tr("ALT Regular"),
            'Sisyphus' : self.tr("Sisyphus"),
            'ALT Server' : self.tr("ALT Server"),
            'ALT Virtualization Server' : self.tr("ALT Virtualization Server"),
            'ALT Starterkit' : self.tr("ALT Starterkit"),
        }

        if name in dictionary:
            name = dictionary[name]

        return name

    def translate_os_url(self, name:str) -> str:
        dictionary = {
            'ALT' : "https://altlinux.org",
            'ALT Education' : "https://www.basealt.ru/alt-education",
            'ALT Workstation' : "https://www.basealt.ru/alt-workstation",
            'ALT Workstation K' : "https://www.basealt.ru/alt-workstation-k",
            'ALT Regular' : "https://www.altlinux.org/Regular",
            'Sisyphus' : "https://altlinux.org",
            'ALT Server' : "https://www.basealt.ru/alt-server",
            'ALT Virtualization Server' : "https://www.basealt.ru/alt-virtualization",
            'ALT Starterkit' : "https://www.altlinux.org/Starterkits",
		}

        if name in dictionary:
            name = dictionary[name]

        return name


    def initUI(self):
        self.setAutoFillBackground(True)
        self.setPalette(self.palette)

        # Основной лэйаут для окна
        main_layout = QVBoxLayout()

        # Создание QScrollArea
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)  # Ресайз области прокрутки
        scroll_area.setFrameShape(QScrollArea.NoFrame)

        # Создание контейнера для виджетов внутри QScrollArea
        container = QWidget()
        # font = QFont('Sans', 11)
        # container.setFont(font)
        container_layout = QVBoxLayout(container)  # Внутренний лэйаут для контейнера
        container_layout.setSpacing(10)

        # Добавляем Spacer сверху (с помощью QSizePolicy.Expanding)
        top_spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        container_layout.addItem(top_spacer)

        # Создаем метки
        os_info = my_utils.parse_os_release()
        s = self.translate_os_name(os_info["MY_NAME"])
        os_name = "{}{}".format(s, os_info["MY_NAME_VERSION"])
        if os_info["MY_NAME_NICK"] != '':
            os_name = os_name + '\n' + os_info["MY_NAME_NICK"]

        # Product logo
        label_logo = QLabel(self)
        label_logo.setAlignment(Qt.AlignCenter)
        if 'LOGO' in os_info and os_info['LOGO'] != '':
            label_logo.setPixmap(QIcon.fromTheme(os_info['LOGO']).pixmap(128))

        label1 = QLabel(os_name)
        label1.setAlignment(Qt.AlignCenter)
        label1.setWordWrap(True)
        label_font = container.font()
        label_font.setPointSize(int(label_font.pointSize() * 1.75))
        label1.setFont(label_font)
        self.text = []
        self.text.append(os_name)

        url = self.translate_os_url(os_info["MY_NAME"])
        label2 = QLabel('')
        label2.setAlignment(Qt.AlignCenter)
        label2.setOpenExternalLinks(True)
        if url != '':
            label2.setText('<a href="%s">%s</a>' % (url, url))
            self.text.append(url)

        # Добавляем метки в контейнер
        container_layout.addWidget(label_logo)
        container_layout.addWidget(label1)
        container_layout.addWidget(label2)
        container_layout.addWidget(QLabel())

        # Сетка для расположения элементов
        grid_layout = QGridLayout()


        # Создаем элементы для сетки

        # DE
        de, version = my_utils.get_de_info_from_inxi()
        label_de_name = QLabel(self.tr("DE:"))
        label_de_value = QLabel(de if version in (None, "", "None") else f"{de} {version}")
        self.text.append('{} {}'.format(label_de_name.text(), label_de_value.text()))
        label_de_name.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid_layout.addWidget(label_de_name, 0, 0)
        grid_layout.addWidget(label_de_value, 0, 1)


        # kernel
        uname = os.uname()
        label_kernel_name = QLabel(self.tr("Kernel:"))
        label_kernel_value = QLabel(uname.release)
        self.text.append('{} {}'.format(label_kernel_name.text(), label_kernel_value.text()))
        label_kernel_name.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid_layout.addWidget(label_kernel_name, 1, 0)
        grid_layout.addWidget(label_kernel_value, 1, 1)


        # Display server
        label_ds_name = QLabel(self.tr("Display server:"))
        label_ds_value = QLabel(my_utils.get_display_server())
        self.text.append('{} {}'.format(label_ds_name.text(), label_ds_value.text()))
        label_ds_name.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid_layout.addWidget(label_ds_name, 2, 0)
        grid_layout.addWidget(label_ds_value, 2, 1)


        # cpu
        line: int = 2
        cpus = my_utils.get_cpu_info_from_proc()
        title = self.tr("Processor:")
        is_one_cpu: bool = len(cpus) == 1
        for cpu in cpus:
            line = line + 1

            if is_one_cpu:
                name = title
            else:
                name = f'{title[:-1]} #{line - 2}:'

            cpu_name, num_cores, num_threads = cpu

            if num_cores < num_threads:
                value = '{}({}) x {}'.format(num_cores, num_threads, cpu_name)
            else:
                value = '{} x {}'.format(num_cores, cpu_name)

            label_cpu_name = QLabel(name)
            label_cpu_value = QLabel(value)
            self.text.append('{} {}'.format(name, value))

            label_cpu_name.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid_layout.addWidget(label_cpu_name, line, 0)
            grid_layout.addWidget(label_cpu_value, line, 1)


        # memory
        line = line + 1
        total_memory, used_memory, free_memory = my_utils.get_memory_info_from_free()
        label_ram_name = QLabel(self.tr("Memory:"))
        gb = self.tr("GB")
        s = f"{total_memory / (1024 ** 3):.2f} {gb}"
        label_ram_value = QLabel(s)
        self.text.append('{} {}\n'.format(label_ram_name.text(), label_ram_value.text()))
        label_ram_name.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        grid_layout.addWidget(label_ram_name, line, 0)
        grid_layout.addWidget(label_ram_value, line, 1)


        # Добавляем сетку в контейнер
        container_layout.addLayout(grid_layout)

        # Добавляем Spacer снизу
        bottom_spacer = QSpacerItem(5, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
        container_layout.addItem(bottom_spacer)

        # Добавляем контейнер в scroll_area
        scroll_area.setWidget(container)

        # Центрируем QScrollArea внутри основного лэйаута
        main_layout.addWidget(scroll_area)

        # Устанавливаем основной лэйаут для окна
        self.setLayout(main_layout)

        # Устанавливаем поведение контекстного меню
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)


    def show_context_menu(self, pos):
        context_menu = QMenu(self)

        # Добавляем пункт "Скопировать текст"
        copy_action = QAction(self.tr("Copy text"), self)
        context_menu.addAction(copy_action)

        # Связываем действие с функцией
        copy_action.triggered.connect(self.copy_text)

        # Показываем контекстное меню
        context_menu.exec_(self.mapToGlobal(pos))


    def copy_text(self):
        # Собираем весь текст с QLabel
        text_to_copy = "\n".join(self.text)

        # Копируем в буфер обмена
        clipboard = QApplication.clipboard()
        clipboard.setText(text_to_copy)
        # print("Текст скопирован в буфер обмена.")


class PluginAbout(plugins.Base):
    def __init__(self, plist: QStandardItemModel=None, pane: QStackedWidget = None):
        super().__init__("about", 1, plist, pane)

        if self.plist != None and self.pane != None:
            self.node = QStandardItem(self.tr("About system"))
            self.node.setData(self.name)
            self.plist.appendRow([self.node])
            self.pane.addWidget(QWidget())


    def _do_start(self, idx: int):
        main_palette = self.pane.window().palette()
        main_widget = AboutWidget(main_palette)
        self.pane.insertWidget(idx, main_widget)
