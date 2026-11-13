from concurrent.futures import ThreadPoolExecutor
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sqlite3
import sys
from time import time
from ipaddress import IPv4Address
from math import nan

from PySide6 import QtCore as Q, QtGui as G, QtWidgets as W
import pyqtgraph as pg

from .advisor import overlap, possible_channels, recommend
from .diagnostics import Ping, assessment, wifi_route
from .history import History, export_csv, timestamp
from .native import NativeWifi
from .radio import BANDS, UNKNOWN, channel_frequency, load_vendors


STYLE = """
QWidget { background:#101722; color:#e7effa; font:14px 'Segoe UI'; }
QLabel#title { font-size:26px; font-weight:700; }
QLabel#status { color:#9cb4ce; }
QLineEdit,QComboBox,QSpinBox,QPushButton { padding:6px 10px; border:1px solid #31465c;
    border-radius:5px; background:#1a2939; }
QPushButton:hover { background:#263c52; }
QTableWidget { background:#14202e; alternate-background-color:#182637; gridline-color:#25384a;
    selection-background-color:#28577b; }
QHeaderView::section { background:#213448; padding:7px; border:0; }
QTabBar::tab { padding:10px 18px; background:#182637; color:#b9cde1; }
QTabBar::tab:selected { color:#effaff; background:#26415a; border-bottom:2px solid #59d6cb; }
QToolTip { background:#1a2939; color:white; border:1px solid #31465c; }
"""


def label(text=""):
    item = W.QLabel(text)
    item.setTextFormat(Q.Qt.TextFormat.PlainText)
    item.setWordWrap(True)
    return item


def combo(values=()):
    item = W.QComboBox()
    item.addItems(values)
    return item


def button(text, action):
    item = W.QPushButton(text)
    item.clicked.connect(action)
    return item


def line(layout, *widgets):
    row = W.QHBoxLayout()
    for widget in widgets:
        row.addWidget(widget)
    layout.addLayout(row)


def table(headers):
    item = W.QTableWidget(0, len(headers))
    item.setHorizontalHeaderLabels(headers)
    item.setEditTriggers(W.QAbstractItemView.EditTrigger.NoEditTriggers)
    item.setSelectionBehavior(W.QAbstractItemView.SelectionBehavior.SelectRows)
    item.setSelectionMode(W.QAbstractItemView.SelectionMode.SingleSelection)
    item.setAlternatingRowColors(True)
    item.verticalHeader().hide()
    return item


def graph(y_label, unit, dates=False):
    axes = {"bottom": pg.DateAxisItem()} if dates else {}
    item = pg.PlotWidget(background="#14202e", axisItems=axes)
    item.setLabel("left", y_label, units=unit)
    item.showGrid(x=True, y=True, alpha=.25)
    return item


NETWORK_HEADERS = ("SSID", "BSSID", "ГГц", "Канал", "Частота приёма, МГц",
                   "Ширина, МГц", "Центр полосы, МГц", "RSSI, dBm", "Сигнал, %",
                   "Стандарт", "Безопасность", "Производитель")


def network_values(net):
    return (net.ssid or "Скрытая сеть", net.bssid, net.band, net.channel, net.frequency, net.width,
            " + ".join(f"{center:g}" for center in net.centers) or None,
            net.rssi, net.quality, net.standard, net.security, net.vendor)


class Window(W.QMainWindow):
    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self.history = History(folder / "history.sqlite3")
        self.vendors = load_vendors(folder / "oui.csv")
        self.settings = Q.QSettings(str(folder / "settings.ini"), Q.QSettings.Format.IniFormat)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="wifi")
        self.scan_job = self.ping_job = None
        self.networks = []
        self.own = None
        self.scan_valid = False
        self.refresh_adapters = True
        self.next_scan = self.next_ping = 0
        self.ping_generation = 0
        self.pinging = False
        self.pings = []
        self.setWindowTitle("Wi-Fi Analyzer")
        self.resize(1320, 830)
        central = W.QWidget()
        self.setCentralWidget(central)
        layout = W.QVBoxLayout(central)
        layout.setContentsMargins(18, 16, 18, 16)
        heading = label("Wi-Fi Analyzer")
        heading.setObjectName("title")
        self.adapters = combo()
        self.adapters.setMinimumWidth(290)
        self.adapters.currentIndexChanged.connect(self.adapter_changed)
        self.pause = W.QCheckBox("Пауза")
        self.pause.toggled.connect(self.update_freshness)
        self.pause.setToolTip("Приостанавливает активное сканирование")
        line(layout, heading, self.adapters, button("Обновить адаптеры", self.reload_adapters), self.pause)
        self.status = label("Поиск Wi-Fi-адаптеров…")
        self.status.setObjectName("status")
        layout.addWidget(self.status)
        self.tabs = W.QTabWidget()
        layout.addWidget(self.tabs)
        self.network_tab()
        self.channel_tab()
        self.signal_tab()
        self.advisor_tab()
        self.diagnostics_tab()
        self.timer = Q.QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(150)

    def tab(self, name):
        widget = W.QWidget()
        self.tabs.addTab(widget, name)
        return W.QVBoxLayout(widget)

    def network_tab(self):
        layout = self.tab("Сети")
        self.search = W.QLineEdit()
        self.search.setPlaceholderText("Поиск по SSID, BSSID или производителю")
        self.band = combo(("Все диапазоны", *BANDS))
        self.channel = W.QLineEdit()
        self.channel.setPlaceholderText("Канал")
        self.channel.setValidator(G.QIntValidator(1, 233, self))
        self.channel.setMaximumWidth(85)
        self.security = W.QLineEdit()
        self.security.setPlaceholderText("Безопасность")
        self.minimum = W.QSpinBox()
        self.minimum.setRange(-127, 0)
        self.minimum.setValue(-127)
        self.minimum.setPrefix("RSSI от ")
        self.minimum.setSuffix(" dBm")
        line(layout, self.search, self.band, self.channel, self.minimum, self.security,
             button("Экспорт CSV", self.export_networks))
        self.network_table = table(NETWORK_HEADERS)
        self.network_table.setSortingEnabled(True)
        self.network_table.itemSelectionChanged.connect(self.network_selected)
        self.network_table.cellDoubleClicked.connect(self.open_signal)
        layout.addWidget(self.network_table)
        for widget in (self.search, self.channel, self.security):
            widget.textChanged.connect(self.show_networks)
        self.band.currentIndexChanged.connect(self.show_networks)
        self.minimum.valueChanged.connect(self.show_networks)

    def channel_tab(self):
        layout = self.tab("График каналов")
        self.graph_band = combo(BANDS)
        self.graph_network = combo()
        line(layout, label("Диапазон, ГГц"), self.graph_band, label("Выделение"), self.graph_network,
             button("Сброс масштаба", self.reset_channel_range))
        self.channel_plot = graph("RSSI", "dBm")
        self.channel_plot.setLabel("bottom", "Частота", units="MHz")
        self.channel_plot.getAxis("bottom").enableAutoSIPrefix(False)
        layout.addWidget(self.channel_plot)
        layout.addWidget(label("Бирюзовый — подключённая сеть. Круг — ширина неизвестна. "
                               "Красные полосы — перекрытие известных полос разных сетей."))
        self.graph_band.currentIndexChanged.connect(self.change_graph_band)
        self.graph_network.currentIndexChanged.connect(self.show_channels)
        self.reset_channel_range()

    def signal_tab(self):
        layout = self.tab("Монитор RSSI")
        self.signal_network = combo()
        self.signal_network.currentIndexChanged.connect(self.signal_changed)
        line(layout, label("Точка доступа"), self.signal_network, button("Экспорт истории CSV", self.export_signal))
        self.signal_status = label("Выберите точку доступа.")
        layout.addWidget(self.signal_status)
        self.signal_plot = graph("RSSI", "dBm", dates=True)
        layout.addWidget(self.signal_plot)

    def advisor_tab(self):
        layout = self.tab("Channel Advisor")
        self.advisor_band = combo(BANDS)
        self.allowed = W.QLineEdit()
        self.allowed.setPlaceholderText("Например, 36, 40, 44, 48")
        line(layout, label("Диапазон, ГГц"), self.advisor_band,
             label("Каналы, доступные в настройках роутера"), self.allowed)
        self.advisor_status = label()
        layout.addWidget(self.advisor_status)
        self.advisor_table = table(("Каналы блока", "Ширина, МГц", "Оценка помех",
                                    "Пересечений", "Неизв. ширина", "Уверенность"))
        self.advisor_table.horizontalHeader().setSectionResizeMode(W.QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.advisor_table)
        layout.addWidget(label("Оценка учитывает RSSI и долю пересечения полос. При неизвестной ширине "
                               "учитывается только частота приёма внутри блока. Меньше — лучше в пределах "
                               "одной ширины. Сканирование не измеряет занятость эфира и не видит помехи вне Wi-Fi."))
        self.advisor_band.currentIndexChanged.connect(self.load_allowed)
        self.allowed.textChanged.connect(self.show_advice)
        self.load_allowed()

    def diagnostics_tab(self):
        layout = self.tab("Диагностика")
        self.external = W.QLineEdit(self.settings.value("external", "", str))
        self.external.setPlaceholderText("Внешний IPv4, необязательно")
        self.ping_button = button("Запустить ping", self.toggle_ping)
        line(layout, label("Цель"), self.external, self.ping_button,
             button("Экспорт CSV", self.export_ping))
        layout.addWidget(label("Шлюз выбирается для Wi-Fi-адаптера. Внешний ping выполняется при заданном IPv4."))
        self.ping_status = label("Диагностика остановлена.")
        layout.addWidget(self.ping_status)
        self.ping_plot = graph("Задержка", "ms", dates=True)
        self.ping_plot.addLegend()
        layout.addWidget(self.ping_plot)
        self.ping_rssi = graph("RSSI подключённой точки", "dBm", dates=True)
        self.ping_rssi.setXLink(self.ping_plot)
        layout.addWidget(self.ping_rssi)

    def adapter(self):
        return self.adapters.currentData()

    def adapter_changed(self):
        adapter = self.adapter()
        if adapter is None:
            return
        self.settings.setValue("adapter", adapter.guid)
        self.stop_ping()
        self.pings.clear()
        self.show_ping()
        self.networks, self.own, self.scan_valid = [], None, False
        self.next_scan = 0
        self.status.setText(f"{adapter.name} · ожидание сканирования")
        self.update_views()

    def reload_adapters(self):
        self.refresh_adapters = True

    def update_freshness(self):
        self.show_signal()
        self.show_advice()

    @staticmethod
    def scan(adapter, vendors, history, watched):
        with NativeWifi() as wlan:
            networks, own = wlan.scan(adapter, vendors)
        moment = time()
        history.record(adapter.guid, moment, networks, watched)
        return moment, networks, own

    def tick(self):
        now = time()
        if self.scan_job and self.scan_job.done():
            self.finish_scan()
        if not self.scan_job:
            adapter = self.adapter()
            if self.refresh_adapters:
                self.refresh_adapters = False
                self.scan_target = None
                self.scan_job = self.pool.submit(self.list_adapters)
            elif adapter and not self.pause.isChecked() and now >= self.next_scan:
                self.next_scan = now + 5
                self.scan_target = adapter
                watched = {bssid for bssid in (self.signal_network.currentData(), self.own) if bssid}
                self.scan_job = self.pool.submit(self.scan, adapter, self.vendors, self.history, watched)
        if self.ping_job and self.ping_job.done():
            self.finish_ping()
        if not self.ping_job and self.pinging and now >= self.next_ping:
            self.next_ping = now + 2
            self.ping_target = self.ping_generation
            self.ping_job = self.pool.submit(self.probe, self.adapter(), self.external.text().strip(), self.ping_route)

    @staticmethod
    def list_adapters():
        with NativeWifi() as wlan:
            return wlan.adapters()

    def finish_scan(self):
        job, self.scan_job = self.scan_job, None
        try:
            result = job.result()
        except Exception as error:
            logging.warning("WLAN: %s", error)
            if self.scan_target is None or self.scan_target == self.adapter():
                self.scan_valid = False
                if self.scan_target is None:
                    self.adapters.clear()
                    self.stop_ping()
                    self.networks, self.own = [], None
                    self.update_views()
                self.status.setText(f"{error}" + (" · показан предыдущий снимок" if self.networks else ""))
                self.update_freshness()
            return
        if self.scan_target is None:
            previous = self.adapter()
            preferred = self.settings.value("adapter", "", str)
            self.adapters.blockSignals(True)
            self.adapters.clear()
            for adapter in result:
                self.adapters.addItem(adapter.name, adapter)
            for index, adapter in enumerate(result):
                if adapter.guid == preferred:
                    self.adapters.setCurrentIndex(index)
                    break
            self.adapters.blockSignals(False)
            if not result:
                self.status.setText("Windows не обнаружила Wi-Fi-адаптеров. Подключите или включите адаптер и обновите список.")
                self.stop_ping()
                self.networks, self.own, self.scan_valid = [], None, False
                self.update_views()
            elif self.adapter() != previous:
                self.adapter_changed()
        elif self.adapter() == self.scan_target:
            moment, self.networks, self.own = result
            self.scan_valid = True
            clock = Q.QDateTime.fromSecsSinceEpoch(int(moment)).toString("HH:mm:ss")
            self.status.setText(f"{len(self.networks)} точек доступа · снимок {clock}"
                                + (f" · подключённая точка {self.own}" if self.own else ""))
            self.update_views()

    def filtered_networks(self):
        query = self.search.text().strip().casefold()
        security = self.security.text().strip().casefold()
        channel = self.channel.text()
        return [net for net in self.networks
                if (not self.band.currentIndex() or net.band == self.band.currentText())
                and (not channel or str(net.channel) == channel)
                and net.rssi >= self.minimum.value() and security in net.security.casefold()
                and query in " ".join((net.ssid, net.bssid, net.vendor)).casefold()]

    def show_networks(self):
        item = self.network_table
        rows = self.filtered_networks()
        selected = item.selectedItems()
        bssid = item.item(selected[0].row(), 1).text() if selected else None
        item.blockSignals(True)
        item.setSortingEnabled(False)
        item.setRowCount(len(rows))
        for row, net in enumerate(rows):
            for col, value in enumerate(network_values(net)):
                cell = W.QTableWidgetItem()
                cell.setData(Q.Qt.ItemDataRole.DisplayRole, UNKNOWN if value is None else value)
                if net.bssid == self.own:
                    cell.setForeground(G.QColor("#59d6cb"))
                item.setItem(row, col, cell)
        item.setSortingEnabled(True)
        for row in range(item.rowCount()):
            if item.item(row, 1).text() == bssid:
                item.selectRow(row)
                break
        item.blockSignals(False)

    def update_views(self):
        self.show_networks()
        self.update_graph_choices()
        self.update_signal_choices()
        self.show_advice()

    @staticmethod
    def replace_choices(widget, choices, empty=None):
        prior = widget.currentData()
        widget.blockSignals(True)
        widget.clear()
        if empty:
            widget.addItem(empty, None)
        for key, name in choices:
            widget.addItem(f"{name} · {key}", key)
        index = widget.findData(prior)
        if index >= 0:
            widget.setCurrentIndex(index)
        widget.blockSignals(False)

    def network_selected(self):
        row = self.network_table.currentRow()
        if row < 0 or not self.network_table.selectedItems():
            return
        bssid = self.network_table.item(row, 1).text()
        net = next((net for net in self.networks if net.bssid == bssid), None)
        if net and net.band in BANDS:
            self.graph_band.setCurrentText(net.band)
            self.graph_network.setCurrentIndex(self.graph_network.findData(bssid))
        index = self.signal_network.findData(bssid)
        if index >= 0:
            self.signal_network.setCurrentIndex(index)

    def open_signal(self, *_):
        self.network_selected()
        self.tabs.setCurrentIndex(2)

    def change_graph_band(self):
        self.reset_channel_range()
        self.update_graph_choices()

    def reset_channel_range(self):
        start, end = {"2,4": (2397, 2494), "5": (5160, 5900), "6": (5925, 7135)}[self.graph_band.currentText()]
        self.channel_plot.setXRange(start, end, padding=0)
        self.channel_plot.setYRange(-108, -20, padding=0)

    def update_graph_choices(self):
        band = self.graph_band.currentText()
        self.replace_choices(self.graph_network,
                             ((net.bssid, net.ssid or "Скрытая сеть") for net in self.networks if net.band == band),
                             "Все сети")
        self.show_channels()

    def show_channels(self):
        plot = self.channel_plot
        plot.clear()
        band = self.graph_band.currentText()
        selected = self.graph_network.currentData()
        channels = possible_channels(band)
        plot.getAxis("bottom").setTicks([[(channel_frequency(band, ch), f"{channel_frequency(band, ch)} / {ch}")
                                         for ch in channels[::(2 if band != "6" else 4)]]])
        drawn = [net for net in self.networks if net.band == band and net.frequency is not None]
        drawn.sort(key=lambda net: (net.bssid == selected, net.bssid == self.own))
        spans = []
        for net in drawn:
            color = "#59d6cb" if net.bssid == self.own else pg.intColor(int(net.bssid.replace(":", ""), 16) % 19, hues=19)
            highlight = net.bssid in (selected, self.own)
            if not net.spans():
                mark = pg.ScatterPlotItem([net.frequency], [net.rssi], size=13 if highlight else 8,
                                          pen=pg.mkPen(color, width=2), brush=None)
                mark.sigClicked.connect(lambda *_, key=net.bssid: self.graph_network.setCurrentIndex(self.graph_network.findData(key)))
                plot.addItem(mark)
            for span in net.spans():
                left, right = span
                shoulder = min(4, (right - left) / 5)
                curve = plot.plot([left, left + shoulder, right - shoulder, right],
                                  [-110, net.rssi, net.rssi, -110], pen=pg.mkPen(color, width=3 if highlight else 1.5))
                curve.setCurveClickable(True, width=8)
                curve.sigClicked.connect(lambda *_, key=net.bssid: self.graph_network.setCurrentIndex(self.graph_network.findData(key)))
                spans.append((net.bssid, span))
        for index, (bssid, first) in enumerate(spans):
            for other, second in spans[index + 1:]:
                if other != bssid and overlap(first, second):
                    region = pg.LinearRegionItem((max(first[0], second[0]), min(first[1], second[1])),
                                                 brush=(245, 98, 96, 22), pen=None, movable=False)
                    region.setZValue(-10)
                    plot.addItem(region, ignoreBounds=True)

    def update_signal_choices(self):
        adapter = self.adapter()
        devices = self.history.devices(adapter.guid) if adapter else {}
        self.replace_choices(self.signal_network, devices.items(), "Выберите точку доступа")
        if self.signal_network.currentData() is None and adapter:
            saved = self.settings.value(f"signal/{adapter.guid}", "", str)
            index = self.signal_network.findData(saved)
            if index >= 0:
                self.signal_network.setCurrentIndex(index)
        self.show_signal()

    def signal_changed(self):
        if self.adapter() and self.signal_network.currentData():
            self.settings.setValue(f"signal/{self.adapter().guid}", self.signal_network.currentData())
        self.show_signal()

    def signal_samples(self, limit=None):
        adapter, bssid = self.adapter(), self.signal_network.currentData()
        return self.history.samples(adapter.guid, bssid, limit) if adapter and bssid else []

    def show_signal(self):
        self.signal_plot.clear()
        samples = self.signal_samples(720)
        if not samples:
            self.signal_status.setText("Выберите точку доступа для мониторинга.")
            return
        x, y = [], []
        for moment, rssi in samples:
            if x and moment - x[-1] > 15:
                x.append(moment)
                y.append(nan)
            x.append(moment)
            y.append(rssi if rssi is not None else nan)
        self.signal_plot.plot(x, y, pen=pg.mkPen("#59d6cb", width=2), symbol="o", symbolSize=4, connect="finite")
        observed = [value for _, value in samples if value is not None]
        state = ("Последний снимок устарел" if not self.scan_valid or self.pause.isChecked() else
                 "Обнаружена" if any(net.bssid == self.signal_network.currentData() for net in self.networks)
                 else "Точка отсутствует в последнем снимке")
        stats = (f"мин. {min(observed)} · макс. {max(observed)} · среднее "
                 f"{sum(observed) / len(observed):.1f} dBm") if observed else "нет измерений RSSI"
        self.signal_status.setText(f"{state} · {stats} · последние {len(samples)} записей")

    def load_allowed(self):
        self.allowed.setText(self.settings.value(f"channels/{self.advisor_band.currentText()}", "", str))
        self.show_advice()

    def show_advice(self):
        self.advisor_table.setRowCount(0)
        band = self.advisor_band.currentText()
        self.settings.setValue(f"channels/{band}", self.allowed.text())
        try:
            allowed = {int(part) for part in self.allowed.text().replace(",", " ").split()}
            if not allowed <= set(possible_channels(band)):
                raise ValueError
        except ValueError:
            self.advisor_status.setText("Укажите номера каналов выбранного диапазона через запятую.")
            return
        if not allowed or not self.scan_valid or self.pause.isChecked():
            self.advisor_status.setText("Для расчёта нужны свежий снимок и список разрешённых каналов роутера.")
            return
        options = recommend(self.networks, band, allowed, self.own)
        self.advisor_status.setText(f"{len(options)} вариантов. Основной канал можно выбрать внутри блока "
                                    "с учётом настроек роутера и требований DFS.")
        self.advisor_table.setRowCount(len(options))
        for row, option in enumerate(options):
            values = (", ".join(map(str, option.channels)), option.width, f"{option.score:.3f}",
                      option.overlapping, option.unknown_width, option.confidence)
            for column, value in enumerate(values):
                self.advisor_table.setItem(row, column, W.QTableWidgetItem(str(value)))

    def toggle_ping(self):
        if self.pinging:
            self.stop_ping()
            return
        if not self.adapter():
            self.ping_status.setText("Выберите Wi-Fi-адаптер.")
            return
        address = self.external.text().strip()
        if address:
            try:
                IPv4Address(address)
            except ValueError:
                self.ping_status.setText("Укажите корректный IPv4-адрес.")
                return
        self.settings.setValue("external", address)
        self.ping_generation += 1
        self.pinging = True
        self.ping_route = None
        self.pings.clear()
        self.next_ping = 0
        self.external.setEnabled(False)
        self.ping_button.setText("Остановить")
        self.ping_status.setText("Определение IPv4-маршрута…")

    def stop_ping(self):
        self.ping_generation += 1
        self.pinging = False
        self.external.setEnabled(True)
        self.ping_button.setText("Запустить ping")
        self.ping_status.setText("Диагностика остановлена.")

    @staticmethod
    def probe(adapter, address, route):
        route = route or wifi_route(adapter)
        with Ping() as ping:
            gateway = ping.echo(route.source, route.gateway) if route.gateway and route.gateway != "0.0.0.0" else None
            external = ping.echo(route.source, address) if address else None
        return time(), route, gateway, external

    def finish_ping(self):
        job, self.ping_job = self.ping_job, None
        if not self.pinging or self.ping_target != self.ping_generation:
            return
        try:
            moment, route, gateway, external = job.result()
        except Exception as error:
            logging.warning("Диагностика: %s", error)
            self.stop_ping()
            self.ping_status.setText(str(error))
            return
        self.ping_route = route
        own_rssi = None
        if self.scan_valid and not self.pause.isChecked() and self.own:
            samples = self.history.samples(self.adapter().guid, self.own, 1)
            if samples and abs(moment - samples[0][0]) <= 7:
                own_rssi = samples[0][1]
        self.pings.append((moment, gateway, external, own_rssi, self.own))
        self.show_ping()
        stats = []
        for index, name in ((1, f"Шлюз {route.gateway or '—'}"), (2, "Внешний адрес")):
            checks = [row[index] for row in self.pings if row[index] is not None]
            if checks:
                failures = sum(check[0] is None for check in checks)
                current = f"{checks[-1][0]} мс" if checks[-1][0] is not None else f"нет ответа (код {checks[-1][1]})"
                stats.append(f"{name} · {current} · без ответа {failures}/{len(checks)} ({100 * failures / len(checks):.1f} %)")
        last = self.pings[-2] if len(self.pings) > 1 else None
        recovered = last and any(last[i] and last[i][0] is None and value and value[0] is not None
                                 for i, value in ((1, gateway), (2, external)))
        self.ping_status.setText(" | ".join(stats) + "\n" + assessment(gateway, external)
                                 + (" Ответ восстановился после пропуска." if recovered else ""))

    def show_ping(self):
        self.ping_plot.clear()
        self.ping_rssi.clear()
        recent = self.pings[-720:]
        times = [row[0] for row in recent]
        for index, name, color in ((1, "Шлюз", "#59d6cb"), (2, "Внешний IP", "#f4bc73")):
            values = [row[index][0] if row[index] and row[index][0] is not None else nan for row in recent]
            self.ping_plot.plot(times, values, name=name, pen=pg.mkPen(color, width=2),
                                symbol="o", symbolSize=4, connect="finite")
            failed = [row[0] for row in recent if row[index] and row[index][0] is None]
            if failed:
                self.ping_plot.plot(failed, [0] * len(failed), pen=None, symbol="x",
                                    symbolPen=color, symbolSize=8, name=f"{name}: нет ответа")
        self.ping_rssi.plot(times, [row[3] if row[3] is not None else nan for row in recent],
                            pen=pg.mkPen("#9dabff", width=2), symbol="o", symbolSize=4, connect="finite")

    def save(self, name, headers, rows):
        path, _ = W.QFileDialog.getSaveFileName(self, "Сохранить CSV", name, "CSV (*.csv)")
        if path:
            try:
                export_csv(path, headers, rows)
            except OSError as error:
                W.QMessageBox.warning(self, "Ошибка экспорта", str(error))

    def export_networks(self):
        self.save("networks.csv", NETWORK_HEADERS, map(network_values, self.filtered_networks()))

    def export_signal(self):
        bssid = self.signal_network.currentData()
        if bssid:
            self.save("signal.csv", ("UTC", "BSSID", "RSSI dBm", "Обнаружена"),
                      ((timestamp(moment), bssid, rssi, int(rssi is not None)) for moment, rssi in self.signal_samples()))

    def export_ping(self):
        if self.pings:
            self.save("ping.csv", ("UTC", "Шлюз мс", "Код шлюза", "Внешний IP мс", "Код внешнего IP", "RSSI dBm", "BSSID"),
                      ((timestamp(moment), *(gateway or (None, None)), *(external or (None, None)), rssi, bssid)
                       for moment, gateway, external, rssi, bssid in self.pings))

    def closeEvent(self, event):
        self.timer.stop()
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.settings.sync()
        super().closeEvent(event)


def main():
    app = W.QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    pg.setConfigOptions(antialias=True, foreground="#b6cce3")
    folder = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "WiFiAnalyzer"
    folder.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        handlers=[RotatingFileHandler(folder / "analyzer.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")],
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        window = Window(folder)
    except (OSError, RuntimeError, sqlite3.Error) as error:
        logging.exception("Запуск")
        W.QMessageBox.critical(None, "Wi-Fi Analyzer", str(error))
        return 1
    window.show()
    return app.exec()
