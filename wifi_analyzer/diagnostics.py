import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import subprocess
from uuid import UUID


@dataclass(frozen=True)
class Route:
    source: str
    gateway: str | None


def wifi_route(adapter):
    guid = UUID(adapter.guid)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $adapter = Get-NetAdapter | Where-Object {{ [guid]$_.InterfaceGuid -eq [guid]'{guid}' }}
        if (!$adapter) {{ throw 'Adapter unavailable' }}
        $index = $adapter.ifIndex
        $ip = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 |
            Where-Object {{ $_.AddressState -eq 'Preferred' -and !$_.SkipAsSource }} |
            Select-Object -First 1 -ExpandProperty IPAddress
        $gateway = Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop
        @{{source=$ip; gateway=$gateway}} | ConvertTo-Json -Compress
    """
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(executable), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise RuntimeError("Не удалось получить параметры IPv4 Wi-Fi-адаптера.")
    route = json.loads(result.stdout)
    if not route["source"]:
        raise RuntimeError("У выбранного Wi-Fi-адаптера нет рабочего IPv4-адреса.")
    return Route(route["source"], route["gateway"])


class Ping:
    def __enter__(self):
        self.api = C.WinDLL("iphlpapi.dll", use_last_error=True)
        self.api.IcmpCreateFile.argtypes = []
        self.api.IcmpCreateFile.restype = W.HANDLE
        self.api.IcmpCloseHandle.argtypes = [W.HANDLE]
        self.api.IcmpCloseHandle.restype = W.BOOL
        self.api.IcmpSendEcho2Ex.argtypes = [
            W.HANDLE, W.HANDLE, C.c_void_p, C.c_void_p, W.DWORD, W.DWORD,
            C.c_void_p, W.WORD, C.c_void_p, C.c_void_p, W.DWORD, W.DWORD,
        ]
        self.api.IcmpSendEcho2Ex.restype = W.DWORD
        self.handle = self.api.IcmpCreateFile()
        if self.handle in (None, C.c_void_p(-1).value):
            raise C.WinError(C.get_last_error())
        return self

    def __exit__(self, *_):
        self.api.IcmpCloseHandle(self.handle)

    def echo(self, source, destination):
        payload = C.create_string_buffer(b"WiFiAnalyzer")
        reply = (W.DWORD * 256)()
        source_ip = int.from_bytes(IPv4Address(source).packed, "little")
        dest_ip = int.from_bytes(IPv4Address(destination).packed, "little")
        count = self.api.IcmpSendEcho2Ex(
            self.handle, None, None, None, source_ip, dest_ip,
            payload, C.sizeof(payload) - 1, None, reply, C.sizeof(reply), 850,
        )
        if not count:
            return None, C.get_last_error()
        return (reply[2] if reply[1] == 0 else None), reply[1]


def assessment(gateway, external):
    if gateway is None:
        return "Без проверки шлюза источник сбоя определить нельзя."
    if gateway[0] is None and external is not None and external[0] is not None:
        return "Внешний адрес отвечает. Шлюз мог отфильтровать ICMP."
    if gateway[0] is None:
        return "Шлюз не ответил. Возможен локальный сбой Wi-Fi, маршрута или фильтрация ICMP."
    if external is not None and external[0] is None:
        return "Шлюз отвечает. Возможен сбой за шлюзом или фильтрация ICMP."
    return "На проверенных маршрутах получены ответы."
