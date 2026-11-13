import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import threading
from uuid import UUID

from .radio import Network, UNKNOWN, elements, frequency_channel, operation, security


class GUID(C.Structure):
    _fields_ = [("data1", W.DWORD), ("data2", W.WORD), ("data3", W.WORD), ("data4", C.c_ubyte * 8)]


class SSID(C.Structure):
    _fields_ = [("length", W.ULONG), ("data", C.c_ubyte * 32)]


class Rates(C.Structure):
    _fields_ = [("length", W.ULONG), ("data", W.USHORT * 126)]


class Bss(C.Structure):
    _fields_ = [
        ("ssid", SSID), ("phy_id", W.ULONG), ("mac", C.c_ubyte * 6),
        ("bss_type", C.c_int), ("phy", C.c_int), ("rssi", W.LONG),
        ("quality", W.ULONG), ("in_domain", C.c_ubyte), ("beacon", W.USHORT),
        ("timestamp", C.c_uint64), ("host_timestamp", C.c_uint64), ("capability", W.USHORT),
        ("frequency", W.ULONG), ("rates", Rates), ("ie_offset", W.ULONG), ("ie_size", W.ULONG),
    ]


class Interface(C.Structure):
    _fields_ = [("guid", GUID), ("description", W.WCHAR * 256), ("state", C.c_int)]


class Notification(C.Structure):
    _fields_ = [
        ("source", W.DWORD), ("code", W.DWORD), ("guid", GUID),
        ("size", W.DWORD), ("data", C.c_void_p),
    ]


class Association(C.Structure):
    _fields_ = [
        ("ssid", SSID), ("bss_type", C.c_int), ("mac", C.c_ubyte * 6),
        ("phy", C.c_int), ("phy_index", W.ULONG), ("quality", W.ULONG),
        ("rx_rate", W.ULONG), ("tx_rate", W.ULONG),
    ]


class Connection(C.Structure):
    _fields_ = [
        ("state", C.c_int), ("mode", C.c_int), ("profile", W.WCHAR * 256),
        ("association", Association),
    ]


@dataclass(frozen=True)
class Adapter:
    guid: str
    name: str


def mac_text(mac):
    return ":".join(f"{octet:02X}" for octet in mac)


def decode_bss(address, end, entries_end, vendors):
    entry = Bss.from_address(address)
    start = address + entry.ie_offset
    blob = b""
    if entries_end <= start <= end and 0 < entry.ie_size <= min(2324, end - start):
        blob = C.string_at(start, entry.ie_size)
    ies = elements(blob)
    frequency = entry.frequency / 1000 if entry.frequency and entry.phy != 1 else None
    band, channel = frequency_channel(frequency) if frequency is not None else (UNKNOWN, None)
    width, centers = operation(ies, band, channel, entry.phy)
    ssid = bytes(entry.ssid.data[:min(entry.ssid.length, 32)]).decode("utf-8", "backslashreplace")
    ssid = "".join(char if char.isprintable() else f"\\x{ord(char):02x}" for char in ssid)
    phy = {4: "802.11a", 5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac",
           9: "802.11ad", 10: "802.11ax", 11: "802.11be"}.get(entry.phy, UNKNOWN)
    return Network(
        ssid, mac_text(entry.mac), band, channel, frequency, width, centers, entry.rssi,
        entry.quality, phy, security(ies, bool(entry.capability & 0x10)),
        vendors.get(bytes(entry.mac[:3]).hex().upper(), UNKNOWN) if not entry.mac[0] & 2 else UNKNOWN,
    )


class WifiError(RuntimeError):
    def __init__(self, action, code):
        self.code = code
        hints = {
            5: "Разрешите доступ к геопозиции для классических приложений в параметрах Windows.",
            1062: "Запустите службу автонастройки WLAN (WlanSvc).",
            1168: "Проверьте, что Wi-Fi-адаптер включён и доступен.",
            2150899714: "Проверьте, что Wi-Fi включён и режим полёта выключен.",
        }
        detail = hints.get(code) or C.FormatError(code).strip()
        super().__init__(f"{action} — {detail} (код {code})")


def checked(code, action):
    if code:
        raise WifiError(action, code)


class NativeWifi:
    def __init__(self):
        self.dll = C.WinDLL("wlanapi.dll")
        pointer = C.c_void_p
        out = C.POINTER(pointer)
        guid = C.POINTER(GUID)
        self.callback_type = C.WINFUNCTYPE(None, C.POINTER(Notification), pointer)
        signatures = {
            "WlanOpenHandle": (W.DWORD, pointer, C.POINTER(W.DWORD), out),
            "WlanCloseHandle": (pointer, pointer),
            "WlanEnumInterfaces": (pointer, pointer, out),
            "WlanScan": (pointer, guid, pointer, pointer, pointer),
            "WlanRegisterNotification": (
                pointer, W.DWORD, W.BOOL, self.callback_type, pointer, pointer, C.POINTER(W.DWORD),
            ),
            "WlanGetNetworkBssList": (pointer, guid, pointer, C.c_int, W.BOOL, pointer, out),
            "WlanQueryInterface": (pointer, guid, C.c_int, pointer, C.POINTER(W.DWORD), out, pointer),
            "WlanFreeMemory": (pointer,),
        }
        for name, args in signatures.items():
            method = getattr(self.dll, name)
            method.argtypes = args
            method.restype = None if name == "WlanFreeMemory" else W.DWORD
        self.handle = pointer()
        checked(self.dll.WlanOpenHandle(2, None, C.byref(W.DWORD()), C.byref(self.handle)), "Открытие WLAN")
        self.event = threading.Event()
        self.target = None
        self.scan_code = None
        self.callback = self.callback_type(self._notify)
        self.registered = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.dll.WlanCloseHandle(self.handle, None)

    def _notify(self, pointer, _):
        data = pointer.contents
        if data.source == 8 and data.code in (7, 8) and bytes(data.guid) == self.target:
            self.scan_code = data.code
            self.event.set()

    def adapters(self):
        data = C.c_void_p()
        checked(self.dll.WlanEnumInterfaces(self.handle, None, C.byref(data)), "Список Wi-Fi-адаптеров")
        try:
            count = W.DWORD.from_address(data.value).value
            interfaces = (Interface * count).from_address(data.value + 8)
            return [Adapter(str(UUID(bytes_le=bytes(item.guid))), item.description) for item in interfaces]
        finally:
            self.dll.WlanFreeMemory(data)

    def connected_bssid(self, guid):
        size, data = W.DWORD(), C.c_void_p()
        code = self.dll.WlanQueryInterface(self.handle, C.byref(guid), 7, None,
                                           C.byref(size), C.byref(data), None)
        if code:  # Includes ERROR_INVALID_STATE when disconnected.
            return None
        try:
            if size.value >= C.sizeof(Connection):
                connection = Connection.from_address(data.value)
                if connection.state == 1:
                    return mac_text(connection.association.mac)
            return None
        finally:
            self.dll.WlanFreeMemory(data)

    def scan(self, adapter, vendors):
        if not self.registered:
            checked(self.dll.WlanRegisterNotification(self.handle, 8, False, self.callback,
                                                      None, None, None), "Уведомления WLAN")
            self.registered = True
        guid = GUID.from_buffer_copy(UUID(adapter.guid).bytes_le)
        self.target = bytes(guid)
        self.scan_code = None
        self.event.clear()
        checked(self.dll.WlanScan(self.handle, C.byref(guid), None, None, None), "Сканирование Wi-Fi")
        self.event.wait(4.0)
        if self.scan_code != 7:
            reason = "Драйвер сообщил об ошибке сканирования." if self.scan_code == 8 else "Драйвер не подтвердил сканирование за 4 секунды."
            raise RuntimeError(reason)
        data = C.c_void_p()
        checked(self.dll.WlanGetNetworkBssList(self.handle, C.byref(guid), None, 3, False,
                                               None, C.byref(data)), "Чтение списка BSS")
        try:
            total, count = (W.DWORD * 2).from_address(data.value)
            end = data.value + total
            size = C.sizeof(Bss)
            entries_end = data.value + 8 + count * size
            if entries_end > end:
                raise RuntimeError("WLAN вернула повреждённый список BSS.")
            networks = {}
            for index in range(count):
                network = decode_bss(data.value + 8 + index * size, end, entries_end, vendors)
                current = networks.get(network.bssid)
                if current is None or network.rssi > current.rssi:
                    networks[network.bssid] = network
        finally:
            self.dll.WlanFreeMemory(data)
        return list(networks.values()), self.connected_bssid(guid)
