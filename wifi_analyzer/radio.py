from dataclasses import dataclass
from struct import unpack_from


UNKNOWN = "Не определено"
BANDS = ("2,4", "5", "6")


@dataclass(frozen=True)
class Network:
    ssid: str
    bssid: str
    band: str
    channel: int | None
    frequency: float | None
    width: int | str | None
    centers: tuple[float, ...]
    rssi: int
    quality: int
    standard: str
    security: str
    vendor: str

    def spans(self):
        segment = 80 if self.width == "80+80" else self.width
        if not isinstance(segment, int):
            return ()
        return tuple((center - segment / 2, center + segment / 2) for center in self.centers)


def channel_frequency(band, channel):
    if band == "2,4":
        if channel == 14:
            return 2484
        return 2407 + 5 * channel if 1 <= channel <= 13 else None
    if band == "5":
        return 5000 + 5 * channel if 1 <= channel <= 179 else None
    if band == "6":
        if channel == 2:
            return 5935
        return 5950 + 5 * channel if 1 <= channel <= 233 else None
    return None


def frequency_channel(frequency):
    if frequency == 2484:
        return "2,4", 14
    if frequency == 5935:
        return "6", 2
    for band, base, low, high in (
        ("2,4", 2407, 2412, 2472), ("5", 5000, 5005, 5895), ("6", 5950, 5955, 7115)
    ):
        if low <= frequency <= high and (frequency - base) % 5 == 0:
            return band, int((frequency - base) / 5)
    return UNKNOWN, None


def elements(blob):
    result = {}
    offset = 0
    while offset + 2 <= len(blob):
        identifier, size = blob[offset:offset + 2]
        offset += 2
        if offset + size > len(blob):
            return {}
        payload = blob[offset:offset + size]
        if identifier == 255 and payload:
            key, payload = (255, payload[0]), payload[1:]
        elif identifier == 221 and len(payload) >= 4:
            key, payload = (221, payload[:4]), payload[4:]
        else:
            key = identifier
        if key in result and result[key] != payload:
            result[key] = b""
        else:
            result[key] = payload
        offset += size
    return result if offset == len(blob) else {}


def wide_segments(mode, first, second):
    if mode == 1:
        if second == 0:
            return 80, (first,)
        if abs(first - second) == 8:
            return 160, (second,)
        if abs(first - second) > 16:
            return "80+80", (first, second)
    if mode == 2 and second == 0:
        return 160, (first,)
    if mode == 3 and abs(first - second) > 16:
        return "80+80", (first, second)
    return None, ()


def operation(ies, band, primary, phy=0):
    if primary is None:
        return None, ()
    he = ies.get((255, 36), b"")
    eht = ies.get((255, 106))
    vht = ies.get(192)
    he_six = None
    if len(he) >= 6:
        flags = int.from_bytes(he[:3], "little")
        offset = 6
        if flags & (1 << 14):
            vht = he[offset:offset + 3]
            offset += 3
        if flags & (1 << 15):
            offset += 1
        if flags & (1 << 17) and len(he) >= offset + 5:
            he_six = he[offset:offset + 5]
    if band == "6" and (not he_six or he_six[0] != primary):
        return None, ()

    if eht is not None and (not eht or len(eht) < 5):
        return None, ()
    if eht and eht[0] & 1:
        if len(eht) < (10 if eht[0] & 2 else 8):
            return None, ()
        code, first, second = eht[5:8]
        code &= 7
        if code > 4:
            return None, ()
        width = 20 << code
        channels = (second if width >= 160 else first,)
    elif band == "6":
        if phy == 11 and eht is None:
            return None, ()
        _, control, first, second, _ = he_six
        mode = control & 3
        if mode < 3:
            width, channels = 20 << mode, (first,)
        elif second:
            width, channels = wide_segments(1, first, second)
        else:
            return None, ()
    elif vht is not None and (len(vht) < 3 or vht[0] != 0):
        if band != "5" or len(vht) < 3:
            return None, ()
        width, channels = wide_segments(*vht[:3])
    else:
        if (phy == 11 and eht is None) or (band == "5" and phy in (8, 10, 11) and vht is None):
            return None, ()
        ht = ies.get(61, b"")
        if len(ht) < 22 or ht[0] != primary:
            return None, ()
        offset = ht[1] & 3
        if not (ht[1] & 4) and offset == 0:
            width, channels = 20, (primary,)
        elif ht[1] & 4 and offset in (1, 3):
            width, channels = 40, (primary + (2 if offset == 1 else -2),)
        else:
            return None, ()

    if width is None or (band == "2,4" and width not in (20, 40)) or (width == 320 and band != "6"):
        return None, ()
    centers = tuple(channel_frequency(band, channel) for channel in channels)
    frequency = channel_frequency(band, primary)
    segment_width = 80 if width == "80+80" else width
    if frequency is None or None in centers:
        return None, ()
    distance = abs(frequency - centers[0])
    if distance not in range(segment_width // 2 - 10, -1, -20):
        return None, ()
    return width, centers


def authentication(payload, suite_oui, names):
    if len(payload) < 8 or payload[:2] != b"\x01\x00":
        return ()
    pair_count = unpack_from("<H", payload, 6)[0]
    offset = 8 + pair_count * 4
    if not pair_count or len(payload) < offset + 2:
        return ()
    count = unpack_from("<H", payload, offset)[0]
    start = offset + 2
    if not count or len(payload) < start + 4 * count:
        return ()
    suites = (payload[index:index + 4] for index in range(start, start + 4 * count, 4))
    return tuple(dict.fromkeys(names.get(suite[3], "другой AKM")
                               if suite[:3] == suite_oui else "другой AKM" for suite in suites))


def security(ies, privacy):
    wpa = ies.get((221, b"\x00\x50\xf2\x01"))
    rsn = ies.get(48)
    labels = []
    if wpa is not None:
        modes = authentication(wpa, b"\x00\x50\xf2", {1: "Enterprise", 2: "PSK"})
        labels.append("WPA " + "/".join(modes) if modes else "WPA (режим неизвестен)")
    if rsn is not None:
        modes = authentication(rsn, b"\x00\x0f\xac", {
            1: "802.1X", 2: "WPA2-PSK", 3: "FT-802.1X", 4: "FT-PSK",
            5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "WPA3-SAE", 9: "FT-SAE",
            11: "Suite-B", 12: "WPA3-Enterprise 192", 18: "OWE", 24: "SAE-EXT",
        })
        labels.append(" / ".join(modes) if modes else "RSN (режим неизвестен)")
    if labels:
        return " + ".join(labels)
    return "Защищена (тип неизвестен)" if privacy else "Открытая"


def load_vendors(path):
    """Read the IEEE MA-L CSV format from a local file."""
    import csv

    if not path.is_file():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as source:
        return {row["Assignment"].upper(): row["Organization Name"]
                for row in csv.DictReader(source) if row.get("Assignment") and row.get("Organization Name")}
