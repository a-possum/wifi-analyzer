from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from wifi_analyzer.advisor import overlap, recommend
from wifi_analyzer.diagnostics import assessment
from wifi_analyzer.history import History, export_csv
from wifi_analyzer.radio import Network, UNKNOWN, elements, frequency_channel, operation, security


def ap(width, centers, bssid="A", rssi=-55):
    return Network("Example", bssid, "5", 36, 5180, width, centers, rssi, 90, "802.11ax", "WPA2-PSK", UNKNOWN)


class RadioTests(unittest.TestCase):
    def test_frequency(self):
        self.assertEqual(frequency_channel(2484), ("2,4", 14))
        self.assertEqual(frequency_channel(5935), ("6", 2))
        self.assertEqual(frequency_channel(5975), ("6", 5))
        self.assertEqual(frequency_channel(5181), (UNKNOWN, None))

    def test_invalid_and_missing_elements(self):
        self.assertEqual(elements(b"\x3d\x16\x01"), {})
        self.assertEqual(operation({}, "5", 36), (None, ()))
        self.assertEqual(operation({61: bytes([36, 0])}, "5", 36), (None, ()))
        self.assertEqual(operation({61: bytes([36, 5]) + bytes(20)}, "5", 36, 10), (None, ()))

    def test_ht(self):
        self.assertEqual(operation({61: bytes([1, 0]) + bytes(20)}, "2,4", 1), (20, (2412,)))
        self.assertEqual(operation({61: bytes([6, 7]) + bytes(20)}, "2,4", 6), (40, (2427,)))

    def test_vht(self):
        self.assertEqual(operation({192: bytes([1, 42, 0, 0, 0])}, "5", 36), (80, (5210,)))
        self.assertEqual(operation({192: bytes([1, 42, 50, 0, 0])}, "5", 36), (160, (5250,)))
        self.assertEqual(operation({192: bytes([1, 42, 155, 0, 0])}, "5", 36), ("80+80", (5210, 5775)))
        self.assertEqual(operation({192: bytes([1, 58, 0, 0, 0])}, "5", 36), (None, ()))

    def test_he_eht(self):
        he = {(255, 36): bytes([0, 0, 2, 0, 0, 0, 1, 2, 7, 0, 0])}
        self.assertEqual(operation(he, "6", 1, 10), (80, (5985,)))
        self.assertEqual(operation(he, "6", 1, 11), (None, ()))
        he[(255, 106)] = bytes([1, 0, 0, 0, 0, 4, 15, 31])
        self.assertEqual(operation(he, "6", 1, 11), (320, (6105,)))

    def test_security(self):
        rsn = bytes.fromhex("0100 000fac04 0100 000fac04 0200 000fac02 000fac08")
        self.assertEqual(security({48: rsn}, True), "WPA2-PSK / WPA3-SAE")
        self.assertEqual(security({}, True), "Защищена (тип неизвестен)")
        self.assertEqual(security({}, False), "Открытая")


class AdvisorTests(unittest.TestCase):
    def test_overlap_edges(self):
        self.assertEqual(overlap((0, 20), (20, 40)), 0)
        self.assertEqual(overlap((0, 20), (15, 25)), 5)
        self.assertEqual(overlap((0, 20), (5, 10)), 5)

    def test_80mhz_requires_all_channels(self):
        self.assertFalse(any(result.width == 80 for result in recommend([], "5", {36, 40, 44})))
        options = recommend([ap(80, (5210,)), ap(None, (), "B")], "5", {36, 40, 44, 48, 149})
        self.assertEqual(options[0].channels, (149,))
        wide = next(option for option in options if option.width == 80)
        self.assertEqual((wide.overlapping, wide.unknown_width, wide.confidence), (1, 1, "Низкая"))
        self.assertEqual(recommend([ap(80, (5210,))], "5", {36}, "A")[0].score, 0)


class HistoryTests(unittest.TestCase):
    def test_adapter_isolation_and_missing_sample(self):
        with TemporaryDirectory() as folder:
            history = History(Path(folder) / "samples.sqlite3")
            history.record("wifi1", 100, [ap(20, (5180,))], [])
            history.record("wifi1", 105, [], ["A"])
            history.record("wifi2", 110, [ap(20, (5180,), rssi=-76)], [])
            self.assertEqual(history.samples("wifi1", "A"), [(100, -55), (105, None)])
            self.assertEqual(history.samples("wifi2", "A"), [(110, -76)])
            self.assertEqual(history.devices("wifi1"), {"A": "Example"})

    def test_csv_preserves_numeric_rssi_and_escapes_formulas(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "sample.csv"
            export_csv(path, ("SSID", "RSSI"), [("=unsafe", -60)])
            self.assertEqual(path.read_text(encoding="utf-8-sig").splitlines(), ["SSID,RSSI", "'=unsafe,-60"])


class DiagnosticsTests(unittest.TestCase):
    def test_local_external_and_filtering(self):
        self.assertIn("локальный", assessment((None, 11010), (None, 11010)))
        self.assertIn("за шлюзом", assessment((1, 0), (None, 11010)))
        self.assertIn("отфильтровать", assessment((None, 11010), (6, 0)))


if __name__ == "__main__":
    unittest.main()
