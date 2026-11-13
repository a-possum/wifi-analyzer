import csv
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds")


def export_csv(path, headers, rows):
    def safe(value):
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    with Path(path).open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(tuple(safe(value) for value in row) for row in rows)


class History:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS signal (
                    adapter TEXT, bssid TEXT, moment REAL, rssi INTEGER,
                    PRIMARY KEY (adapter, bssid, moment)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS devices (
                    adapter TEXT, bssid TEXT, label TEXT,
                    PRIMARY KEY (adapter, bssid)
                ) WITHOUT ROWID;
            """)

    def devices(self, adapter):
        with closing(sqlite3.connect(self.path)) as db:
            return dict(db.execute("SELECT bssid, label FROM devices WHERE adapter = ? ORDER BY label", (adapter,)))

    def record(self, adapter, moment, networks, watched):
        samples = {network.bssid: network.rssi for network in networks}
        for bssid in watched:
            samples.setdefault(bssid, None)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany("INSERT INTO signal VALUES (?, ?, ?, ?)",
                           ((adapter, bssid, moment, rssi) for bssid, rssi in samples.items()))
            db.executemany("INSERT OR REPLACE INTO devices VALUES (?, ?, ?)",
                           ((adapter, net.bssid, net.ssid or "Скрытая сеть") for net in networks))

    def samples(self, adapter, bssid, limit=None):
        query = "SELECT moment, rssi FROM signal WHERE adapter = ? AND bssid = ? ORDER BY moment DESC"
        args = (adapter, bssid)
        if limit is not None:
            query += " LIMIT ?"
            args += (limit,)
        with closing(sqlite3.connect(self.path)) as db:
            return list(reversed(db.execute(query, args).fetchall()))
