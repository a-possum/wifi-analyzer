# Wi-Fi Analyzer for Windows

[Инструкция на русском](README.md)

**The app has no regional lock.** It does not check your country, IP address, or Windows region to enable features. Available channels and 6 GHz support depend on local regulations, Windows, the adapter, its driver, and router settings.

Wi-Fi Analyzer is a Windows 10/11 x64 desktop app built with the Windows Native Wi-Fi API, PySide6, PyQtGraph, and SQLite. A Wi-Fi adapter can scan while Ethernet provides internet access. Scanning works without joining a Wi-Fi network, without internet access, and without monitor mode.

## Download and run

1. Open **Releases** on GitHub and download `WiFiAnalyzer.exe` under **Assets**. If you built the app yourself, find it at `dist/WiFiAnalyzer.exe`.
2. Run the EXE. The packaged app includes its Python runtime.
3. Select your Wi-Fi adapter in the top bar. The first scan usually appears within a few seconds. If you connect an adapter after startup, click **Обновить адаптеры** (Refresh adapters).

The interface is currently in Russian. This guide includes the tab labels as displayed in the app.

### Troubleshooting

- **Access denied.** Open **Settings → Privacy & security → Location** on Windows 11. Enable Location services and allow desktop apps to access location, then refresh the adapter list. [Microsoft Wi-Fi access and location changes](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)
- **No adapter listed.** Check airplane mode, make sure Windows recognizes and enables the adapter, and verify that the **WLAN AutoConfig** service (`WlanSvc`) is running.
- **No IPv4 address for diagnostics.** Join a Wi-Fi network using the selected adapter, then restart the ping session. The adapter can still scan while disconnected.

## Use the analyzer

| Tab | What to do |
| --- | --- |
| **Сети** (Networks) | Sort by clicking a column header. Filter by band, channel, RSSI, or security. Search by SSID, BSSID, or vendor. Export the filtered snapshot to CSV. |
| **График каналов** (Channel Graph) | Select 2.4, 5, or 6 GHz. Zoom with the mouse wheel and select an access point in the plot, dropdown, or table. The connected BSSID is turquoise. A circle marks unknown width, while shading marks overlaps between known nominal channel spans. |
| **Монитор RSSI** (Signal Monitor) | Select an access point or double-click its network row. The chart and min/max/mean statistics cover the latest 720 records. CSV includes the selected BSSID's full history for that adapter. A successful scan that misses the selected BSSID leaves an RSSI gap. |
| **Channel Advisor** | Select a band and enter the channel numbers your router makes available, for example `36,40,44,48`. Review the ranked 20, 40, or 80 MHz blocks, overlap counts, and confidence levels. Compare scores within the same width. |
| **Диагностика** (Diagnostics) | Connect the selected adapter to Wi-Fi, optionally enter an external IPv4 address, and click **Запустить ping** (Start ping). Review gateway and external latency, unanswered probes, recovery, and nearby RSSI readings. Export the session to CSV. |

The diagnostics session uses the selected adapter's source IPv4 address. A gateway reply paired with a failed external probe suggests a problem beyond the gateway or ICMP filtering. A failed gateway probe can indicate a local connectivity issue or filtering. Pause active scans to measure latency without scan traffic. Restart the ping session after a network configuration change so it refreshes the address and gateway. [Microsoft IcmpSendEcho2Ex](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex)

## Channel widths and recommendations

Native Wi-Fi reports the frequency on which the Beacon or Probe Response was received. The analyzer shows that frequency separately from the center of the advertised operating channel. It parses HT, VHT, HE, and EHT Operation elements when the driver supplies them. It recognizes 20, 40, 80, and 160 MHz, as well as 80+80 MHz and nominal 320 MHz. Missing or inconsistent operation fields appear as **Не определено** (Unknown). With EHT puncturing, the plot shows the nominal span. [Microsoft WLAN_BSS_ENTRY](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry)

The advisor sums neighboring access points' relative signal powers weighted by how much of the candidate band they overlap. If a neighbor's width is unknown, its received frequency contributes only when it lies inside the candidate block, and confidence drops. The connected BSSID is excluded. The scan observes access points and their advertised operating parameters. Airtime use, client activity, and non-Wi-Fi interference remain unmeasured. Check DFS and channel availability on your router before applying a result.

## Local data and optional vendor database

Settings, SQLite history, and rotating logs are stored in `%LOCALAPPDATA%\WiFiAnalyzer`. The app sends no telemetry. External ICMP probes run only when you provide an external address and start diagnostics. To enable vendor lookup, save an IEEE MA-L CSV as `oui.csv` in that directory and restart the app. It must include the columns `Assignment` and `Organization Name`.

## Run from source, test, and build

Clone or download the repository, install Python 3.12 x64, then open PowerShell in the project directory.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
& .\.venv\Scripts\python.exe main.py
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\build.ps1 -Python .\.venv\Scripts\python.exe
```

PyInstaller produces `dist/WiFiAnalyzer.exe`. The Windows 11 x64 build was tested with Intel Wi-Fi 6 AX201 and active Ethernet. The EXE stored 21 real samples while Wi-Fi was disconnected. All five tabs were exercised using live scan results, and the native ICMP call was tested on loopback. Windows 10, 6 GHz scanning, and ping through an associated Wi-Fi access point still need hardware verification.
