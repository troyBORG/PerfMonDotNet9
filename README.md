# PerfMonDotNet9
[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Drop-in .NET 9 replacement** for the original [perf_mon_server.py](https://github.com/Anomalous/AnomalousNeosExperiments/blob/master/PerformanceMonitor/server/perf_mon_server.py) used with **Resonite** (formerly NeosVR).  
Serves identical CSV-formatted performance data via a simple HTTP server.

---

## ✨ What’s new
- **Launch arg `--procs`** to filter **CPU%**/**core%** to specific apps**.

**Windows (PowerShell):**
```powershell
# IMPORTANT: quote the list because semicolons separate commands in PowerShell
.\PerfMonDotNet9.exe --procs 'Resonite;Renderite.Host;Renderite.Renderer'
```

**Linux (Resonite runs as dotnet Resonite.dll):**
```bash
./PerfMonDotNet9 --procs 'Resonite.dll'
```

---

## 🧩 Features

- 1 : 1 data format match with the Python version:
  ```
  cpu_percent, core_percent, mem_total, mem_avail, total_bytes_sent, total_bytes_received, bps_sent, bps_received
  ```
- `/perf-stats` endpoint optimized for lightweight LogiX/ProtoFlux GET parsing.  
- `/reset-counters` endpoint to reset network usage counters.  
- `/index.html` optional (for local test UI).  
- Works on **Windows** and **Linux** — no dependency on `psutil`.  
- Uses **.NET 9 minimal API** for high performance.  

---

## ⚙️ Build

### Windows
```powershell
dotnet build -f net9.0-windows -c Release
```

### Linux
```bash
dotnet build -f net9.0 -c Release
```

### Single-file publish (optional)
```bash
dotnet publish -c Release -r linux-x64 --self-contained false -o out
```
The compiled binary will appear in `/out/PerfMonDotNet9`.

---

## ▶️ Run

### Default port 8082
```bash
dotnet run
```

Or run your built binary directly:
```bash
./PerfMonDotNet9
```

### Example endpoints
| Endpoint | Description |
|-----------|--------------|
| `/` | Redirects to `/index.html` |
| `/index.html` | Serves static HTML (if present) |
| `/perf-stats` | Returns comma-separated stats |
| `/reset-counters` | Resets bandwidth counters |

---

## 🖥️ Example Output

```
12.4, 18.7, 17179869184, 9264179200, 1073741824, 2147483648, 53248.7, 73114.5
```

Which corresponds to:
- Overall CPU %
- Max single-core %
- Total RAM (B)  
- Available RAM (B)  
- Total bytes sent/received since start (system)  
- Current upload/download B/s (system)  

---

## 🧾 Systemd Service (Linux)

Example `/etc/systemd/system/perfmon.service`:
```ini
[Unit]
Description=Resonite Performance Monitor
After=network.target

[Service]
Type=simple
User=steam
WorkingDirectory=/home/steam/.steam/steam/steamapps/common/Resonite/Headless
ExecStart=/home/steam/.steam/steam/steamapps/common/Resonite/Headless/PerfMonDotNet9
Restart=always

[Install]
WantedBy=multi-user.target
```

**Filter CPU/Core to Resonite only (optional):**
```ini
ExecStart=/home/steam/.steam/steam/steamapps/common/Resonite/Headless/PerfMonDotNet9 --procs 'Resonite.dll'
```

Enable & start:
```bash
sudo systemctl enable perfmon.service
sudo systemctl start perfmon.service
```

---

## 🧠 Notes

- Identical CSV and endpoint as the Python `psutil` version (`/perf-stats`).  
- `--procs` only affects CPU and core load; memory and network stay system-wide for portability.  
- Automatically detects Windows/Linux counters.  
- Can be queried from Resonite’s built-in WebRequest node.

---

## 📜 License
MIT License (same as upstream AnomalousNeosExperiments).
