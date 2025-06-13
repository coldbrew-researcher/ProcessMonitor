# 🛡️ MiniAV – Lightweight Behavior-Based Malware Detection System

**MiniAV** is a lightweight, modular malware detection system that monitors system behavior at both user and kernel levels. It integrates with **LM Studio** to receive security insights and detection recommendations based on collected behavioral signals.

* * *

## 📁 Folder Structure: `ProcessMonitor`

| Folder / Component | Description |
| --- | --- |
| `FileFilterSys` | Kernel-mode driver to monitor and filter file access and creation events. |
| `Monitor` | DLL using API hooking (Detour) to intercept sensitive WinAPI calls. |
| `processMonitorsys` | Kernel-mode driver for monitoring process creation, DLL loading, and registry changes. |
| `ProcessMonitor` | Main user-mode executable. Collects data from all components and interacts with LM Studio. |

<br>

<br>

* * *

## 🚀 Getting Started

### 1\. Build Components

- Build `FileFilterSys.sys` and `processMonitorsys.sys` using Visual Studio (Driver Kit required).
- Build `Monitor.dll` with proper API detour hooks.
- Build `ProcessMonitor.exe` – the main application.

### 2\. Install and Run

```
sc create ProcessMonitor type= kernel binPath= "Path2\ProcessMonitorSys.sys"
sc create FileMonitor type= kernel binPath= "Path2\FileFilterSys.sys"
reg add HKLM\SYSTEM\CurrentControlSet\Services\FileMonitor\Instances /v DefaultInstance /t REG_SZ /d MyFileFilterInstance
reg add HKLM\SYSTEM\CurrentControlSet\Services\FileMonitor\Instances\MyFileFilterInstance /v Altitude /t REG_SZ /d 385201
reg add HKLM\SYSTEM\CurrentControlSet\Services\FileMonitor\Instances\MyFileFilterInstance /v Flags /t REG_DWORD /d 0
# Launch main MiniAV executable
ProcessMonitor.exe
```

> ⚠️ Admin rights are required for driver installation and process monitoring.
> 
> <br>

* * *

## 🧠 LM Studio Integration

MiniAV integrates with **LM Studio** using the **phi-3.1-mini-128k-instruct** model. Behavioral data collected at runtime is sent to LM Studio along with prompt **“You are a cybersecurity analyst. Analyze the list of file paths and registry keys and summarize all findings in about 20 words. Do not use backslashes, quotes, or line breaks in the output.”** to receive intelligent analysis and detection recommendations.

* * *

## 🛠️ Requirements

- Windows 10/11 (64-bit)
- Visual Studio 2019 or later
- Windows Driver Kit (WDK)
- Administrator privileges
- LM Studio installed and running (local or remote)

* * *

## ⚠️ Disclaimer

This is a **research-focused** prototype and should not be used in production environments. Driver signing enforcement may need to be disabled for development/testing.

<br>