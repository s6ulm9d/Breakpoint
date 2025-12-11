# 🧪 Breakpoint Enterprise User Guide

**BREAKPOINT (Enterprise Edition)** is designed for zero-configuration deployment. 

---

## 📦 1. Installation

### Windows (One-Click)
1.  Download **`breakpoint-installer.exe`** from the [Releases Page](https://github.com/soulmad/breakpoint/releases).
2.  Double-click the installer.
3.  Follow the prompt (Admin access required).
    - It installs to `C:\Program Files\BreakPoint`.
    - It configures your PATH automatically.

### Linux / macOS
Download and install the binary (Example for Linux):
```bash
wget https://github.com/soulmad/breakpoint/releases/latest/download/breakpoint-linux-x86_64
chmod +x breakpoint-linux-x86_64
sudo mv breakpoint-linux-x86_64 /usr/local/bin/breakpoint
```

### Verification
Run:
```bash
breakpoint --version
```

---

## 🚀 2. Quick Start (Zero Config)

No initialization or setup is required. The tool auto-detects your environment.

### Run a Scan
Simply provide the target URL:
```bash
breakpoint https://target.com
```

### Advanced Scan
```bash
breakpoint --base-url https://target.com --aggressive
```

---

## � 3. Configuration & Reports

### Configuration
Breakpoint manages its own configuration in your AppData folder:
- **Windows**: `%LOCALAPPDATA%\BreakPoint\config.yaml`
- **Linux/Mac**: `~/.config/breakpoint/config.yaml`

You can edit this file to permanently change default behaviors.

### Reports
By default, comprehensive HTML reports are saved to your Documents folder:
- **Location**: `Documents/BreakPoint/Reports/audit_<TIMESTAMP>.html`

You can verify this in the scan output:
> `[*] Report will be saved to: ...`

---

## 🏢 4. Enterprise Features

### License Registration
Unlock full capability (if applicable):
```bash
breakpoint register <YOUR-LICENSE-KEY>
```

### Updates
Check for the latest engine version:
```bash
breakpoint update
```

---

## �️ 5. Uninstallation

### Windows
Delete the folder `C:\Program Files\BreakPoint`. Remove the PATH entry if desired.

### Linux / macOS
```bash
sudo rm /usr/local/bin/breakpoint
```
