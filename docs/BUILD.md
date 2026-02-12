# 🏗️ Building BREAKPOINT Binaries

This guide explains how to compile `BREAKPOINT` into a standalone binary (exe/elf) using standard `PyInstaller` logic. The output is a single file that can run on systems **without Python installed**.

---

## 🔧 Prerequisites

1.  **Python 3.8+** Installed.
2.  **Git** Installed.
3.  **Virtual Environment** (Highly Recommended).

---

## 🚀 Build Instructions

### 1. Setup Environment
Clone the repository and install build dependencies.

```bash
git clone https://github.com/soulmad/breakpoint.git
cd breakpoint

# Create venv (Mac/Linux)
python3 -m venv .venv
source .venv/bin/activate

# Create venv (Windows)
python -m venv .venv
.venv\Scripts\activate

# Install Project + Build Tools
pip install .
pip install pyinstaller
```

### 2. Run Build Script
We provide a helper script to configure PyInstaller automatically (including correct hidden imports).

```bash
python build_binary.py
```

### 3. Verify Output
The compiled binary will be in the `dist/` folder.

- **Windows**: `dist\breakpoint.exe`
- **Linux/Mac**: `dist/breakpoint`

Run it:
```bash
./dist/breakpoint --help
```

---

## 📦 Installation for End-Users

Once built, you can ship the binary file to end-users. They do not need Python or Pip.

### Windows Users
1.  Copy `breakpoint.exe` to a folder, e.g., `C:\Tools\`.
2.  Add `C:\Tools\` to your System `PATH` environment variable.
3.  Run from any command prompt:
    ```cmd
    breakpoint --help
    ```

### Linux / macOS Users
1.  Copy the binary to a bin directory:
    ```bash
    sudo cp dist/breakpoint /usr/local/bin/breakpoint
    sudo chmod +x /usr/local/bin/breakpoint
    ```
2.  Run from any terminal:
    ```bash
    breakpoint --help
    ```

---

## ⚠️ Known Build Notes

- **Antivirus**: PyInstaller binaries (especially single-file ones) are sometimes flagged as false positives by Windows Defender. You may need to whitelist the `dist/` folder.
- **Cross-Compilation**: PyInstaller **does not** support cross-compilation (e.g., you cannot build a Windows .exe from Linux). You must run the build script on the target OS (or use CI/CD runners like GitHub Actions).
