# 🧪 Client-Side Manual QA Checklist

Follow these steps to validate the End-User experience before shipping.

## 1. Installation Test
- [ ] **Download**: Place `breakpoint_windows.exe` and `install.ps1` in a clean folder (e.g., `Downloads\Test`).
- [ ] **Execution**: Right-click `install.ps1` -> Run with PowerShell.
- [ ] **Verification**:
    - Folder `C:\Program Files\BreakPoint` exists?
    - File `breakpoint.exe` exists inside?
    - Environment Variable `Path` includes the folder?
- [ ] **CLI Check**: Open a NEW terminal and run `breakpoint --version`.

## 2. Initialization Test
- [ ] Run `breakpoint init`.
- [ ] Verify `breakpoint_config.yaml` is created in the current folder.
- [ ] Run `breakpoint` (no args). It should auto-load the local config.

## 3. License Registration
- [ ] Run `breakpoint register CHECK-KEY`.
- [ ] Verify it says "License Activated".
- [ ] Run `breakpoint`. Verify banner shows License status.

## 4. Update Mechanism
- [ ] Run `breakpoint update`.
- [ ] Verify it connects to GitHub API and prints version info.

## 5. Uninstallation Test
- [ ] Run `uninstall.ps1` as Admin.
- [ ] Verify `C:\Program Files\BreakPoint` is gone.
- [ ] Verify `breakpoint` command no longer works in a new terminal.

## 6. Linux/Mac Smoke Test (Optional)
- [ ] Run `sudo ./install.sh`.
- [ ] Check `which breakpoint`.
- [ ] Run `sudo ./uninstall.sh`.
