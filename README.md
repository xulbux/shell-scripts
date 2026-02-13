# Shell Scripts

All of my different Bash, Batch and PowerShell scripts.

## win11_sandbox_startup.ps1

> [!NOTE]
> Big thanks to **[@ThioJoe](https://github.com/ThioJoe)** for providing the **[original scripts](https://github.com/ThioJoe/Windows-Sandbox-Tools/tree/main)** which I combined and modified to create this script.

This script is supposed to be run after a fresh start of a Windows 11 Sandbox VM.

The script will configure the following:
* **General Tweaks:**
  - apply MSI package install performance fix
  - set the execution policy to allow running scripts
* **Dark Theme:**
  - set system to dark mode
  - set dark wallpaper
* **Windows Explorer:**
  - show file extensions
  - show hidden files
  - add `Open PowerShell/CMD Here` to context menu
  - add `New Text Document` to context menu
  - add `New PowerShell Script` to context menu
* **Microsoft Store:**
  - download and install Microsoft Store and all dependencies
  - configure region settings for Store compatibility
* **WinGet:**
  - download and install WinGet (*Windows Package Manager*)
  - install WinGet dependencies
  - configure WinGet sources

### Parameters

- `-debugSaveFiles` - Save debug logs and XML requests/responses
- `-noDownload` - Skip downloading packages (useful for testing)
- `-noInstall` - Skip installing packages (useful for testing)
- `-removeMsStoreAsSource` - Remove Microsoft Store as a WinGet source after installation

Run the script with the following command in a PowerShell (*opened **as Administrator** in the directory where the script is located*):
```powershell
powershell -ExecutionPolicy Bypass -File "./Win11_Sandbox_startup.ps1"
```
