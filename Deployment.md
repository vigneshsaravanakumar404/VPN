# Deployment Guide

## Prerequisites

```bash
python -m pip install pyinstaller
```

## Build Executable

### Basic Build

```bash
python -m PyInstaller --onefile --windowed --name="AWS_EC2_VPN" Client/main.py
```

### Build with Icon

```bash
python -m PyInstaller --onefile --windowed --icon=icon.ico --name="AWS_EC2_VPN" Client/main.py
```

## Output

- Executable location: `dist/AWS_EC2_VPN.exe`
- Can be distributed as standalone file
- No Python installation required for end users

## Clean Build Files

```bash
rmdir /s build
rmdir /s __pycache__
del AWS_EC2_VPN.spec
```

## Troubleshooting

- If `pathlib` error: `python -m pip uninstall pathlib`
- If command not found: Use `python -m PyInstaller` instead of `pyinstaller`
