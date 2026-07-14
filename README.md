# Veyra Scan

Advanced Minecraft mod and Java runtime scanner focused on cheat detection, deep JAR analysis and clear evidence reporting.

## Download

**[Download Veyra Scan v1.0.0 for Windows](https://github.com/x1eqn/Veyra-Scan/releases/download/v1.0.0/Veyra-Scan-v1.0.0-Windows-x64.exe)**

SHA-256: `027A4539B63D42898225B2E803DA07F2D189775585F4A38C5A7DA23354D25DC5`

The application requests administrator permission when process-memory inspection is required.

## Main features

- Minecraft JAR and mod scanning
- Manual deep JAR analysis
- `javaw.exe` runtime and memory inspection
- MouseTweaks, Freecam and Freelook finder
- Xray, AutoClicker, Auto-Totem and Mace-Swap finder
- Modrinth exact-hash verification
- In-application evidence reports

## Run from source

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Build the Windows executable

Run `build_exe.bat`. The executable will be created under `dist`.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Scanner findings are evidence for manual review, not automatic proof of cheating. Veyra Scan is not affiliated with Mojang, Microsoft or Modrinth.
