# windows-mouse-wheel-accelerator
Low effort Win32 program to accelerate mouse wheel with inertia.

> **Note:** "Low effort" means this project was quickly hacked together to solve a personal need.  
> I don't plan to spend much time maintaining it beyond my own use.  
> That said, feel free to create pull requests or fork the project.

## Features

- Accelerated scroll
- Inertia effect for smooth scrolling
- Configurable through json
- Basic game mode detection - automatically disables acceleration in fullscreen Direct3D applications  

## Usage
You can run the program in several ways:

- **Double-click the executable** to launch it with the default settings.
- **Run it via terminal or script** to specify a custom config:
    ```bash
      windows-mouse-wheel-accelerator.exe --config path\to\config.json
    ```
    or using shorthand:
    ```bash
      windows-mouse-wheel-accelerator.exe -c path\to\config.json
    ```
- **Use a shortcut**: Right-click the executable, choose "Create shortcut", then edit the shortcut's Target field to include the --config parameter if needed.

## Startup
To run the program automatically on Windows startup:

1. Press Win + R, type shell:common startup, and hit Enter.
This opens the Startup folder: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
2. Place the .exe file or a configured shortcut into this folder.

The program will now launch automatically each time Windows starts.

## Default Config
Below is the default configuration (used if no config is specified).
Values of ignoredProcesses and ignoredClassPatterns don't have to be specified explicitly, default values are always merged with user's values.
```json
{
    "ignoredProcesses": [
        "virtual pc.exe",
        "startmenuexperiencehost.exe",
        "searchapp.exe",
        "searchui.exe",
        "osk.exe",
        "shellexperiencehost.exe",
        "cortana.exe",
        "textinputhost.exe",
        "lockapp.exe",
        "winlogon.exe",
        "dwm.exe",
        "sihost.exe"
    ],
    // format: <window title>|class
    "ignoredClassPatterns": [
        "Program Manager|Progman",
        "*|MultitaskingViewFrame",
        "Volume Control|Tray Volume",
        "Volume Control|Windows.UI.Core.CoreWindow",
        "*|TaskSwitcherWnd",
        "*|TaskSwitcherOverlayWnd",
        "*|WorkerW",
        "*|Shell_TrayWnd",
        "*|BaseBar",
        "*|#32768",
        "*|XamlExplorerHostIslandWindow",
        "*|TSSHELLWND"
    ],
    "baseMultiplier": 1.0,
    "maxMultiplier": 3.0,
    "resetTimeoutMs": 50,
    "inertiaBaseDecay": 0.88,
    "inertiaThreshold": 0.05,
    "inertiaIntervalMs": 15,
    "minMomentumForInertia": 0.5,
    "inertiaAccumulationFactor": 1.5,
    "maxInertiaMomentum": 9.0
}
```
