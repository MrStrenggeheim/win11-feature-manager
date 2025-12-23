# Windows 11 Feature Manager

A PowerShell script to manage Windows 11 AI features, background services, and resource-heavy processes. All changes are fully reversible with built-in backup and restore functionality.

## Features

- **20+ Configurable Features** across 9 categories:
  - AI & Copilot (Copilot, Recall, Cortana)
  - Widgets & News
  - Telemetry & Privacy
  - Search & Suggestions
  - Background Services
  - Gaming
  - Cloud & Sync
  - Content Delivery

- **Interactive Arrow-Key Navigation** - Single unified UI with keyboard controls
- **Preset Modes** - Safe (non-essential only) or Aggressive (maximum savings)
- **Full Reversibility** - Automatic backups before any changes
- **Staged Changes** - Preview changes before applying

## Requirements

- Windows 11 (Build 22000+)
- PowerShell 5.1 or later
- Administrator privileges

## Usage

### Interactive Mode (Recommended)

```powershell
# Right-click PowerShell → Run as Administrator
.\Win11FeatureManager.ps1
```

### Controls

| Key | Action |
|-----|--------|
| ↑ / ↓ | Navigate through features |
| ← / → | Set Enabled / Disabled |
| Space | Toggle current item |
| Enter | Apply all pending changes |
| Esc | Discard changes / Exit |
| S | Apply Safe preset |
| A | Apply Aggressive preset |
| R | Reset to Windows defaults |
| B | Create backup |
| L | Load/restore backup |
| I | Toggle full info panel |

### Command-Line Options

```powershell
# List all features and their status
.\Win11FeatureManager.ps1 -ListFeatures

# Apply Safe preset (non-essential features only)
.\Win11FeatureManager.ps1 -DisablePreset Safe

# Apply Aggressive preset (all features)
.\Win11FeatureManager.ps1 -DisablePreset Aggressive

# Re-enable all features
.\Win11FeatureManager.ps1 -EnableAll

# Create backup only
.\Win11FeatureManager.ps1 -BackupOnly

# Restore from specific backup
.\Win11FeatureManager.ps1 -RestoreBackup ".\Backups\backup_20231225_120000.json"
```

## Presets

### Safe Preset `[S]`
Disables non-essential features that have minimal impact on functionality:
- Copilot, Recall, Cortana
- Widgets Panel
- Telemetry, Activity History, Advertising ID
- Web Search, Search Highlights
- Start Menu Recommendations
- Game DVR
- Suggested Apps, Tips, Lock Screen Tips

### Aggressive Preset `[A]`
Disables all features for maximum resource savings:
- Everything in Safe preset, plus:
- Location Services
- Cloud Search
- Background Apps
- SysMain (Superfetch)
- Prefetch
- OneDrive Sync

## Backup & Restore

Backups are automatically created before any changes and stored in the `.\Backups\` folder as JSON files. Each backup contains:
- Timestamp
- Windows version
- All registry values and service states

## Logs

All operations are logged to `.\Logs\FeatureManager_YYYYMMDD.log`

## Limitations

- Some policy-based registry keys may require ownership changes on Windows 11 Home
- A reboot is required for some features to take full effect
- Windows Updates may reset some settings

## License

MIT License - Feel free to modify and distribute.
