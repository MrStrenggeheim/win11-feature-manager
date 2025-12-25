<#
.SYNOPSIS
    Windows 11 AI & Feature Manager - Control Windows 11 AI features and resource-heavy services
    
.DESCRIPTION
    An interactive PowerShell script to enable/disable Windows 11 AI features, background services,
    and resource-heavy processes. All changes are fully reversible with built-in backup and restore.
    
.PARAMETER DisablePreset
    Apply a preset: 'Safe' (non-essential only) or 'Aggressive' (maximum RAM savings)
    
.PARAMETER EnableAll
    Re-enable all features to Windows defaults
    
.PARAMETER ListFeatures
    List all available features and their current status
    
.PARAMETER BackupOnly
    Create a backup of current settings without making changes
    
.PARAMETER RestoreBackup
    Path to a backup file to restore from
    
.EXAMPLE
    .\Win11FeatureManager.ps1
    
.EXAMPLE
    .\Win11FeatureManager.ps1 -DisablePreset Safe
    
.EXAMPLE
    .\Win11FeatureManager.ps1 -RestoreBackup ".\Backups\backup_20231225_120000.json"

.NOTES
    Author: Windows 11 Feature Manager
    Version: 1.0
    Requires: Windows 11 Home, Administrator privileges
#>

[CmdletBinding()]
param(
    [ValidateSet('Safe', 'Aggressive')]
    [string]$DisablePreset,
    
    [switch]$EnableAll,
    
    [switch]$ListFeatures,
    
    [switch]$BackupOnly,
    
    [string]$RestoreBackup
)

# ============================================
# CONFIGURATION
# ============================================

$Script:Version = "1.0"
$Script:ScriptPath = $PSScriptRoot
$Script:BackupFolder = Join-Path $Script:ScriptPath "Backups"
$Script:LogFolder = Join-Path $Script:ScriptPath "Logs"
$Script:LogFile = Join-Path $Script:LogFolder ("FeatureManager_" + (Get-Date -Format 'yyyyMMdd') + ".log")

# ============================================
# FEATURE DEFINITIONS
# ============================================

$Script:Features = @{
    "Copilot" = @{
        Category = "AI and Copilot"
        Name = "Windows Copilot"
        Description = "Microsoft AI assistant integrated into Windows taskbar"
        Impact = "Removes Copilot button from taskbar, disables Win+C shortcut, stops AI assistant"
        Preset = "Safe"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
                Name = "TurnOffWindowsCopilot"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = $null
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Name = "ShowCopilotButton"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "Recall" = @{
        Category = "AI and Copilot"
        Name = "Windows Recall"
        Description = "AI-powered timeline that captures screenshots of your activity"
        Impact = "Prevents continuous screenshot capture, significant disk/RAM/CPU savings"
        Preset = "Safe"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
                Name = "AllowRecallEnablement"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = $null
            },
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
                Name = "DisableAIDataAnalysis"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = $null
            }
        )
    }
    
    "Cortana" = @{
        Category = "AI and Copilot"
        Name = "Cortana"
        Description = "Voice assistant and search companion"
        Impact = "Disables voice activation, removes Cortana from search"
        Preset = "Safe"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                Name = "AllowCortana"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "Widgets" = @{
        Category = "Widgets and News"
        Name = "Widgets Panel"
        Description = "News, weather, and AI-curated content panel on taskbar"
        Impact = "Removes widget button from taskbar, disables Win+W shortcut, stops background content fetching"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
                Name = "AllowNewsAndInterests"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = $null
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Name = "TaskbarDa"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "Telemetry" = @{
        Category = "Telemetry and Privacy"
        Name = "Diagnostic Telemetry"
        Description = "Windows sends diagnostic and usage data to Microsoft"
        Impact = "Reduces background network activity, CPU usage, and data collection"
        Preset = "Safe"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                Name = "AllowTelemetry"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 3
            },
            @{
                Type = "Service"
                ServiceName = "DiagTrack"
                DisplayName = "Connected User Experiences and Telemetry"
                DisabledStartup = "Disabled"
                EnabledStartup = "Automatic"
            },
            @{
                Type = "Service"
                ServiceName = "dmwappushservice"
                DisplayName = "Device Management WAP Push Service"
                DisabledStartup = "Disabled"
                EnabledStartup = "Manual"
            }
        )
    }
    
    "ActivityHistory" = @{
        Category = "Telemetry and Privacy"
        Name = "Activity History"
        Description = "Tracks and syncs your activity across devices"
        Impact = "Stops activity logging and cloud sync"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                Name = "PublishUserActivities"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = $null
            },
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                Name = "UploadUserActivities"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = $null
            }
        )
    }
    
    "AdvertisingID" = @{
        Category = "Telemetry and Privacy"
        Name = "Advertising ID"
        Description = "Unique identifier used for personalized advertising"
        Impact = "Disables ad personalization tracking"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
                Name = "Enabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "LocationTracking" = @{
        Category = "Telemetry and Privacy"
        Name = "Location Services"
        Description = "System-wide location tracking"
        Impact = "Disables location-based features and tracking (weather, maps still work with manual location)"
        Preset = "Aggressive"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
                Name = "DisableLocation"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = 0
            }
        )
    }
    
    "WebSearch" = @{
        Category = "Search and Suggestions"
        Name = "Web Search in Start Menu"
        Description = "Bing web search results appear in Start menu and taskbar search"
        Impact = "Local search only, faster and cleaner results"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
                Name = "DisableSearchBoxSuggestions"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = 0
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
                Name = "BingSearchEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "SearchHighlights" = @{
        Category = "Search and Suggestions"
        Name = "Search Highlights"
        Description = "AI-curated search suggestions, trending content, and imagery in search"
        Impact = "Cleaner, faster search experience without promotional content"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"
                Name = "IsDynamicSearchBoxEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "CloudSearch" = @{
        Category = "Search and Suggestions"
        Name = "Cloud Content Search"
        Description = "Search results from OneDrive, Outlook, and other cloud services"
        Impact = "Local search only, faster results"
        Preset = "Aggressive"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                Name = "AllowCloudSearch"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "StartMenuSuggestions" = @{
        Category = "Search and Suggestions"
        Name = "Start Menu Recommendations"
        Description = "AI-driven app recommendations in Start menu Recommended section"
        Impact = "Removes suggested/promoted apps from Start menu"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Name = "Start_IrisRecommendations"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "BackgroundApps" = @{
        Category = "Background Services"
        Name = "Background Apps"
        Description = "Apps running in background consuming resources"
        Impact = "Significant RAM and CPU reduction, some apps may not send notifications"
        Preset = "Aggressive"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
                Name = "LetAppsRunInBackground"
                ValueType = "DWord"
                DisabledValue = 2
                EnabledValue = 0
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
                Name = "GlobalUserDisabled"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = 0
            }
        )
    }
    
    "SysMain" = @{
        Category = "Background Services"
        Name = "SysMain (Superfetch)"
        Description = "Preloads frequently used apps into RAM for faster launching"
        Impact = "Frees significant RAM, may slightly slow initial app launches (recommended for SSDs)"
        Preset = "Aggressive"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Service"
                ServiceName = "SysMain"
                DisplayName = "SysMain (Superfetch)"
                DisabledStartup = "Disabled"
                EnabledStartup = "Automatic"
            },
            @{
                Type = "Registry"
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
                Name = "EnableSuperfetch"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 3
            }
        )
    }
    
    "Prefetch" = @{
        Category = "Background Services"
        Name = "Prefetch"
        Description = "Pre-caches boot and application files"
        Impact = "Reduces disk I/O, may slightly affect boot time on HDDs (safe for SSDs)"
        Preset = "Aggressive"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
                Name = "EnablePrefetcher"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 3
            }
        )
    }
    
    "GameDVR" = @{
        Category = "Gaming"
        Name = "Game DVR and Recording"
        Description = "Background game recording and capture features"
        Impact = "Reduces CPU/RAM/GPU overhead during gaming, disables background recording"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
                Name = "AppCaptureEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\System\GameConfigStore"
                Name = "GameDVR_Enabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
                Name = "AllowGameDVR"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = $null
            }
        )
    }
    
    "OneDriveSync" = @{
        Category = "Cloud and Sync"
        Name = "OneDrive Sync"
        Description = "Automatic file synchronization to OneDrive cloud"
        Impact = "Stops background sync, reduces network and CPU usage (manual sync still possible)"
        Preset = "Aggressive"
        RequiresReboot = $true
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
                Name = "DisableFileSyncNGSC"
                ValueType = "DWord"
                DisabledValue = 1
                EnabledValue = 0
            }
        )
    }
    
    "SuggestedApps" = @{
        Category = "Content Delivery"
        Name = "Suggested Apps and Bloatware"
        Description = "Auto-installed promotional apps and suggestions"
        Impact = "Prevents automatic installation of promotional apps"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SilentInstalledAppsEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "ContentDeliveryAllowed"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "PreInstalledAppsEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "OemPreInstalledAppsEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "TipsAndSuggestions" = @{
        Category = "Content Delivery"
        Name = "Tips and Suggestions"
        Description = "Windows tips, welcome experience, and suggestions"
        Impact = "Cleaner notification experience, no promotional tips"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SoftLandingEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SubscribedContent-338389Enabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SubscribedContent-310093Enabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SystemPaneSuggestionsEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
    
    "LockScreenTips" = @{
        Category = "Content Delivery"
        Name = "Lock Screen Tips"
        Description = "Fun facts, tips, and suggestions on the lock screen"
        Impact = "Clean lock screen without promotional content"
        Preset = "Safe"
        RequiresReboot = $false
        Settings = @(
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "RotatingLockScreenOverlayEnabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            },
            @{
                Type = "Registry"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name = "SubscribedContent-338387Enabled"
                ValueType = "DWord"
                DisabledValue = 0
                EnabledValue = 1
            }
        )
    }
}

# ============================================
# LOGGING FUNCTIONS
# ============================================

function Initialize-Logging {
    if (-not (Test-Path $Script:LogFolder)) {
        New-Item -Path $Script:LogFolder -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
    
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage -ForegroundColor Gray }
    }
}

# ============================================
# REGISTRY ELEVATION HELPER
# ============================================

function Set-RegistryValueWithElevation {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$ValueType
    )
    
    # Ensure the path exists first
    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        } catch [System.UnauthorizedAccessException] {
            Write-Log "  Access denied creating path, attempting ownership takeover..." -Level WARNING
            # Need to take ownership of parent path
            $parentPath = Split-Path $Path -Parent
            if (-not (Grant-RegistryAccess -Path $parentPath)) {
                return $false
            }
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
    }
    
    # Try normal approach first
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $ValueType -ErrorAction Stop
        return $true
    } catch [System.UnauthorizedAccessException] {
        Write-Log "  Access denied, attempting ownership takeover..." -Level WARNING
    } catch {
        throw
    }
    
    # Take ownership and grant access
    if (-not (Grant-RegistryAccess -Path $Path)) {
        return $false
    }
    
    # Retry the operation
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $ValueType -ErrorAction Stop
        Write-Log "  Successfully set after taking ownership" -Level SUCCESS
        return $true
    } catch {
        Write-Log "  Failed even after ownership attempt: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Grant-RegistryAccess {
    param(
        [string]$Path
    )
    
    try {
        # Convert PowerShell path to .NET format
        $hive = $Path.Split(':')[0]
        $subKey = $Path.Split(':')[1].TrimStart('\')
        
        $regHive = switch ($hive) {
            "HKLM" { [Microsoft.Win32.RegistryHive]::LocalMachine }
            "HKCU" { [Microsoft.Win32.RegistryHive]::CurrentUser }
            "HKCR" { [Microsoft.Win32.RegistryHive]::ClassesRoot }
            default { 
                Write-Log "  Unsupported registry hive: $hive" -Level ERROR
                return $false 
            }
        }
        
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($regHive, [Microsoft.Win32.RegistryView]::Default)
        
        # Step 1: Take ownership
        $key = $baseKey.OpenSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, 
            [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        
        if ($null -eq $key) {
            Write-Log "  Could not open key for ownership: $Path" -Level ERROR
            $baseKey.Close()
            return $false
        }
        
        $acl = $key.GetAccessControl()
        $admin = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
        $acl.SetOwner($admin)
        $key.SetAccessControl($acl)
        $key.Close()
        
        # Step 2: Grant full control
        $key = $baseKey.OpenSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        
        if ($null -eq $key) {
            Write-Log "  Could not open key for permissions: $Path" -Level ERROR
            $baseKey.Close()
            return $false
        }
        
        $acl = $key.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $admin,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        $key.SetAccessControl($acl)
        $key.Close()
        $baseKey.Close()
        
        Write-Log "  Granted access to: $Path" -Level INFO
        return $true
    } catch {
        Write-Log "  Failed to grant access: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# ============================================
# BACKUP AND RESTORE FUNCTIONS
# ============================================


function Initialize-BackupFolder {
    if (-not (Test-Path $Script:BackupFolder)) {
        New-Item -Path $Script:BackupFolder -ItemType Directory -Force | Out-Null
    }
}

function Get-CurrentSettings {
    $currentSettings = @{}
    
    foreach ($featureKey in $Script:Features.Keys) {
        $feature = $Script:Features[$featureKey]
        $featureSettings = @{
            Name = $feature.Name
            Settings = @()
        }
        
        foreach ($setting in $feature.Settings) {
            $settingData = @{
                Type = $setting.Type
            }
            
            switch ($setting.Type) {
                "Registry" {
                    $settingData.Path = $setting.Path
                    $settingData.Name = $setting.Name
                    $settingData.ValueType = $setting.ValueType
                    
                    try {
                        if (Test-Path $setting.Path) {
                            $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
                            if ($null -ne $value) {
                                $settingData.CurrentValue = $value.$($setting.Name)
                                $settingData.Exists = $true
                            } else {
                                $settingData.Exists = $false
                            }
                        } else {
                            $settingData.Exists = $false
                        }
                    } catch {
                        Write-Log "Failed to read registry $($setting.Path)\$($setting.Name): $($_.Exception.Message)" -Level WARNING
                        $settingData.Exists = $false
                    }
                }
                "Service" {
                    $settingData.ServiceName = $setting.ServiceName
                    try {
                        $svc = Get-Service -Name $setting.ServiceName -ErrorAction SilentlyContinue
                        if ($svc) {
                            $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$($setting.ServiceName)'" -ErrorAction SilentlyContinue
                            if ($wmiSvc) {
                                $settingData.CurrentStartup = $wmiSvc.StartMode
                            }
                            $settingData.CurrentStatus = $svc.Status.ToString()
                            $settingData.Exists = $true
                        } else {
                            $settingData.Exists = $false
                        }
                    } catch {
                        Write-Log "Failed to read service $($setting.ServiceName): $($_.Exception.Message)" -Level WARNING
                        $settingData.Exists = $false
                    }
                }
            }
            
            $featureSettings.Settings += $settingData
        }
        
        $currentSettings[$featureKey] = $featureSettings
    }
    
    return $currentSettings
}

function New-Backup {
    param(
        [string]$BackupName = ""
    )
    
    Initialize-BackupFolder
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    if ($BackupName) {
        $backupFileName = "backup_" + $BackupName + "_" + $timestamp + ".json"
    } else {
        $backupFileName = "backup_" + $timestamp + ".json"
    }
    $backupPath = Join-Path $Script:BackupFolder $backupFileName
    
    Write-Log "Creating backup: $backupFileName" -Level INFO
    
    $backupData = @{
        Timestamp = (Get-Date).ToString("o")
        WindowsVersion = [System.Environment]::OSVersion.Version.ToString()
        WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
        Settings = Get-CurrentSettings
    }
    
    $backupData | ConvertTo-Json -Depth 10 | Set-Content -Path $backupPath -Encoding UTF8
    
    Write-Log "Backup created successfully: $backupPath" -Level SUCCESS
    return $backupPath
}

function Restore-FromBackup {
    param(
        [string]$BackupPath
    )
    
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Backup file not found: $BackupPath" -Level ERROR
        return $false
    }
    
    Write-Log "Restoring from backup: $BackupPath" -Level INFO
    
    # Track success/failure
    $successCount = 0
    $failCount = 0
    $failedItems = @()
    
    try {
        $backupData = Get-Content -Path $BackupPath -Raw | ConvertFrom-Json
        
        foreach ($featureKey in $backupData.Settings.PSObject.Properties.Name) {
            $featureBackup = $backupData.Settings.$featureKey
            
            foreach ($settingBackup in $featureBackup.Settings) {
                if (-not $settingBackup.Exists) {
                    continue
                }
                
                switch ($settingBackup.Type) {
                    "Registry" {
                        if ($settingBackup.Exists -and $null -ne $settingBackup.CurrentValue) {
                            try {
                                if (-not (Test-Path $settingBackup.Path)) {
                                    New-Item -Path $settingBackup.Path -Force | Out-Null
                                }
                                Set-ItemProperty -Path $settingBackup.Path -Name $settingBackup.Name -Value $settingBackup.CurrentValue -Type $settingBackup.ValueType -ErrorAction Stop
                                Write-Log ("Restored: " + $settingBackup.Name + " = " + $settingBackup.CurrentValue) -Level INFO
                                $successCount++
                            } catch {
                                $failCount++
                                $failedItems += $settingBackup.Name
                                Write-Log ("  Failed: " + $settingBackup.Name + " - " + $_.Exception.Message) -Level WARNING
                            }
                        }
                    }
                    "Service" {
                        if ($settingBackup.Exists -and $settingBackup.CurrentStartup) {
                            try {
                                Set-Service -Name $settingBackup.ServiceName -StartupType $settingBackup.CurrentStartup -ErrorAction Stop
                                Write-Log ("Restored service: " + $settingBackup.ServiceName + " to " + $settingBackup.CurrentStartup) -Level INFO
                                $successCount++
                            } catch {
                                $failCount++
                                $failedItems += ("Service: " + $settingBackup.ServiceName)
                                Write-Log ("  Failed service: " + $settingBackup.ServiceName + " - " + $_.Exception.Message) -Level WARNING
                            }
                        }
                    }
                }
            }
        }
        
        # Summary
        $totalCount = $successCount + $failCount
        Write-Host ""
        if ($failCount -eq 0) {
            Write-Log "$successCount/$totalCount settings restored successfully!" -Level SUCCESS
        } else {
            Write-Log "$successCount/$totalCount settings restored successfully." -Level WARNING
            Write-Host ""
            Write-Host "Failed to restore ($failCount):" -ForegroundColor Red
            foreach ($item in $failedItems) {
                Write-Host "  - $item" -ForegroundColor Yellow
            }
        }
        
        return $true
    } catch {
        Write-Log "Failed to restore backup: $_" -Level ERROR
        return $false
    }
}


function Get-BackupList {
    Initialize-BackupFolder
    $backups = Get-ChildItem -Path $Script:BackupFolder -Filter "backup_*.json" | Sort-Object LastWriteTime -Descending
    return $backups
}

# ============================================
# FEATURE STATUS FUNCTIONS
# ============================================

function Get-FeatureStatus {
    param(
        [string]$FeatureKey
    )
    
    $feature = $Script:Features[$FeatureKey]
    if (-not $feature) {
        return "Unknown"
    }
    
    $disabledCount = 0
    $enabledCount = 0
    $totalSettings = 0
    
    foreach ($setting in $feature.Settings) {
        $totalSettings++
        
        switch ($setting.Type) {
            "Registry" {
                try {
                    if (Test-Path $setting.Path) {
                        $currentValue = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
                        if ($null -ne $currentValue) {
                            $value = $currentValue.$($setting.Name)
                            if ($value -eq $setting.DisabledValue) {
                                $disabledCount++
                            } else {
                                $enabledCount++
                            }
                        } else {
                            $enabledCount++
                        }
                    } else {
                        $enabledCount++
                    }
                } catch {
                    $enabledCount++
                }
            }
            "Service" {
                try {
                    $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$($setting.ServiceName)'" -ErrorAction SilentlyContinue
                    if ($wmiSvc) {
                        if ($wmiSvc.StartMode -eq "Disabled") {
                            $disabledCount++
                        } else {
                            $enabledCount++
                        }
                    } else {
                        $totalSettings--
                    }
                } catch {
                    $totalSettings--
                }
            }
        }
    }
    
    if ($totalSettings -eq 0) {
        return "N/A"
    } elseif ($disabledCount -eq $totalSettings) {
        return "Disabled"
    } elseif ($enabledCount -eq $totalSettings) {
        return "Enabled"
    } elseif ($disabledCount -gt 0) {
        return "Partial"
    } else {
        return "Unknown"
    }
}

# ============================================
# FEATURE TOGGLE FUNCTIONS
# ============================================

function Set-Feature {
    param(
        [string]$FeatureKey,
        [bool]$Disable
    )
    
    $feature = $Script:Features[$FeatureKey]
    if (-not $feature) {
        Write-Log "Feature not found: $FeatureKey" -Level ERROR
        return $false
    }
    
    if ($Disable) {
        $action = "Disabling"
    } else {
        $action = "Enabling"
    }
    Write-Log "$action feature: $($feature.Name)" -Level INFO
    
    $success = $true
    
    foreach ($setting in $feature.Settings) {
        try {
            switch ($setting.Type) {
                "Registry" {
                    if ($Disable) {
                        $targetValue = $setting.DisabledValue
                    } else {
                        $targetValue = $setting.EnabledValue
                    }
                    
                    if ($null -eq $targetValue) {
                        if (Test-Path $setting.Path) {
                            Remove-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
                            Write-Log ("  Removed: " + $setting.Path + "\" + $setting.Name) -Level INFO
                        }
                    } else {
                        $result = Set-RegistryValueWithElevation -Path $setting.Path -Name $setting.Name -Value $targetValue -ValueType $setting.ValueType
                        if ($result) {
                            Write-Log ("  Set: " + $setting.Path + "\" + $setting.Name + " = " + $targetValue) -Level INFO
                        } else {
                            $success = $false
                        }
                    }
                }
                "Service" {
                    if ($Disable) {
                        $targetStartup = $setting.DisabledStartup
                    } else {
                        $targetStartup = $setting.EnabledStartup
                    }
                    $svc = Get-Service -Name $setting.ServiceName -ErrorAction SilentlyContinue
                    
                    if ($svc) {
                        if ($Disable) {
                            Stop-Service -Name $setting.ServiceName -Force -ErrorAction SilentlyContinue
                        }
                        Set-Service -Name $setting.ServiceName -StartupType $targetStartup -ErrorAction Stop
                        Write-Log ("  Service " + $setting.ServiceName + ": " + $targetStartup) -Level INFO
                    } else {
                        Write-Log ("  Service not found: " + $setting.ServiceName) -Level WARNING
                    }
                }
            }
        } catch {
            Write-Log "  Failed to configure $($setting.Type) '$($setting.Name)': $($_.Exception.Message)" -Level ERROR
            $success = $false
        }
    }
    
    if ($feature.RequiresReboot) {
        Write-Log "  Note: Reboot required for full effect" -Level WARNING
    }
    
    return $success
}

function Set-AllFeatures {
    param(
        [bool]$Disable,
        [string]$Preset = ""
    )
    
    $targetFeatures = @($Script:Features.Keys)
    
    if ($Preset -eq "Safe") {
        $targetFeatures = @($Script:Features.Keys | Where-Object {
            $Script:Features[$_].Preset -eq "Safe"
        })
    }
    
    foreach ($featureKey in $targetFeatures) {
        Set-Feature -FeatureKey $featureKey -Disable $Disable
    }
}

# ============================================
# UNIFIED INTERACTIVE UI
# ============================================

function Start-UnifiedUI {
    # Build hierarchical list: Categories with their features
    $categories = @($Script:Features.Values | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
    
    # Build navigation items: each item is either a category header or a feature
    $navItems = @()
    foreach ($cat in $categories) {
        # Add category header
        $navItems += @{
            Type = "Category"
            Key = $cat
            Name = $cat
            Category = $cat
        }
        # Add features under this category
        $catFeatures = $Script:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $cat } | Sort-Object Key
        foreach ($f in $catFeatures) {
            $navItems += @{
                Type = "Feature"
                Key = $f.Key
                Name = $f.Value.Name
                Category = $cat
            }
        }
    }
    
    # State tracking
    $selectedIndex = 0
    $pendingStates = @{}  # Track desired states (true=enabled, false=disabled)
    $originalStates = @{}  # Original states for comparison
    
    # Initialize states from current system
    foreach ($key in $Script:Features.Keys) {
        $status = Get-FeatureStatus -FeatureKey $key
        $isEnabled = ($status -ne "Disabled")
        $pendingStates[$key] = $isEnabled
        $originalStates[$key] = $isEnabled
    }
    
    $showFullInfo = $false
    $showBackupMenu = $false
    $backupMenuIndex = 0
    $backupList = @()
    $statusMessage = ""
    $statusColor = "Gray"
    
    function Get-CategoryState {
        param([string]$CategoryName)
        $catFeatures = $Script:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $CategoryName }
        $enabledCount = 0
        $disabledCount = 0
        foreach ($f in $catFeatures) {
            if ($pendingStates[$f.Key]) { $enabledCount++ } else { $disabledCount++ }
        }
        if ($enabledCount -eq 0) { return "Disabled" }
        elseif ($disabledCount -eq 0) { return "Enabled" }
        else { return "Partial" }
    }
    
    function Toggle-Category {
        param([string]$CategoryName)
        $catFeatures = $Script:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $CategoryName }
        $state = Get-CategoryState -CategoryName $CategoryName
        # If any enabled, disable all. If all disabled, enable all.
        $newState = ($state -eq "Disabled")
        foreach ($f in $catFeatures) {
            $pendingStates[$f.Key] = $newState
        }
    }
    
    function Count-PendingChanges {
        $count = 0
        foreach ($key in $Script:Features.Keys) {
            if ($pendingStates[$key] -ne $originalStates[$key]) { $count++ }
        }
        return $count
    }
    
    function Apply-SafePreset {
        foreach ($key in $Script:Features.Keys) {
            if ($Script:Features[$key].Preset -eq "Safe") {
                $pendingStates[$key] = $false
            }
        }
    }
    
    function Apply-AggressivePreset {
        foreach ($key in $Script:Features.Keys) {
            $pendingStates[$key] = $false
        }
    }
    
    function Reset-ToDefaults {
        foreach ($key in $Script:Features.Keys) {
            $pendingStates[$key] = $true
        }
    }
    
    function Draw-MainUI {
        Clear-Host
        $width = 90
        
        # Header
        Write-Host ""
        Write-Host ("=" * $width) -ForegroundColor Cyan
        Write-Host "  WINDOWS 11 FEATURE MANAGER v$($Script:Version)".PadRight($width - 1) -ForegroundColor Cyan
        Write-Host ("=" * $width) -ForegroundColor Cyan
        Write-Host ""
        
        # Calculate visible window (scrolling if needed)
        $maxVisible = 18
        $startIdx = 0
        if ($navItems.Count -gt $maxVisible) {
            $halfWindow = [Math]::Floor($maxVisible / 2)
            if ($selectedIndex -gt $halfWindow) {
                $startIdx = $selectedIndex - $halfWindow
            }
            if ($startIdx + $maxVisible -gt $navItems.Count) {
                $startIdx = $navItems.Count - $maxVisible
            }
            if ($startIdx -lt 0) { $startIdx = 0 }
        }
        $endIdx = [Math]::Min($startIdx + $maxVisible, $navItems.Count)
        
        # Show scroll indicator if needed
        if ($startIdx -gt 0) {
            Write-Host "  ... (scroll up for more)" -ForegroundColor DarkGray
        }
        
        # Feature list
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $item = $navItems[$i]
            $isSelected = ($i -eq $selectedIndex)
            
            if ($item.Type -eq "Category") {
                # Category header
                $catState = Get-CategoryState -CategoryName $item.Key
                
                if ($isSelected) {
                    Write-Host ">" -NoNewline -ForegroundColor Yellow
                } else {
                    Write-Host " " -NoNewline
                }
                
                Write-Host " [" -NoNewline -ForegroundColor DarkGray
                switch ($catState) {
                    "Enabled"  { Write-Host "+" -NoNewline -ForegroundColor Green }
                    "Disabled" { Write-Host "-" -NoNewline -ForegroundColor Red }
                    "Partial"  { Write-Host "~" -NoNewline -ForegroundColor Yellow }
                }
                Write-Host "] " -NoNewline -ForegroundColor DarkGray
                
                if ($isSelected) {
                    Write-Host $item.Name.ToUpper() -ForegroundColor Black -BackgroundColor Yellow
                } else {
                    Write-Host $item.Name.ToUpper() -ForegroundColor Yellow
                }
            } else {
                # Feature item
                $isEnabled = $pendingStates[$item.Key]
                $hasChanged = ($pendingStates[$item.Key] -ne $originalStates[$item.Key])
                $feature = $Script:Features[$item.Key]
                $presetTag = if ($feature.Preset -eq "Safe") { "S" } else { "A" }
                
                if ($isSelected) {
                    Write-Host ">" -NoNewline -ForegroundColor Yellow
                } else {
                    Write-Host " " -NoNewline
                }
                
                Write-Host "    " -NoNewline
                
                # Feature name
                $displayName = $item.Key
                if ($displayName.Length -gt 20) { $displayName = $displayName.Substring(0, 17) + "..." }
                
                if ($isSelected) {
                    Write-Host $displayName.PadRight(20) -NoNewline -ForegroundColor Black -BackgroundColor Yellow
                } elseif ($hasChanged) {
                    Write-Host $displayName.PadRight(20) -NoNewline -ForegroundColor Magenta
                } else {
                    Write-Host $displayName.PadRight(20) -NoNewline -ForegroundColor White
                }
                
                # Preset indicator
                Write-Host " [" -NoNewline -ForegroundColor DarkGray
                if ($presetTag -eq "S") {
                    Write-Host $presetTag -NoNewline -ForegroundColor Green
                } else {
                    Write-Host $presetTag -NoNewline -ForegroundColor Magenta
                }
                Write-Host "] " -NoNewline -ForegroundColor DarkGray
                
                # Status toggle
                if ($isEnabled) {
                    Write-Host " ON " -NoNewline -ForegroundColor Black -BackgroundColor Green
                    Write-Host " off" -NoNewline -ForegroundColor DarkGray
                } else {
                    Write-Host " on " -NoNewline -ForegroundColor DarkGray
                    Write-Host " OFF" -NoNewline -ForegroundColor Black -BackgroundColor Red
                }
                
                # Change indicator
                if ($hasChanged) {
                    Write-Host " *" -ForegroundColor Magenta
                } else {
                    Write-Host ""
                }
            }
        }
        
        # Show scroll indicator if needed
        if ($endIdx -lt $navItems.Count) {
            Write-Host "  ... (scroll down for more)" -ForegroundColor DarkGray
        }
        
        Write-Host ""
        Write-Host ("-" * $width) -ForegroundColor DarkGray
        
        # Info panel
        $selectedItem = $navItems[$selectedIndex]
        if ($selectedItem.Type -eq "Feature") {
            $feature = $Script:Features[$selectedItem.Key]
            Write-Host " INFO: " -NoNewline -ForegroundColor Cyan
            Write-Host $feature.Name -ForegroundColor White
            
            if ($showFullInfo) {
                Write-Host "  Category:    " -NoNewline -ForegroundColor DarkCyan
                Write-Host $feature.Category -ForegroundColor Gray
                Write-Host "  Preset:      " -NoNewline -ForegroundColor DarkCyan
                Write-Host $feature.Preset -ForegroundColor $(if ($feature.Preset -eq "Safe") { "Green" } else { "Magenta" })
                Write-Host "  Reboot:      " -NoNewline -ForegroundColor DarkCyan
                Write-Host $(if ($feature.RequiresReboot) { "Required" } else { "Not required" }) -ForegroundColor Gray
                Write-Host "  Description: " -NoNewline -ForegroundColor DarkCyan
                Write-Host $feature.Description -ForegroundColor Gray
                Write-Host "  Impact:      " -NoNewline -ForegroundColor DarkCyan
                Write-Host $feature.Impact -ForegroundColor Gray
            } else {
                # Compact: just impact
                $impactText = $feature.Impact
                if ($impactText.Length -gt 75) { $impactText = $impactText.Substring(0, 72) + "..." }
                Write-Host "  " -NoNewline
                Write-Host $impactText -ForegroundColor Gray
                Write-Host "  (Press I for full details)" -ForegroundColor DarkGray
            }
        } else {
            # Category selected
            Write-Host " INFO: " -NoNewline -ForegroundColor Cyan
            Write-Host "Category - $($selectedItem.Name)" -ForegroundColor Yellow
            $catFeatures = @($Script:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $selectedItem.Key })
            Write-Host "  Contains $($catFeatures.Count) features. Toggle to enable/disable all." -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host ("-" * $width) -ForegroundColor DarkGray
        
        # Pending changes count
        $changeCount = Count-PendingChanges
        if ($changeCount -gt 0) {
            Write-Host " PENDING CHANGES: $changeCount " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
            Write-Host " (Press Enter to apply, Esc to discard)" -ForegroundColor Yellow
        } else {
            Write-Host " No pending changes" -ForegroundColor DarkGray
        }
        
        # Status message
        if ($statusMessage) {
            Write-Host ""
            Write-Host " $statusMessage" -ForegroundColor $statusColor
        }
        
        Write-Host ""
        Write-Host ("-" * $width) -ForegroundColor DarkGray
        
        # Hotkey legend
        Write-Host " CONTROLS:" -ForegroundColor Cyan
        Write-Host "  [Up/Down] Navigate   [Left/Right/Space] Toggle   [Enter] Apply   [Esc] Exit" -ForegroundColor Gray
        Write-Host "  [S] Safe Preset   [A] Aggressive   [R] Reset Defaults   [B] Backup   [L] Load Backup   [I] Info" -ForegroundColor Gray
    }
    
    function Draw-BackupMenu {
        Clear-Host
        Write-Host ""
        Write-Host "=================================================================================" -ForegroundColor Cyan
        Write-Host "                              SELECT BACKUP TO RESTORE                          " -ForegroundColor Cyan
        Write-Host "=================================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        if ($backupList.Count -eq 0) {
            Write-Host "  No backups found." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key to return..." -ForegroundColor Gray
            return
        }
        
        for ($i = 0; $i -lt $backupList.Count; $i++) {
            $backup = $backupList[$i]
            if ($i -eq $backupMenuIndex) {
                Write-Host "> " -NoNewline -ForegroundColor Yellow
                Write-Host $backup.Name -NoNewline -ForegroundColor Black -BackgroundColor Yellow
                Write-Host " - $($backup.LastWriteTime)" -ForegroundColor Yellow
            } else {
                Write-Host "  $($backup.Name) - $($backup.LastWriteTime)" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
        Write-Host "  [Enter] Restore   [Esc] Cancel" -ForegroundColor Gray
    }
    
    # Main loop
    $done = $false
    
    while (-not $done) {
        if ($showBackupMenu) {
            Draw-BackupMenu
        } else {
            Draw-MainUI
        }
        
        $keyInfo = [Console]::ReadKey($true)
        $statusMessage = ""
        
        if ($showBackupMenu) {
            # Backup menu navigation
            switch ($keyInfo.Key) {
                "UpArrow" {
                    if ($backupMenuIndex -gt 0) { $backupMenuIndex-- }
                }
                "DownArrow" {
                    if ($backupMenuIndex -lt $backupList.Count - 1) { $backupMenuIndex++ }
                }
                "Enter" {
                    if ($backupList.Count -gt 0) {
                        $selectedBackup = $backupList[$backupMenuIndex]
                        New-Backup -BackupName "before_restore" | Out-Null
                        Restore-FromBackup -BackupPath $selectedBackup.FullName | Out-Null
                        # Refresh states
                        foreach ($key in $Script:Features.Keys) {
                            $status = Get-FeatureStatus -FeatureKey $key
                            $isEnabled = ($status -ne "Disabled")
                            $pendingStates[$key] = $isEnabled
                            $originalStates[$key] = $isEnabled
                        }
                        $statusMessage = "Backup restored successfully!"
                        $statusColor = "Green"
                    }
                    $showBackupMenu = $false
                }
                "Escape" {
                    $showBackupMenu = $false
                }
                default {
                    if ($backupList.Count -eq 0) {
                        $showBackupMenu = $false
                    }
                }
            }
        } else {
            # Main UI navigation
            switch ($keyInfo.Key) {
                "UpArrow" {
                    if ($selectedIndex -gt 0) { $selectedIndex-- }
                }
                "DownArrow" {
                    if ($selectedIndex -lt $navItems.Count - 1) { $selectedIndex++ }
                }
                "LeftArrow" {
                    $item = $navItems[$selectedIndex]
                    if ($item.Type -eq "Category") {
                        Toggle-Category -CategoryName $item.Key
                    } else {
                        $pendingStates[$item.Key] = $true  # Enable
                    }
                }
                "RightArrow" {
                    $item = $navItems[$selectedIndex]
                    if ($item.Type -eq "Category") {
                        Toggle-Category -CategoryName $item.Key
                    } else {
                        $pendingStates[$item.Key] = $false  # Disable
                    }
                }
                "Spacebar" {
                    $item = $navItems[$selectedIndex]
                    if ($item.Type -eq "Category") {
                        Toggle-Category -CategoryName $item.Key
                    } else {
                        $pendingStates[$item.Key] = -not $pendingStates[$item.Key]
                    }
                }
                "Enter" {
                    # Apply changes
                    $changeCount = Count-PendingChanges
                    if ($changeCount -gt 0) {
                        Clear-Host
                        Write-Host ""
                        Write-Host "Applying $changeCount changes..." -ForegroundColor Cyan
                        Write-Host ""
                        
                        New-Backup -BackupName "before_changes" | Out-Null
                        
                        foreach ($key in $Script:Features.Keys) {
                            if ($pendingStates[$key] -ne $originalStates[$key]) {
                                $disable = -not $pendingStates[$key]
                                Set-Feature -FeatureKey $key -Disable $disable
                            }
                        }
                        
                        # Update original states
                        foreach ($key in $Script:Features.Keys) {
                            $originalStates[$key] = $pendingStates[$key]
                        }
                        
                        $statusMessage = "Changes applied! Reboot may be required."
                        $statusColor = "Green"
                        
                        Write-Host ""
                        Write-Host "Press any key to continue..." -ForegroundColor Gray
                        [Console]::ReadKey($true) | Out-Null
                    }
                }
                "Escape" {
                    $changeCount = Count-PendingChanges
                    if ($changeCount -gt 0) {
                        # Reset pending to original
                        foreach ($key in $Script:Features.Keys) {
                            $pendingStates[$key] = $originalStates[$key]
                        }
                        $statusMessage = "Changes discarded."
                        $statusColor = "Yellow"
                    } else {
                        $done = $true
                    }
                }
                "S" {
                    Apply-SafePreset
                    $statusMessage = "Safe preset applied (staged). Press Enter to apply."
                    $statusColor = "Green"
                }
                "A" {
                    Apply-AggressivePreset
                    $statusMessage = "Aggressive preset applied (staged). Press Enter to apply."
                    $statusColor = "Magenta"
                }
                "R" {
                    Reset-ToDefaults
                    $statusMessage = "Reset to Windows defaults (staged). Press Enter to apply."
                    $statusColor = "Cyan"
                }
                "B" {
                    $backupPath = New-Backup -BackupName "manual"
                    $statusMessage = "Backup created: $backupPath"
                    $statusColor = "Green"
                }
                "L" {
                    $backupList = @(Get-BackupList)
                    $backupMenuIndex = 0
                    $showBackupMenu = $true
                }
                "I" {
                    $showFullInfo = -not $showFullInfo
                }
                "Q" {
                    $done = $true
                }
            }
        }
    }
    
    Clear-Host
    Write-Host ""
    Write-Host "Goodbye! Remember to reboot if you made changes that require it." -ForegroundColor Cyan
    Write-Host ""
}

# ============================================
# COMMAND-LINE HANDLING
# ============================================

Initialize-Logging

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# Check Windows version
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 22000)) {
    Write-Host "ERROR: This script requires Windows 11 (build 22000 or later)." -ForegroundColor Red
    exit 1
}

# Handle command-line parameters
if ($ListFeatures) {
    # Quick text list for CLI usage
    $categories = @($Script:Features.Values | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)
    foreach ($cat in $categories) {
        Write-Host "`n--- $cat ---" -ForegroundColor Yellow
        $catFeatures = $Script:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $cat }
        foreach ($f in $catFeatures) {
            $status = Get-FeatureStatus -FeatureKey $f.Key
            $preset = if ($f.Value.Preset -eq "Safe") { "[S]" } else { "[A]" }
            Write-Host "  $($f.Key.PadRight(22)) $preset [$status]" -ForegroundColor Gray
        }
    }
    exit 0
}

if ($BackupOnly) {
    $backupPath = New-Backup
    Write-Host "Backup created: $backupPath" -ForegroundColor Green
    exit 0
}

if ($RestoreBackup) {
    if (Restore-FromBackup -BackupPath $RestoreBackup) {
        Write-Host "Backup restored successfully. Reboot recommended." -ForegroundColor Green
    } else {
        Write-Host "Failed to restore backup." -ForegroundColor Red
        exit 1
    }
    exit 0
}

if ($EnableAll) {
    New-Backup -BackupName "before_enable_all" | Out-Null
    Set-AllFeatures -Disable $false
    Write-Host "All features enabled. Reboot recommended." -ForegroundColor Green
    exit 0
}

if ($DisablePreset) {
    New-Backup -BackupName ("before_" + $DisablePreset + "_preset") | Out-Null
    Set-AllFeatures -Disable $true -Preset $DisablePreset
    Write-Host "$DisablePreset preset applied. Reboot recommended." -ForegroundColor Green
    exit 0
}

# Default: Launch unified interactive UI
Start-UnifiedUI
