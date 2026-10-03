# Tasklet Kernel Driver Management Script
# Requires Administrator privileges

param(
    [ValidateSet("status", "install", "uninstall", "start", "stop", "testsign")]
    [string]$Action = "status",
    [string]$DriverPath = "driver\bin\Debug\TaskletTelemetry.sys"
)

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TASKLET // KERNEL DRIVER TELEMETRY CONTROLLER" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

$ServiceName = "TaskletTelemetry"

switch ($Action) {
    "status" {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Service '$ServiceName': " -NoNewline
            Write-Host "$($svc.Status)" -ForegroundColor ($svc.Status -eq "Running" ? "Green" : "Yellow")
        } else {
            Write-Host "Service '$ServiceName' is NOT registered." -ForegroundColor Yellow
        }

        $devicePath = "\\.\TaskletTelemetry"
        if (Test-Path $devicePath) {
            Write-Host "Driver Device '$devicePath' is ACCESSIBLE." -ForegroundColor Green
        } else {
            Write-Host "Driver Device '$devicePath' is NOT accessible." -ForegroundColor Gray
            Write-Host "Note: Tasklet application automatically uses high-resolution NT API + ETW co-monitor." -ForegroundColor DarkCyan
        }
    }

    "install" {
        if (-not (Test-Admin)) {
            Write-Error "Administrator privileges required to install kernel driver service."
            return
        }

        $fullPath = Resolve-Path $DriverPath -ErrorAction SilentlyContinue
        if (-not $fullPath) {
            Write-Error "Driver binary not found at '$DriverPath'. Build with WDK first."
            return
        }

        Write-Host "Creating kernel driver service '$ServiceName'..." -ForegroundColor Cyan
        & sc.exe create $ServiceName type= kernel binPath= "$fullPath"
        & sc.exe query $ServiceName
    }

    "start" {
        if (-not (Test-Admin)) {
            Write-Error "Administrator privileges required to start kernel driver service."
            return
        }
        Write-Host "Starting kernel driver service '$ServiceName'..." -ForegroundColor Cyan
        & sc.exe start $ServiceName
    }

    "stop" {
        if (-not (Test-Admin)) {
            Write-Error "Administrator privileges required to stop kernel driver service."
            return
        }
        Write-Host "Stopping kernel driver service '$ServiceName'..." -ForegroundColor Cyan
        & sc.exe stop $ServiceName
    }

    "uninstall" {
        if (-not (Test-Admin)) {
            Write-Error "Administrator privileges required to remove kernel driver service."
            return
        }
        & sc.exe stop $ServiceName
        & sc.exe delete $ServiceName
        Write-Host "Service '$ServiceName' deleted." -ForegroundColor Green
    }

    "testsign" {
        if (-not (Test-Admin)) {
            Write-Error "Administrator privileges required to enable test-signing."
            return
        }
        Write-Host "Enabling Windows BCD test-signing..." -ForegroundColor Cyan
        & bcdedit.exe /set testsigning on
        Write-Host "Test signing enabled. Reboot machine to take effect." -ForegroundColor Green
    }
}
