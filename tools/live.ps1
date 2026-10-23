[CmdletBinding()]
param(
    [ValidateSet('Start','Reload','Reset','Stop','Status')]
    [string]$Action = 'Start',
    [ValidateSet('disk','iso')]
    [string]$Media = 'disk'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$firmware = 'C:\Program Files\qemu\share\edk2-x86_64-code.fd'
$stateDirectory = Join-Path $root 'build\live'
$pidFile = Join-Path $stateDirectory 'qemu.pid'
$serialLog = Join-Path $stateDirectory 'serial.log'
$qmpPort = 45454

function Get-LiveProcess {
    if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
    $savedPid = [int](Get-Content -LiteralPath $pidFile -Raw)
    return Get-Process -Id $savedPid -ErrorAction SilentlyContinue
}

function Send-Qmp([string]$Command) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect('127.0.0.1', $qmpPort)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000
        $reader = [System.IO.StreamReader]::new($stream)
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.AutoFlush = $true
        [void]$reader.ReadLine()
        $writer.WriteLine('{"execute":"qmp_capabilities"}')
        [void]$reader.ReadLine()
        $writer.WriteLine($Command)
        Start-Sleep -Milliseconds 100
    } finally {
        $client.Dispose()
    }
}

function Stop-LiveProcess {
    $process = Get-LiveProcess
    if ($null -eq $process) { return }
    try { Send-Qmp '{"execute":"quit"}' } catch { $process.Kill() }
    try { $process.WaitForExit(3000) | Out-Null } catch { }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}

function Start-LiveProcess {
    if (-not (Test-Path -LiteralPath $qemu)) { throw 'QEMU is not installed in the expected location.' }
    if (-not (Test-Path -LiteralPath $firmware)) { throw 'EDK2 firmware is unavailable.' }
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    Remove-Item -LiteralPath $serialLog -Force -ErrorAction SilentlyContinue
    $common = @(
        '-name','Doxxer-OS-Live',
        '-machine','q35','-cpu','max','-smp','4','-m','512M',
        '-drive',"`"if=pflash,format=raw,readonly=on,file=$firmware`"",
        '-device','intel-iommu,intremap=off',
        '-serial',"file:$serialLog",
        '-qmp',"tcp:127.0.0.1:$qmpPort,server=on,wait=off"
    )
    if ($Media -eq 'disk') {
        $artifact = Join-Path $root 'dist\doxxer-uefi.img'
        $mediaArguments = @('-drive',"format=raw,file=$artifact")
    } else {
        $artifact = Join-Path $root 'dist\doxxer.iso'
        $mediaArguments = @('-cdrom',$artifact)
    }
    if (-not (Test-Path -LiteralPath $artifact)) { throw "Missing artifact: $artifact" }
    # This intentionally starts a visible native QEMU process. It is the live
    # development VM, not a browser preview or a hidden test runner.
    $process = Start-Process -FilePath $qemu -ArgumentList ($common + $mediaArguments) -PassThru
    Set-Content -LiteralPath $pidFile -Value $process.Id -NoNewline
    Write-Host "Doxxer live VM started (PID $($process.Id)). Close its QEMU window to stop it."
}

switch ($Action) {
    'Start' {
        $process = Get-LiveProcess
        if ($null -ne $process) { Write-Host "Doxxer live VM is already running (PID $($process.Id))." }
        else { Start-LiveProcess }
    }
    'Reload' { Stop-LiveProcess; Start-LiveProcess }
    'Reset' {
        if ($null -eq (Get-LiveProcess)) { throw 'Doxxer live VM is not running.' }
        Send-Qmp '{"execute":"system_reset"}'
        Write-Host 'Doxxer live VM reset requested.'
    }
    'Stop' { Stop-LiveProcess; Write-Host 'Doxxer live VM stopped.' }
    'Status' {
        $process = Get-LiveProcess
        if ($null -eq $process) { Write-Host 'Doxxer live VM is stopped.' }
        else { Write-Host "Doxxer live VM is running (PID $($process.Id))." }
    }
}
