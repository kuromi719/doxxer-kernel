[CmdletBinding()]
param([int]$TimeoutSeconds = 10)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$qemu = 'C:\Progra~1\qemu\qemu-system-x86_64.exe'
$firmware = 'C:\Progra~1\qemu\share\edk2-x86_64-code.fd'
$logDir = Join-Path $root 'build\test-logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

& (Join-Path $PSScriptRoot 'invoke-make.ps1') -Target clean
& (Join-Path $PSScriptRoot 'invoke-make.ps1') -Target all -Arguments @('TEST_MODE=1')

function Invoke-SmokeTest([string]$Name, [string[]]$MediaArgs, [string]$Memory = '512M') {
    $log = Join-Path $logDir "$Name.log"
    $errorLog = Join-Path $logDir "$Name-qemu-error.log"
    Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $errorLog -ErrorAction SilentlyContinue
    $args = @(
        '-machine','q35','-m',$Memory,'-display','none','-monitor','none',
        '-drive',"if=pflash,format=raw,readonly=on,file=$firmware",
        '-serial',"file:$log",'-no-reboot',
        '-device','isa-debug-exit'
    ) + $MediaArgs
    $process = Start-Process -FilePath $qemu -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardError $errorLog
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        throw "$Name smoke test timed out. See $log"
    }
    if (-not (Test-Path -LiteralPath $log)) {
        $details = if (Test-Path -LiteralPath $errorLog) { Get-Content -LiteralPath $errorLog -Raw } else { 'no QEMU diagnostics' }
        throw "$Name produced no serial log (exit $($process.ExitCode)): $details"
    }
    $serial = Get-Content -LiteralPath $log -Raw
    $markers = @(
        'DOXXER_BOOT_START',
        '[OK] SERIAL ONLINE',
        '[OK] STACK GUARD SEEDED',
        '[OK] PMM ONLINE',
        '[OK] VMM ONLINE',
        '[OK] GDT TSS IDT ONLINE',
        '[OK] EXCEPTION AND GUARD SELF-TEST PASSED',
        '[OK] GUARDED KERNEL STACK ACTIVE',
        '[OK] HARDENED HEAP ONLINE',
        '[OK] FRAMEBUFFER ONLINE',
        'DOXXER_BOOT_OK'
    )
    foreach ($marker in $markers) {
        if (-not $serial.Contains($marker)) { throw "$Name missing marker '$marker'. See $log" }
    }
    if ($process.ExitCode -ne 33) { throw "$Name returned $($process.ExitCode), expected 33. See $log" }
    Write-Host "$Name smoke test passed." -ForegroundColor Green
}

Invoke-SmokeTest 'disk' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')")
Invoke-SmokeTest 'iso' @('-cdrom',(Join-Path $root 'dist\doxxer.iso'))
Invoke-SmokeTest 'lowmem' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '128M'
Invoke-SmokeTest 'highmem' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '5G'
