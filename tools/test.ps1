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

function Invoke-SmokeTest([string]$Name, [string[]]$MediaArgs, [string]$Memory = '512M', [int]$Processors = 4) {
    $log = Join-Path $logDir "$Name.log"
    $errorLog = Join-Path $logDir "$Name-qemu-error.log"
    Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $errorLog -ErrorAction SilentlyContinue
    $args = @(
        '-machine','q35','-cpu','max','-smp',"$Processors",'-m',$Memory,'-display','none','-monitor','none',
        '-drive',"if=pflash,format=raw,readonly=on,file=$firmware",
        '-device','intel-iommu,intremap=off',
        '-serial',"file:$log",'-no-reboot',
        '-device','isa-debug-exit'
    ) + $MediaArgs
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $qemu
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Arguments = (($args | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' ')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "$Name could not start QEMU" }
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        throw "$Name smoke test timed out. See $log"
    }
    $diagnostics = $process.StandardError.ReadToEnd()
    [System.IO.File]::WriteAllText($errorLog, $diagnostics)
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    if (-not (Test-Path -LiteralPath $log)) {
        $details = if (Test-Path -LiteralPath $errorLog) { Get-Content -LiteralPath $errorLog -Raw } else { 'no QEMU diagnostics' }
        throw "$Name produced no serial log (exit $exitCode): $details"
    }
    $serial = Get-Content -LiteralPath $log -Raw
    $markers = @(
        'DOXXER_BOOT_START',
        '[OK] SERIAL ONLINE',
        '[OK] STACK GUARD SEEDED',
        '[OK] AUTHENTICATED SEALED MEMORY ONLINE',
        '[OK] PMM ONLINE',
        '[OK] SEALED SHADOW PAGE LEDGER ONLINE',
        '[OK] VMM ONLINE',
        '[OK] CROSS-DOMAIN RAM ISOLATION VERIFIED',
        '[OK] MAPPED USER PAGE LIFETIMES PINNED',
        '[OK] USER HHDM ACCESS API SEALED',
        '[OK] GDT TSS IDT ONLINE',
        '[OK] CPU PRIVILEGE BOUNDARIES LOCKED',
        '[OK] KERNEL ELF PERMISSIONS VERIFIED',
        '[OK] SMAP ENFORCEMENT PROBED',
        '[OK] SMEP ENFORCEMENT PROBED',
        '[OK] EPHEMERAL USER MEMORY WINDOWS VERIFIED',
        '[OK] SUPERVISOR MAPPING LIFETIMES PINNED',
        '[OK] PAGE-TABLE GRAPH LIFETIMES PINNED',
        '[OK] SUPERVISOR STACK WINDOWS ISOLATED',
        '[OK] EXCEPTION AND GUARD SELF-TEST PASSED',
        '[OK] GUARDED KERNEL STACK ACTIVE',
        '[OK] GUARDED SHADOW MEMORY REGIONS ONLINE',
        '[OK] HARDENED HEAP ONLINE',
        '[OK] CAPABILITY SECURITY MODEL ONLINE',
        '[OK] CAPABILITY IPC ONLINE',
        '[OK] CAPABILITY EVENTS ONLINE',
        '[OK] ISOLATED PROCESS CONTAINERS ONLINE',
        '[OK] BOUNDED SYSCALL ABI ONLINE',
        '[OK] USER SYSCALL COPY GATEWAY ONLINE',
        '[OK] CAPABILITY SERVICE REGISTRY ONLINE',
        '[OK] VALIDATED USER MEMORY ACCESS ONLINE',
        '[OK] HARDENED ELF64 LOADER ONLINE',
        '[OK] SEALED IMAGE TRUST POLICY ONLINE',
        '[OK] GUARDED USER THREAD CONTEXTS ONLINE',
        '[OK] RING-3 SYSCALL TRANSITION VERIFIED',
        '[OK] END-TO-END USER ABI DISPATCH VERIFIED',
        '[OK] ACPI TABLES VALIDATED',
        '[OK] DMA REMAPPING DEFAULT-DENY',
        '[OK] DMA ROOT TABLES PINNED',
        '[OK] LOCAL APIC ONLINE',
        '[OK] IOAPIC MASKED',
        '[OK] PER-CPU RUNTIME ONLINE',
        '[OK] ALL CPU SECURITY STATE VERIFIED',
        '[OK] SMP IPI SELF-TEST PASSED',
        '[OK] PER-CPU GUARDED SYSCALL STACKS ONLINE',
        '[OK] ALL-CPU SYSCALL MSRS VERIFIED',
        '[OK] SWAPGS SYSCALL ENTRY ONLINE',
        '[OK] VALIDATED IRETQ USER RETURN VERIFIED',
        '[OK] USER EXCEPTION DELIVERY VERIFIED',
        '[OK] CAPABILITY-BOUND USER THREAD DISPATCH VERIFIED',
        '[OK] PER-CPU SCHEDULER ONLINE',
        '[OK] CROSS-CPU TASK SELF-TEST PASSED',
        '[OK] SCHEDULER USER CONTEXT BINDING VERIFIED',
        '[OK] APIC TIMER ONLINE',
        '[OK] FRAMEBUFFER ONLINE',
        'DOXXER_BOOT_OK'
    )
    foreach ($marker in $markers) {
        if (-not $serial.Contains($marker)) { throw "$Name missing marker '$marker'. See $log" }
    }
    if ($exitCode -ne 33) { throw "$Name returned $exitCode, expected 33. See $log" }
    Write-Host "$Name smoke test passed." -ForegroundColor Green
}

Invoke-SmokeTest 'disk' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')")
Invoke-SmokeTest 'iso' @('-cdrom',(Join-Path $root 'dist\doxxer.iso'))
Invoke-SmokeTest 'lowmem' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '128M'
Invoke-SmokeTest 'highmem' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '5G'
Invoke-SmokeTest 'singlecpu' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '512M' 1
Invoke-SmokeTest 'eightcpu' @('-drive',"format=raw,file=$(Join-Path $root 'dist\doxxer-uefi.img')") '512M' 8
