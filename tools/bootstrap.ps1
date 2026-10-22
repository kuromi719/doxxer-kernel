[CmdletBinding()]
param([switch]$SkipInstall)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$msys = 'C:\msys64\usr\bin\bash.exe'

if (-not (Test-Path -LiteralPath $msys)) {
    if ($SkipInstall) { throw 'MSYS2 is not installed at C:\msys64.' }
    winget install --id MSYS2.MSYS2 --exact --accept-source-agreements --accept-package-agreements --silent
}

$packages = @(
    'make','nasm','xorriso','autoconf','autoconf-wrapper','automake','automake-wrapper',
    'libtool','pkgconf','patch','git','curl','mingw-w64-ucrt-x86_64-clang',
    'mingw-w64-ucrt-x86_64-lld','mingw-w64-ucrt-x86_64-llvm',
    'mingw-w64-ucrt-x86_64-mtools','mingw-w64-ucrt-x86_64-gptfdisk'
) -join ' '

if (-not $SkipInstall) {
    & $msys -lc "pacman -Syu --noconfirm"
    & $msys -lc "pacman -S --needed --noconfirm $packages"
}

git -C $root submodule update --init --recursive

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$firmware = 'C:\Program Files\qemu\share\edk2-x86_64-code.fd'
if (-not (Test-Path -LiteralPath $qemu)) { throw "QEMU not found at $qemu" }
if (-not (Test-Path -LiteralPath $firmware)) { throw "EDK2 firmware not found at $firmware" }

& $msys -lc 'export PATH=/ucrt64/bin:/usr/bin:$PATH; clang++ --version | head -n 1; make --version | head -n 1; xorriso -version 2>&1 | head -n 1; mformat -V 2>&1 | head -n 1'
Write-Host 'Doxxer development environment is ready.' -ForegroundColor Green
