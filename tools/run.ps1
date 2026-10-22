[CmdletBinding()]
param([ValidateSet('disk','iso')][string]$Media = 'disk')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$firmware = 'C:\Program Files\qemu\share\edk2-x86_64-code.fd'
if (-not (Test-Path -LiteralPath $qemu)) { throw 'QEMU is not installed in the expected location.' }

$common = @(
    '-machine','q35','-m','512M',
    '-drive',"if=pflash,format=raw,readonly=on,file=$firmware",
    '-serial','stdio','-no-reboot'
)
if ($Media -eq 'disk') {
    $artifact = Join-Path $root 'dist\doxxer-uefi.img'
    $mediaArgs = @('-drive',"format=raw,file=$artifact")
} else {
    $artifact = Join-Path $root 'dist\doxxer.iso'
    $mediaArgs = @('-cdrom',$artifact)
}
if (-not (Test-Path -LiteralPath $artifact)) { throw "Missing artifact: $artifact" }
& $qemu @common @mediaArgs
