[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Target,
    [string[]]$Arguments = @()
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bash = 'C:\msys64\usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash)) { throw 'MSYS2 is missing. Run tools\bootstrap.ps1 first.' }
$msysRoot = $root -replace '\\','/' -replace '^([A-Za-z]):','/$1'
$extra = ($Arguments | ForEach-Object { "'$_'" }) -join ' '
& $bash -lc "set -e; export PATH=/ucrt64/bin:/usr/bin:`$PATH; cd '$msysRoot'; make $Target $extra"
if ($LASTEXITCODE -ne 0) { throw "make $Target failed with exit code $LASTEXITCODE" }
