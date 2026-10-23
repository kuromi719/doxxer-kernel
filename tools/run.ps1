[CmdletBinding()]
param([ValidateSet('disk','iso')][string]$Media = 'disk')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'live.ps1') -Action Start -Media $Media
