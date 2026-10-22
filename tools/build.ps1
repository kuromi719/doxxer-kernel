[CmdletBinding()]
param([ValidateSet('all','kernel','disk','iso')][string]$Target = 'all')
& (Join-Path $PSScriptRoot 'invoke-make.ps1') -Target $Target
