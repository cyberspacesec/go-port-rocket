$ErrorActionPreference = 'Stop'
$packageName = 'go-port-rocket'

# 删除shim
Uninstall-BinFile -Name "go-port-rocket"

$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$files = Get-ChildItem "$toolsDir" -Include "go-port-rocket.exe" -Recurse
foreach ($file in $files) {
  if (Test-Path "$file.gui") {
    Remove-Item "$file.gui" -Force
  }
}

Write-Host "Go Port Rocket 已成功卸载" 