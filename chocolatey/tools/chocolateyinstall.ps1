$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url = 'https://github.com/cyberspacesec/go-port-rocket/releases/download/v$version/go-port-rocket_$version_windows_386.zip'
$url64 = 'https://github.com/cyberspacesec/go-port-rocket/releases/download/v$version/go-port-rocket_$version_windows_amd64.zip'
$checksum = '$sha256_32'
$checksum64 = '$sha256_64'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  unzipLocation  = $toolsDir
  url            = $url
  url64bit       = $url64
  softwareName   = 'go-port-rocket*'
  checksum       = $checksum
  checksumType   = 'sha256'
  checksum64     = $checksum64
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# 创建shim
$files = Get-ChildItem "$toolsDir" -Include "go-port-rocket.exe" -Recurse
foreach ($file in $files) {
  New-Item "$file.gui" -Type File -Force | Out-Null
  Install-BinFile -Name "go-port-rocket" -Path "$file"
}

Write-Host "Go Port Rocket 已成功安装到 $toolsDir"
Write-Host "您可以直接在命令行中使用 'go-port-rocket' 命令"
Write-Host ""
Write-Host "注意：使用网络扫描功能需要 Npcap 或 WinPcap 支持。" 