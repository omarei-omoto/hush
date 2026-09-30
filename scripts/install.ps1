# Install hush on Windows — the single-file binary, no Node needed.
#
#   irm https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.ps1 | iex
#
# Downloads hush-windows-x64.exe and the release's SHA256SUMS, refuses to
# install unless the sha256 matches, checks the provenance attestation too when
# the GitHub CLI is installed and signed in, and puts hush.exe in
# %LOCALAPPDATA%\Programs\hush, adding that folder to *your* PATH (not the
# machine's). No administrator rights.
#
# Settings, all optional: $env:HUSH_VERSION, $env:HUSH_INSTALL_DIR,
# $env:HUSH_VERIFY_ATTESTATION = "0", $env:HUSH_DOWNLOAD_BASE.
# Windows support is in beta; `npm i -g @omarei/hush` works too.

$ErrorActionPreference = "Stop"
$repo = "omarei-omoto/hush"
$file = "hush-windows-x64.exe"

if (-not [Environment]::Is64BitOperatingSystem) { throw "hush install: there is no 32-bit Windows build" }

$version = "$env:HUSH_VERSION".TrimStart("v")
if ($env:HUSH_DOWNLOAD_BASE) { $base = $env:HUSH_DOWNLOAD_BASE.TrimEnd("/") }
elseif ($version) { $base = "https://github.com/$repo/releases/download/v$version" }
else { $base = "https://github.com/$repo/releases/latest/download" }

$dir = if ($env:HUSH_INSTALL_DIR) { $env:HUSH_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\hush" }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hush-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
  Write-Host "hush: downloading $file $version"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS")
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile (Join-Path $tmp $file)

  $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { ($_ -split "\s+")[1] -eq $file } | Select-Object -First 1
  if (-not $line) { throw "hush install: SHA256SUMS does not list $file - not installing" }
  $expected = ($line -split "\s+")[0].ToLower()
  $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $file)).Hash.ToLower()
  if ($actual -ne $expected) { throw "hush install: checksum mismatch for $file - not installing`n  expected $expected`n  got      $actual" }
  Write-Host "hush: sha256 ok ($actual)"

  if ($env:HUSH_VERIFY_ATTESTATION -ne "0" -and (Get-Command gh -ErrorAction SilentlyContinue)) {
    & gh auth status *> $null
    if ($LASTEXITCODE -eq 0) {
      & gh attestation verify (Join-Path $tmp $file) --repo $repo *> $null
      if ($LASTEXITCODE -ne 0) { throw "hush install: the GitHub attestation for $file does not verify - not installing" }
      Write-Host "hush: provenance ok (built by $repo's release workflow)"
    }
  }

  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Move-Item -Force (Join-Path $tmp $file) (Join-Path $dir "hush.exe")
  $installed = & (Join-Path $dir "hush.exe") --version
  Write-Host "hush: installed $installed at $dir\hush.exe"

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not (($userPath -split ";") -contains $dir)) {
    [Environment]::SetEnvironmentVariable("Path", ($(if ($userPath) { "$userPath;" } else { "" }) + $dir), "User")
    Write-Host "  added $dir to your PATH - open a new terminal to use it"
  }
  Write-Host ""
  Write-Host "  Next: cd into a project and run  hush start"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
