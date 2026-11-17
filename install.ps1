<#
.SYNOPSIS
  Twigpine installer for Windows: twigpine and git-remote-twigpine.
.DESCRIPTION
  Downloads a pre-built release archive from GitHub and installs it only if its
  SHA-256 is listed at https://twigpine.com/install-checksums.txt. That list is
  served by twigpine.com, not by GitHub, so a hijacked, renamed or look-alike
  GitHub repository cannot get a different binary installed on its own. The
  list also names the latest version, so no GitHub API call is needed.
.EXAMPLE
  irm https://twigpine.com/install.ps1 | iex
.EXAMPLE
  & ([scriptblock]::Create((irm https://twigpine.com/install.ps1))) -Version v0.7.1
#>
[CmdletBinding()]
param(
  [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 may default to TLS 1.0; GitHub requires TLS 1.2+.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = if ($env:GITLAWB_RELEASE_REPO) { $env:GITLAWB_RELEASE_REPO } else { "Twigpine/node" }
$DownloadBase = if ($env:GITLAWB_DOWNLOAD_BASE) { $env:GITLAWB_DOWNLOAD_BASE.TrimEnd("/") } else { "https://github.com/$Repo/releases/download" }
$ChecksumsUrl = if ($env:GITLAWB_CHECKSUMS_URL) { $env:GITLAWB_CHECKSUMS_URL } else { "https://twigpine.com/install-checksums.txt" }
$InstallDir = if ($env:GITLAWB_INSTALL_DIR) { $env:GITLAWB_INSTALL_DIR } else { "$env:LOCALAPPDATA\Programs\gitlawb" }
$Headers = @{ "User-Agent" = "gitlawb-installer" }

$arch = if ($env:PROCESSOR_ARCHITEW6432) {
  $env:PROCESSOR_ARCHITEW6432
} else {
  $env:PROCESSOR_ARCHITECTURE
}
if ($arch -ne "AMD64") {
  throw "Unsupported architecture: $arch. Only x64 Windows binaries are published. Use WSL for arm64."
}
$target = "x86_64-pc-windows-msvc"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("gitlawb-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  # The checksum list comes first: it names the latest version and is the only
  # thing that can vouch for an archive.
  Write-Host "Fetching checksums from $ChecksumsUrl"
  $sumsPath = Join-Path $tmp "install-checksums.txt"
  Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $sumsPath -UseBasicParsing -Headers $Headers
  $sums = @(Get-Content -LiteralPath $sumsPath)

  if ($Version -eq "latest") {
    $latest = $sums | Where-Object { $_ -match '^# latest:\s*v[0-9][0-9A-Za-z.+-]*\s*$' } | Select-Object -First 1
    if (-not $latest) {
      throw "the checksum list does not name a latest version: $ChecksumsUrl"
    }
    $tag = ($latest -replace '^# latest:\s*', '').Trim()
  } elseif ($Version.StartsWith("v")) {
    $tag = $Version
  } else {
    $tag = "v$Version"
  }
  if ($tag -notmatch '^v[0-9A-Za-z.+-]+$') {
    throw "not a release version: $tag"
  }
  $ver = $tag.Substring(1)

  # Releases before the rename to Twigpine named their archives gitlawb-node-*.
  # Take whichever name the list vouches for, new name first.
  # A list line is "<sha256>  <file>" (or "<sha256> *<file>"), as sha256sum writes it.
  $archive = $null
  $expected = $null
  foreach ($prefix in @("twigpine-node", "gitlawb-node")) {
    $candidate = "$prefix-$ver-$target.zip"
    foreach ($line in $sums) {
      $parts = $line.Trim() -split '\s+'
      if ($parts.Count -ge 2 -and $parts[0] -match '^[0-9A-Fa-f]{64}$' -and ($parts[1] -eq $candidate -or $parts[1] -eq "*$candidate")) {
        $archive = $candidate
        $expected = $parts[0].ToLower()
        break
      }
    }
    if ($expected) { break }
  }
  if (-not $expected) {
    throw "twigpine-node-$ver-$target.zip is not in the checksum list at $ChecksumsUrl. Refusing to install a build the list does not vouch for."
  }
  $url = "$DownloadBase/$tag/$archive"

  Write-Host "Installing Twigpine $tag for windows/x64"
  Write-Host "  Archive: $archive"
  Write-Host "  Into:    $InstallDir"

  $zipPath = Join-Path $tmp $archive
  Write-Host "Downloading..."
  Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -Headers $Headers

  Write-Host "Verifying checksum..."
  $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) {
    throw "checksum mismatch for ${archive}: expected $expected ($ChecksumsUrl), got $actual ($url). Nothing was installed."
  }
  Write-Host "  checksum OK"

  Write-Host "Extracting..."
  $extract = Join-Path $tmp "extract"
  Expand-Archive -Path $zipPath -DestinationPath $extract -Force
  $pkgDir = Get-ChildItem -Path $extract -Directory | Select-Object -First 1

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  # Every program has the name it carries now and the one it had before the
  # rename. The archive ships one of them; the other is installed as a copy, so
  # both names always run the same build. The old names matter: git picks its
  # remote helper by URL scheme, so gitlawb:// remotes run git-remote-gitlawb,
  # and scripts may still call gl. The Windows archive always ships the CLI and
  # the helper; the daemon is optional.
  $pairs = @(
    @{ Name = "twigpine.exe"; Old = "gl.exe"; Extra = @("twig.exe"); Required = $true },
    @{ Name = "git-remote-twigpine.exe"; Old = "git-remote-gitlawb.exe"; Extra = @(); Required = $true },
    @{ Name = "twigpine-node.exe"; Old = "gitlawb-node.exe"; Extra = @(); Required = $false }
  )

  # Work out the full set of copies first, so a missing required program is
  # reported before anything in the install folder changes.
  $plan = @()
  $stale = @()
  foreach ($pair in $pairs) {
    $names = @($pair.Name, $pair.Old) + $pair.Extra
    $shipped = @($pair.Name, $pair.Old) | Where-Object { Test-Path (Join-Path $pkgDir.FullName $_) } | Select-Object -First 1
    if ($shipped) {
      $src = Join-Path $pkgDir.FullName $shipped
      foreach ($name in $names) { $plan += @{ Src = $src; Name = $name } }
    } elseif ($pair.Required) {
      throw "archive is missing a required binary: $($pair.Name)"
    } else {
      # Not shipped (an optional program dropped from a release): remove any
      # leftover so an upgrade never leaves a stale, mixed-version install.
      $stale += $names
    }
  }

  # A directory on a name this run writes cannot be replaced by a file:
  # Copy-Item would put the program inside it and report success.
  foreach ($item in $plan) {
    $dst = Join-Path $InstallDir $item.Name
    if (Test-Path -LiteralPath $dst -PathType Container) {
      throw "$dst is a directory, and the installer needs that name for a program. Move it away or set GITLAWB_INSTALL_DIR. Nothing was installed."
    }
  }

  $installed = @()
  foreach ($item in $plan) {
    Copy-Item -Path $item.Src -Destination (Join-Path $InstallDir $item.Name) -Force
    $installed += $item.Name
  }
  foreach ($name in $stale) {
    $dst = Join-Path $InstallDir $name
    if (Test-Path $dst) { Remove-Item -Path $dst -Force }
  }

  Write-Host ""
  Write-Host "Installed Twigpine $tag"
  foreach ($bin in $installed) { Write-Host "  $bin -> $InstallDir\$bin" }
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# Add to the user PATH if missing.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $InstallDir) {
  $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
  [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  Write-Host ""
  Write-Host "Added $InstallDir to your PATH. Restart your terminal, then run:"
} else {
  Write-Host ""
  Write-Host "Run:"
}
Write-Host "  twigpine doctor"
Write-Host "  twigpine quickstart"
Write-Host ""
Write-Host "Docs: https://explorer.twigpine.com/docs"
