===============================================================
  SecVault -- Bundled Prerequisite Installers
===============================================================

Install-SecVault.ps1 installs its prerequisites from local files in this
folder (no internet download required for prerequisites), the same
convention used by the NocVault suite installer. Place the following files
here before running Install-SecVault.ps1:

  node-v20.19.0-x64.msi         <- Node.js runtime     (required)
  postgresql-16.x-windows-x64.exe <- PostgreSQL 16     (required)
  nssm-2.24.zip                 <- Windows service mgr (required)
  Git-2.54.0-64-bit.exe         <- Git                 (used if Git not already present)
  VC_redist.x64.exe             <- Visual C++ runtime  (installed if present; skipped if not)

These are the same versions already bundled in the NocVault-Suite-v1.1
distribution package -- copy them from there rather than re-downloading:
  Git-2.54.0-64-bit.exe
  node-v20.19.0-x64.msi
  nssm-2.24.zip
  postgresql-16.14-1-windows-x64.exe
  VC_redist.x64.exe

Any tool already installed on the target server (checked via `node -v`,
`git --version`, and the presence of C:\Program Files\PostgreSQL\16\bin\psql.exe)
is left alone and NOT reinstalled -- Install-SecVault.ps1 only uses the file
here as a fallback for whatever isn't already present.

These installer binaries are NOT committed to the SecVault git repository
(too large, and not source code) -- see the parent .gitignore. This
README.txt is the only tracked file in this folder.
