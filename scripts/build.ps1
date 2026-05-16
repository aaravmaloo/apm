$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$DistDir = if ($env:DIST_DIR) { $env:DIST_DIR } else { Join-Path $RootDir "dist" }
$BinName = if ($env:BIN_NAME) { $env:BIN_NAME } else { "pm.exe" }
$Target = if ($env:CARGO_BUILD_TARGET) { $env:CARGO_BUILD_TARGET } else { "x86_64-pc-windows-gnu" }

# Native library output directory
$NativeOut = if ($env:APM_NATIVE_OUT) { $env:APM_NATIVE_OUT } else { Join-Path ([System.IO.Path]::GetPathRoot((Resolve-Path $RootDir).Path)) "apm-native-libs" }

New-Item -ItemType Directory -Force -Path $NativeOut | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

if (-not $env:CARGO_TARGET_DIR) {
    $RootDrive = [System.IO.Path]::GetPathRoot((Resolve-Path $RootDir).Path)
    $env:CARGO_TARGET_DIR = Join-Path $RootDrive "apm-cargo-target"
}

if (Test-Path "C:\msys64\mingw64\bin\gcc.exe") {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
    $env:CC_x86_64_pc_windows_gnu = "C:\msys64\mingw64\bin\gcc.exe"
    $env:CXX_x86_64_pc_windows_gnu = "C:\msys64\mingw64\bin\g++.exe"
    $env:AR_x86_64_pc_windows_gnu = "C:\msys64\mingw64\bin\ar.exe"
}

# Build Unified Native Rust Library
$NativeRustDir = Join-Path $RootDir "rust\apm-native"
Write-Host "Building Unified Native Rust library..."
cargo build --release --manifest-path (Join-Path $NativeRustDir "Cargo.toml") --target $Target
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force (Join-Path $env:CARGO_TARGET_DIR "$Target\release\libapm_native.a") (Join-Path $NativeOut "libapm_native.a")

# Prepare Go build
$GoTags = "faceid nativeget"
$RustNativeFlags = "-lstdc++ -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 -lmfplat -lmf -lmfreadwrite -lmfuuid -lstrmiids -lntdll -luserenv -lws2_32 -ldbghelp"
$ExtLdFlags = "-static -L$NativeOut -lapm_native $RustNativeFlags"

$env:CGO_ENABLED = "1"
Remove-Item Env:CGO_LDFLAGS -ErrorAction SilentlyContinue

Write-Host "Building Go application..."
go build `
    -tags "$GoTags" `
    -ldflags "-linkmode external -extldflags '$ExtLdFlags'" `
    -o (Join-Path $DistDir $BinName) `
    $RootDir

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Built $(Join-Path $DistDir $BinName)"
