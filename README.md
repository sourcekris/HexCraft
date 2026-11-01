# HexCraft

**HexCraft** is a memory-safe, cross-platform reverse engineering and firmware analysis Hex Editor for **Windows 11** and **Linux**, built with **C# (.NET 9)** and **Avalonia UI**.

---

## Key Features

- **Memory-Safe Piece-Table Binary Engine (`HexCraft.Core`)**:
  - Instant opening of large multi-gigabyte files via OS-backed `MemoryMappedFile` views without loading entire files into RAM.
  - Non-destructive byte overwrite, insertion, deletion, full **Undo / Redo** stacks (`Ctrl+Z` / `Ctrl+Y`), pattern search (ASCII & Hex bytes), and atomic saving.
  - In-place selection transformations: **XOR with Key**, **Bitwise Invert (`~NOT`)**, **Zero-Fill (`0x00`)**, and **Reverse Bytes**.
  - **Copy Selection As Code**: Export selected bytes directly to the clipboard as Raw Hex, **C `const uint8_t[]`**, **C# `byte[]`**, **Python `b'...'`**, or **Base64**.
- **010 Editor Binary Template (`.bt`) Engine (`HexCraft.Templates`)**:
  - Built-in lexer, recursive-descent parser, and AST interpreter for [010 Editor Binary Templates (`.bt`)](https://www.sweetscape.com/010editor/manual/IntroTempScripts.htm).
  - Supports `struct`, `union`, `enum`, `typedef`, bitfields (`uchar flag : 4`), dynamic arrays, `local` variables, user-defined functions, imperative control flow inside structs (`if`/`else`, `while`, `for`, `switch`), and `<bgcolor=..., fgcolor=..., format=hex, comment=...>` field attributes.
  - Bundled templates in `templates/`:
    - `PNG.bt` (Portable Network Graphics)
    - `ZIP.bt` (PKZIP / JAR / APK archives)
    - `ELF.bt` (32-bit & 64-bit Linux/Embedded ELF binaries)
    - `PE.bt` (Windows Portable Executables)
    - `SquashFS.bt` (SquashFS v4.0 Little Endian Superblocks)
    - `UImage.bt` (Das U-Boot Legacy Firmware Images)
    - `DTB.bt` (Flattened Device Tree Blobs)
- **Multi-Window Reverse Engineering Workspace (`HexCraft.App`)**:
  - **Multi-Tab Primary Hex + ASCII View**: Hardware-accelerated virtualized rendering with `.bt` template color overlays, bookmark highlights, and a right-edge **Color & Bookmark Minimap**.
  - **Live Data Inspector**: Decodes `Int8/UInt8`, `Int16/UInt16`, `Int32/UInt32`, `Int64/UInt64`, `Float32/Float64`, 8-bit binary, `DOS Date/Time`, UNIX `time_t`, Windows `FILETIME`, ASCII, UTF-8, and UTF-16 in Little Endian or Big Endian.
  - **File Information, Magic ID, Exif Metadata & Entropy**:
    - Magic byte signature detection with one-click recommended `.bt` template application.
    - **Built-in Exif & Format Metadata Inspector** (ExifTool-style): Parses TIFF/JPEG Exif IFDs (`IFD0`, `ExifIFD`, `GPS`), PNG (`IHDR`, `tEXt`, `iTXt`, `pHYs`, `tIME`, `eXIf`), PDF document info, PE/ELF headers, and SquashFS metadata—plus automatic merging with external `exiftool` if installed. Clicking any metadata tag jumps directly to its offset in the Hex Editor.
    - Calculates `CRC-32`, `MD5`, `SHA-1`, `SHA-256`, Shannon entropy, and a 32-block visual entropy sparkline.
  - **Strings Viewer**: Extracts printable ASCII/UTF-8 and UTF-16 (LE/BE) strings with live substring and Regular Expression filtering.
  - **Bookmarks & Annotations Manager**: Tag byte ranges with custom labels and colors.
- **Binwalk & `unsquashfs` Firmware Integration (`HexCraft.Tools`)**:
  - Built-in zero-dependency firmware signature scanner (SquashFS, CramFS, U-Boot `uImage`, DTB, GZip, XZ, LZMA, ZIP, PNG, ELF) plus seamless integration with external `binwalk` and `unsquashfs` (natively on Linux/Windows or automatically bridged via **WSL2** on Windows 11).
  - Built-in automatic decompression/unpacking for carved **GZip** streams and **ZIP** archives, with double-click loading of extracted files into new HexCraft tabs.

---

## Project Structure

```text
HexCraft/
├── HexCraft.sln
├── src/
│   ├── HexCraft.Core/          # Piece-Table buffer engine, Data Inspector, Magic ID, Exif, Hashes, Entropy, Strings
│   ├── HexCraft.Templates/     # 010 Editor .bt Lexer, Parser, AST & Runtime Interpreter
│   ├── HexCraft.Tools/         # Binwalk, unsquashfs, WSL2 path bridge & Built-in Firmware Unpacker
│   └── HexCraft.App/           # Avalonia UI cross-platform desktop application (Windows 11 & Linux)
├── templates/                  # Standard 010 Editor Binary Templates (.bt)
└── tests/
    └── HexCraft.Tests/         # Automated test suite
```

---

## Prerequisites

- **[.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)** (`9.0.x` or newer)
- *(Optional)* External firmware/metadata CLI tools:
  - **Linux**: `sudo apt install -y binwalk squashfs-tools libimage-exiftool-perl`
  - **Windows 11**: Native `binwalk` / `exiftool` in `PATH`, or installed inside **WSL2** (HexCraft automatically bridges Windows paths `C:\...` to `/mnt/c/...`).

---

## Building and Running on Windows 11

### 1. Build and Run in Development Mode
```powershell
git clone https://github.com/sourcekris/HexCraft.git
cd HexCraft

dotnet build HexCraft.sln
dotnet run --project src/HexCraft.App/HexCraft.App.csproj
```

### 2. Publish a Standalone Windows 11 Release Binary (`win-x64`)
```powershell
dotnet publish src/HexCraft.App/HexCraft.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/win-x64
```
The standalone executable will be generated at `publish/win-x64/HexCraft.App.exe`.

---

## Building and Running on Linux

Modern .NET 9 and Avalonia UI run natively on Linux (`X11` and `Wayland`) without Mono. You can either build directly on a Linux machine or cross-compile a standalone Linux binary from Windows.

### 1. Native Build on Linux
```bash
git clone https://github.com/sourcekris/HexCraft.git
cd HexCraft

dotnet build HexCraft.sln
dotnet run --project src/HexCraft.App/HexCraft.App.csproj
```

### 2. Publish a Self-Contained Single-File Linux Binary (From Linux or Windows)
To produce a standalone Linux executable that runs on any Linux distribution **without requiring .NET to be installed on the target machine**:

- **Linux x64 (`linux-x64`)**:
  ```bash
  dotnet publish src/HexCraft.App/HexCraft.App.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/linux-x64
  ```
- **Linux ARM64 (`linux-arm64`)**:
  ```bash
  dotnet publish src/HexCraft.App/HexCraft.App.csproj -c Release -r linux-arm64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/linux-arm64
  ```

Then on the Linux machine:
```bash
chmod +x ./publish/linux-x64/HexCraft.App
./publish/linux-x64/HexCraft.App
```

### Linux Desktop Library Requirements
Standard Linux desktop environments already include the required X11/fontconfig libraries. On a minimal installation, install:
```bash
sudo apt update && sudo apt install -y libfontconfig1 libice6 libsm6 libx11-6 libxext6 libxi6 libxrandr2 libxcursor1
```

---

## Running the Test Suite

```bash
dotnet run --project tests/HexCraft.Tests/HexCraft.Tests.csproj
```
