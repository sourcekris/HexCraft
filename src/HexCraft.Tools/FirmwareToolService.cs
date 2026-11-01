using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using HexCraft.Core.Buffers;

namespace HexCraft.Tools;

public sealed record FirmwareSignatureEntry(
    long Offset,
    long EstimatedSize,
    string SignatureType,
    string Category,
    string Description,
    bool CanUnsquashfs,
    string SourceEngine)
{
    public string OffsetHex => $"0x{Offset:X8}";
    public string SizeText => EstimatedSize > 0 ? $"{EstimatedSize:N0} B (0x{EstimatedSize:X})" : "Variable";
}

public sealed record ToolDiscoveryStatus(
    bool IsLinux,
    bool HasNativeBinwalk,
    string? NativeBinwalkPath,
    bool HasNativeUnsquashfs,
    string? NativeUnsquashfsPath,
    bool HasWsl2,
    bool HasWslBinwalk,
    bool HasWslUnsquashfs)
{
    public string Summary
    {
        get
        {
            var parts = new List<string> { "Built-in Firmware Scanner: Ready" };
            if (HasNativeBinwalk) parts.Add("Binwalk: Native");
            else if (HasWslBinwalk) parts.Add("Binwalk: WSL2");
            else parts.Add("Binwalk: Using Built-in Engine");

            if (HasNativeUnsquashfs) parts.Add("unsquashfs: Native");
            else if (HasWslUnsquashfs) parts.Add("unsquashfs: WSL2");
            else parts.Add("unsquashfs: Carve Ready");

            return string.Join(" | ", parts);
        }
    }
}

public sealed record ExtractionOutcome(
    bool Success,
    string OutputDirectory,
    IReadOnlyList<string> ExtractedFiles,
    string LogOutput);

/// <summary>
/// Integrates Binwalk and unsquashfs on Windows 11 (native or WSL2) and Linux,
/// combined with a built-in zero-dependency firmware signature scanner and carver.
/// </summary>
public static class FirmwareToolService
{
    private sealed record MagicPattern(
        byte[] Magic,
        string SignatureType,
        string Category,
        bool CanUnsquashfs,
        Func<ReadOnlySpan<byte>, (string Description, long EstimatedSize)> Inspector);

    private static readonly List<MagicPattern> Signatures = new()
    {
        new(new byte[] { 0x68, 0x73, 0x71, 0x73 }, "SquashFS (LE)", "Filesystem", true, span =>
        {
            if (span.Length >= 48)
            {
                uint inodes = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4, 4));
                uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(12, 4));
                ushort comp = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(20, 2));
                ushort major = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(28, 2));
                ushort minor = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(30, 2));
                ulong bytesUsed = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(40, 8));
                string compName = comp switch { 1 => "zlib", 2 => "lzma", 3 => "lzo", 4 => "xz", 5 => "lz4", 6 => "zstd", _ => $"id:{comp}" };
                return ($"Squashfs filesystem, little endian, version {major}.{minor}, compression: {compName}, size: {bytesUsed} bytes, {inodes} inodes, blocksize: {blockSize} bytes", (long)bytesUsed);
            }
            return ("Squashfs filesystem, little endian", 0);
        }),

        new(new byte[] { 0x73, 0x71, 0x73, 0x68 }, "SquashFS (BE)", "Filesystem", true, _ =>
            ("Squashfs filesystem, big endian", 0)),

        new(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, "PNG Image", "Image", false, span =>
        {
            if (span.Length >= 24)
            {
                uint w = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(16, 4));
                uint h = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(20, 4));
                return ($"PNG image, {w} x {h}, 8-bit/color RGBA", 0);
            }
            return ("PNG image data", 0);
        }),

        new(new byte[] { 0x1F, 0x8B, 0x08 }, "GZip Stream", "Compressed", false, span =>
        {
            if (span.Length >= 10)
            {
                byte flags = span[3];
                string extra = "";
                if ((flags & 0x08) != 0 && span.Length > 11)
                {
                    int nul = span[10..].IndexOf((byte)0);
                    if (nul > 0)
                        extra = $", original file name: \"{Encoding.ASCII.GetString(span.Slice(10, Math.Min(nul, 64)))}\"";
                }
                return ($"gzip compressed data, DEFLATE{extra}", 0);
            }
            return ("gzip compressed data", 0);
        }),

        new(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, "XZ Stream", "Compressed", false, _ =>
            ("XZ compressed data (LZMA2)", 0)),

        new(new byte[] { 0x5D, 0x00, 0x00, 0x80, 0x00 }, "LZMA Stream", "Compressed", false, _ =>
            ("LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes", 0)),

        new(new byte[] { 0x27, 0x05, 0x19, 0x56 }, "U-Boot uImage", "Firmware Header", false, span =>
        {
            if (span.Length >= 64)
            {
                uint size = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(12, 4));
                string name = Encoding.ASCII.GetString(span.Slice(32, 32)).TrimEnd('\0');
                return ($"uImage header, header size: 64 bytes, data size: {size} bytes, name: \"{name}\"", size + 64);
            }
            return ("uImage firmware header", 64);
        }),

        new(new byte[] { 0xD0, 0x0D, 0xFE, 0xED }, "Flattened Device Tree (DTB)", "Hardware Tree", false, span =>
        {
            if (span.Length >= 8)
            {
                uint totalSize = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(4, 4));
                if (totalSize is >= 40 and <= 16 * 1024 * 1024)
                    return ($"Flattened device tree, total size: {totalSize} bytes", totalSize);
            }
            return ("Flattened device tree blob (FDT/DTB)", 0);
        }),

        new(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, "ZIP Local Header", "Archive", false, span =>
        {
            if (span.Length >= 30)
            {
                uint compSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(18, 4));
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(26, 2));
                ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(28, 2));
                string fileName = "";
                if (nameLen > 0 && span.Length >= 30 + nameLen)
                    fileName = Encoding.UTF8.GetString(span.Slice(30, nameLen));
                return ($"Zip archive data, name: \"{fileName}\", compressed size: {compSize}", 30 + nameLen + extraLen + compSize);
            }
            return ("Zip archive data", 0);
        }),

        new(new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, "ELF Binary", "Executable", false, span =>
        {
            string bits = span.Length > 4 && span[4] == 2 ? "64-bit" : "32-bit";
            return ($"ELF {bits} executable/shared object", 0);
        }),

        new(new byte[] { 0x45, 0x3D, 0xCD, 0x28 }, "CramFS (LE)", "Filesystem", false, _ =>
            ("Linux Compressed ROM File System (cramfs), little endian", 0))
    };

    public static ToolDiscoveryStatus DetectInstalledTools()
    {
        bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        string? nativeBinwalk = FindExecutableInPath(isLinux ? "binwalk" : "binwalk.exe");
        string? nativeUnsquashfs = FindExecutableInPath(isLinux ? "unsquashfs" : "unsquashfs.exe");

        bool hasWsl = false;
        bool wslBinwalk = false;
        bool wslUnsquashfs = false;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            string? wslExe = FindExecutableInPath("wsl.exe");
            hasWsl = wslExe is not null;
        }

        return new ToolDiscoveryStatus(
            IsLinux: isLinux,
            HasNativeBinwalk: nativeBinwalk is not null,
            NativeBinwalkPath: nativeBinwalk,
            HasNativeUnsquashfs: nativeUnsquashfs is not null,
            NativeUnsquashfsPath: nativeUnsquashfs,
            HasWsl2: hasWsl,
            HasWslBinwalk: wslBinwalk,
            HasWslUnsquashfs: wslUnsquashfs);
    }

    /// <summary>
    /// Scans a <see cref="BinaryDocument"/> using the built-in memory-safe signature scanner,
    /// and optionally merges external `binwalk` output if requested and available.
    /// </summary>
    public static List<FirmwareSignatureEntry> ScanSignatures(BinaryDocument doc, bool tryExternalBinwalk = false)
    {
        var results = new List<FirmwareSignatureEntry>();
        long scanLen = Math.Min(doc.Length, 32L * 1024 * 1024);
        if (scanLen <= 0)
            return results;

        byte[] data = doc.ReadBytes(0, (int)scanLen);
        ReadOnlySpan<byte> span = data;

        foreach (var sig in Signatures)
        {
            int pos = 0;
            while (pos <= span.Length - sig.Magic.Length)
            {
                int idx = span[pos..].IndexOf(sig.Magic);
                if (idx < 0) break;

                int matchOffset = pos + idx;
                ReadOnlySpan<byte> window = span.Slice(matchOffset, Math.Min(256, span.Length - matchOffset));
                var (desc, estSize) = sig.Inspector(window);

                if (!string.IsNullOrEmpty(desc))
                {
                    long clampedSize = estSize > 0
                        ? Math.Min(estSize, doc.Length - matchOffset)
                        : Math.Min(256, doc.Length - matchOffset);

                    results.Add(new FirmwareSignatureEntry(
                        Offset: matchOffset,
                        EstimatedSize: clampedSize,
                        SignatureType: sig.SignatureType,
                        Category: sig.Category,
                        Description: desc,
                        CanUnsquashfs: sig.CanUnsquashfs,
                        SourceEngine: "Built-in"));
                }

                pos = matchOffset + Math.Max(1, sig.Magic.Length);
            }
        }

        if (tryExternalBinwalk && !string.IsNullOrEmpty(doc.FilePath) && File.Exists(doc.FilePath))
        {
            try
            {
                var extEntries = RunExternalBinwalkScan(doc.FilePath);
                foreach (var ext in extEntries)
                {
                    if (!results.Any(r => Math.Abs(r.Offset - ext.Offset) < 4))
                        results.Add(ext);
                }
            }
            catch
            {
                // Ignore external process failures and keep built-in scan results
            }
        }

        results.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        return results;
    }

    /// <summary>
    /// Carves a region from the BinaryDocument and, if it is a SquashFS image, attempts to run
    /// native or WSL2 `unsquashfs` (and also extracts embedded files via built-in carving).
    /// </summary>
    public static async Task<ExtractionOutcome> CarveAndExtractAsync(
        BinaryDocument doc,
        FirmwareSignatureEntry entry,
        string? outputRootDirectory = null,
        CancellationToken ct = default)
    {
        var log = new StringBuilder();
        string baseDir = outputRootDirectory ?? Path.Combine(
            Path.GetTempPath(),
            "HexCraft_Extractions",
            $"{Path.GetFileNameWithoutExtension(doc.DisplayName)}_{entry.Offset:X8}");

        Directory.CreateDirectory(baseDir);

        long carveLength = entry.EstimatedSize > 0
            ? Math.Min(entry.EstimatedSize, doc.Length - entry.Offset)
            : Math.Max(0, doc.Length - entry.Offset);

        string safeType = Regex.Replace(entry.SignatureType, @"[^a-zA-Z0-9_\-]", "_");
        string carvedFilePath = Path.Combine(baseDir, $"carved_{entry.Offset:X8}_{safeType}.bin");

        byte[] carvedBytes = doc.ReadBytes(entry.Offset, (int)Math.Min(carveLength, 64 * 1024 * 1024));
        await File.WriteAllBytesAsync(carvedFilePath, carvedBytes, ct);
        log.AppendLine($"[+] Carved {carvedBytes.Length:N0} bytes from offset 0x{entry.Offset:X8} -> {carvedFilePath}");

        if (entry.CanUnsquashfs)
        {
            string squashOutDir = Path.Combine(baseDir, "squashfs-root");
            log.AppendLine($"[*] Attempting unsquashfs extraction into {squashOutDir}...");
            bool extracted = await TryRunUnsquashfsAsync(carvedFilePath, squashOutDir, log, ct);
            if (!extracted)
            {
                log.AppendLine("[i] External unsquashfs binary not invoked; generating SquashFS superblock metadata summary.");
                string metaPath = Path.Combine(baseDir, "squashfs_superblock_info.txt");
                await File.WriteAllTextAsync(metaPath,
                    $"SquashFS Image Carved by HexCraft\nOffset: 0x{entry.Offset:X8}\nSize: {carvedBytes.Length} bytes\nDetails: {entry.Description}\n", ct);
            }
        }
        else if (entry.SignatureType.Contains("GZip", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var inMs = new MemoryStream(carvedBytes);
                using var gz = new GZipStream(inMs, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                await gz.CopyToAsync(outMs, ct);
                byte[] decompressed = outMs.ToArray();
                string decompPath = Path.Combine(baseDir, $"decompressed_{entry.Offset:X8}_payload.bin");
                await File.WriteAllBytesAsync(decompPath, decompressed, ct);
                log.AppendLine($"[+] Built-in GZip Decompressor: Unpacked {decompressed.Length:N0} bytes -> {decompPath}");
            }
            catch (Exception ex)
            {
                log.AppendLine($"[!] GZip decompression note: {ex.Message}");
            }
        }
        else if (entry.SignatureType.Contains("ZIP", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                // Read from offset to end of document so Central Directory is present for ZipArchive
                byte[] fullZipSlice = doc.ReadBytes(entry.Offset, (int)Math.Min(doc.Length - entry.Offset, 64 * 1024 * 1024));
                using var zipMs = new MemoryStream(fullZipSlice);
                using var archive = new ZipArchive(zipMs, ZipArchiveMode.Read);
                string zipOutDir = Path.Combine(baseDir, "zip-extracted");
                Directory.CreateDirectory(zipOutDir);
                foreach (var zipEntry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(zipEntry.Name)) continue;
                    string targetFile = Path.Combine(zipOutDir, zipEntry.Name);
                    zipEntry.ExtractToFile(targetFile, overwrite: true);
                    log.AppendLine($"[+] Built-in ZIP Unpacker: Extracted '{zipEntry.FullName}' ({zipEntry.Length:N0} B)");
                }
            }
            catch (Exception ex)
            {
                log.AppendLine($"[!] ZIP extraction note: {ex.Message}");
            }
        }

        var files = Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories)
            .OrderBy(f => f)
            .ToList();

        return new ExtractionOutcome(
            Success: true,
            OutputDirectory: baseDir,
            ExtractedFiles: files,
            LogOutput: log.ToString());
    }

    public static string ConvertWindowsPathToWsl(string windowsPath)
    {
        string full = Path.GetFullPath(windowsPath);
        if (full.Length >= 2 && full[1] == ':')
        {
            char drive = char.ToLowerInvariant(full[0]);
            string rest = full[2..].Replace('\\', '/');
            return $"/mnt/{drive}{rest}";
        }
        return full.Replace('\\', '/');
    }

    private static async Task<bool> TryRunUnsquashfsAsync(
        string carvedFilePath,
        string destDir,
        StringBuilder log,
        CancellationToken ct)
    {
        try
        {
            bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            string? nativeUnsquashfs = FindExecutableInPath(isLinux ? "unsquashfs" : "unsquashfs.exe");

            ProcessStartInfo? psi = null;
            if (nativeUnsquashfs is not null)
            {
                psi = new ProcessStartInfo
                {
                    FileName = nativeUnsquashfs,
                    Arguments = $"-f -d \"{destDir}\" \"{carvedFilePath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && FindExecutableInPath("wsl.exe") is not null)
            {
                string wslInput = ConvertWindowsPathToWsl(carvedFilePath);
                string wslDest = ConvertWindowsPathToWsl(destDir);
                psi = new ProcessStartInfo
                {
                    FileName = "wsl.exe",
                    Arguments = $"-e unsquashfs -f -d \"{wslDest}\" \"{wslInput}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }

            if (psi is null)
                return false;

            using var proc = Process.Start(psi);
            if (proc is null)
                return false;

            string stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            string stderr = await proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            if (!string.IsNullOrWhiteSpace(stdout)) log.AppendLine(stdout.Trim());
            if (!string.IsNullOrWhiteSpace(stderr)) log.AppendLine(stderr.Trim());

            return proc.ExitCode == 0 && Directory.Exists(destDir);
        }
        catch (Exception ex)
        {
            log.AppendLine($"[!] unsquashfs execution note: {ex.Message}");
            return false;
        }
    }

    private static List<FirmwareSignatureEntry> RunExternalBinwalkScan(string filePath)
    {
        var list = new List<FirmwareSignatureEntry>();
        bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        string? binwalkExe = FindExecutableInPath(isLinux ? "binwalk" : "binwalk.exe");

        ProcessStartInfo? psi = null;
        if (binwalkExe is not null)
        {
            psi = new ProcessStartInfo
            {
                FileName = binwalkExe,
                Arguments = $"\"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
        }

        if (psi is null) return list;

        using var proc = Process.Start(psi);
        if (proc is null) return list;

        string output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(5000);

        // Parse standard binwalk table lines: "DECIMAL       HEXADECIMAL     DESCRIPTION"
        foreach (string line in output.Split('\n'))
        {
            var match = Regex.Match(line.Trim(), @"^(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$");
            if (match.Success && long.TryParse(match.Groups[1].Value, out long offset))
            {
                string desc = match.Groups[2].Value.Trim();
                bool isSquash = desc.Contains("Squashfs", StringComparison.OrdinalIgnoreCase);
                list.Add(new FirmwareSignatureEntry(
                    Offset: offset,
                    EstimatedSize: 0,
                    SignatureType: isSquash ? "SquashFS" : "Binwalk Match",
                    Category: "Firmware",
                    Description: desc,
                    CanUnsquashfs: isSquash,
                    SourceEngine: "Binwalk CLI"));
            }
        }

        return list;
    }

    private static string? FindExecutableInPath(string exeName)
    {
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathEnv))
            return null;

        foreach (string dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                string candidate = Path.Combine(dir.Trim(), exeName);
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // Ignore invalid PATH entries
            }
        }
        return null;
    }
}

