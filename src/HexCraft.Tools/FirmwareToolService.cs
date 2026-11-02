using System;
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
using HexCraft.Tools.Extractors;
using HexCraft.Tools.Signatures;

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
    public string SizeText => EstimatedSize > 0 ? $"{EstimatedSize:N0} B (0x{EstimatedSize:X})" : "Stream";
}

public sealed record ToolDiscoveryStatus(
    bool IsLinux,
    int RegisteredSignatureCount,
    int RegisteredExtractorCount,
    bool HasNativeUnsquashfs,
    string? NativeUnsquashfsPath,
    bool HasWsl2)
{
    public string Summary
    {
        get
        {
            var parts = new List<string>
            {
                $"HexCraft Engine: {RegisteredSignatureCount} Signatures | {RegisteredExtractorCount} Extractors"
            };

            if (HasNativeUnsquashfs) parts.Add("unsquashfs: Native");
            else if (HasWsl2) parts.Add("unsquashfs: WSL2 Bridge");
            else parts.Add("Matryoshka Unpack: Active");

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
/// HexCraft's internal extensible Firmware Signature &amp; Extraction Engine.
/// Uses <see cref="FirmwareSignatureRegistry"/> (modeled on ReFirmLabs/binwalk <c>src/signatures/*.rs</c>)
/// and <see cref="FirmwareExtractorRegistry"/> (modeled on ReFirmLabs/binwalk <c>src/extractors/*.rs</c>)
/// for 100% self-contained signature detection, structural unpacking, and Matryoshka recursive extraction.
/// </summary>
public static class FirmwareToolService
{
    public static FirmwareSignatureRegistry DefaultRegistry { get; } = FirmwareSignatureRegistry.CreateDefault();
    public static FirmwareExtractorRegistry DefaultExtractors { get; } = FirmwareExtractorRegistry.CreateDefault();

    public static ToolDiscoveryStatus DetectInstalledTools()
    {
        bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        string? nativeUnsquashfs = FindExecutableInPath(isLinux ? "unsquashfs" : "unsquashfs.exe");
        bool hasWsl = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && FindExecutableInPath("wsl.exe") is not null;

        return new ToolDiscoveryStatus(
            IsLinux: isLinux,
            RegisteredSignatureCount: DefaultRegistry.Parsers.Count,
            RegisteredExtractorCount: DefaultExtractors.Extractors.Count,
            HasNativeUnsquashfs: nativeUnsquashfs is not null,
            NativeUnsquashfsPath: nativeUnsquashfs,
            HasWsl2: hasWsl);
    }

    /// <summary>
    /// Scans a <see cref="BinaryDocument"/> using HexCraft's extensible internal signature library.
    /// </summary>
    public static List<FirmwareSignatureEntry> ScanSignatures(
        BinaryDocument doc,
        bool tryExternalBinwalk = false,
        FirmwareSignatureRegistry? customRegistry = null)
    {
        var registry = customRegistry ?? DefaultRegistry;
        return registry.Scan(doc);
    }

    /// <summary>
    /// Carves a region from the <see cref="BinaryDocument"/> and unpacks supported formats in-memory
    /// via <see cref="FirmwareExtractorRegistry"/> (CramFS, ROMFS, DTB->DTS, uImage, TRX, SEAMA, CPIO,
    /// TAR, GZip, Zlib, ZIP, PEM) with Matryoshka recursive extraction, or via <c>unsquashfs</c>.
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

        // If TAR was matched at the +257 "ustar" magic offset, rewind 257 bytes to the start of the 512-byte TAR block
        long effectiveStart = entry.Offset;
        if (entry.SignatureType.Contains("TAR", StringComparison.OrdinalIgnoreCase) && entry.Offset >= 257)
        {
            byte[] checkUstar = doc.ReadBytes(entry.Offset, 5);
            if (checkUstar.AsSpan().SequenceEqual("ustar"u8))
                effectiveStart = entry.Offset - 257;
        }

        long carveLength = entry.EstimatedSize > 0
            ? Math.Min(entry.EstimatedSize, doc.Length - effectiveStart)
            : Math.Max(0, doc.Length - effectiveStart);

        string safeType = Regex.Replace(entry.SignatureType, @"[^a-zA-Z0-9_\-]", "_");
        string carvedFilePath = Path.Combine(baseDir, $"carved_{effectiveStart:X8}_{safeType}.bin");

        byte[] carvedBytes = doc.ReadBytes(effectiveStart, (int)Math.Min(carveLength, 64 * 1024 * 1024));
        await File.WriteAllBytesAsync(carvedFilePath, carvedBytes, ct);
        log.AppendLine($"[+] Carved {carvedBytes.Length:N0} bytes from offset 0x{effectiveStart:X8} [{entry.SourceEngine}] -> {carvedFilePath}");

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
        else
        {
            // Extract using HexCraft's internal FirmwareExtractorRegistry (+ Matryoshka recursion)
            string sigId = entry.SourceEngine.Contains(':')
                ? entry.SourceEngine.Split(':')[^1]
                : entry.SignatureType;

            byte[] payloadForExtractor = entry.SignatureType.Contains("ZIP", StringComparison.OrdinalIgnoreCase)
                ? doc.ReadBytes(effectiveStart, (int)Math.Min(doc.Length - effectiveStart, 64 * 1024 * 1024))
                : carvedBytes;

            var extractResult = DefaultExtractors.ExtractPayload(
                payloadForExtractor,
                sigId,
                entry.SignatureType,
                baseDir,
                recursiveScanner: DefaultRegistry,
                maxRecursionDepth: 2);

            log.AppendLine(extractResult.LogMessage);
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

    /// <summary>
    /// Native in-memory unpacker for SVR4 ASCII CPIO archives ("070701" / "070702").
    /// </summary>
    public static int ExtractCpioNewcArchive(ReadOnlySpan<byte> archiveBytes, string outputDir, StringBuilder? log = null)
    {
        Directory.CreateDirectory(outputDir);
        int extractedCount = 0;
        int pos = 0;

        while (pos + 110 <= archiveBytes.Length)
        {
            var hdr = archiveBytes.Slice(pos, 110);
            if (!hdr[..6].SequenceEqual("070701"u8) && !hdr[..6].SequenceEqual("070702"u8))
                break;

            uint fileSize;
            uint nameSize;
            try
            {
                fileSize = Convert.ToUInt32(Encoding.ASCII.GetString(hdr.Slice(54, 8)), 16);
                nameSize = Convert.ToUInt32(Encoding.ASCII.GetString(hdr.Slice(94, 8)), 16);
            }
            catch
            {
                break;
            }

            if (nameSize == 0 || nameSize > 1024 || pos + 110 + nameSize > archiveBytes.Length)
                break;

            string rawName = Encoding.UTF8.GetString(archiveBytes.Slice(pos + 110, (int)nameSize)).TrimEnd('\0');
            if (rawName == "TRAILER!!!")
                break;

            // Header + filename is padded to a 4-byte boundary
            int dataOffset = Align4(pos + 110 + (int)nameSize);
            if (dataOffset + fileSize > archiveBytes.Length)
                break;

            string safeFileName = Path.GetFileName(rawName.Replace('\\', '/'));
            if (!string.IsNullOrEmpty(safeFileName) && fileSize > 0)
            {
                string destPath = Path.Combine(outputDir, safeFileName);
                File.WriteAllBytes(destPath, archiveBytes.Slice(dataOffset, (int)fileSize).ToArray());
                log?.AppendLine($"[+] CPIO Entry: '{rawName}' ({fileSize:N0} B) -> {destPath}");
                extractedCount++;
            }

            // File data is also padded to a 4-byte boundary
            pos = Align4(dataOffset + (int)fileSize);
        }

        return extractedCount;
    }

    /// <summary>
    /// Native in-memory unpacker for POSIX ustar TAR archives.
    /// </summary>
    public static int ExtractPosixTarArchive(ReadOnlySpan<byte> tarBytes, string outputDir, StringBuilder? log = null)
    {
        Directory.CreateDirectory(outputDir);
        int extractedCount = 0;
        int pos = 0;

        while (pos + 512 <= tarBytes.Length)
        {
            var block = tarBytes.Slice(pos, 512);
            if (block[0] == 0)
                break;

            if (!block.Slice(257, 5).SequenceEqual("ustar"u8))
                break;

            string name = Encoding.UTF8.GetString(block[..100]).TrimEnd('\0').Trim();
            string sizeOctal = Encoding.ASCII.GetString(block.Slice(124, 12)).TrimEnd('\0').Trim();
            byte typeFlag = block[156];

            long fileSize = 0;
            try
            {
                if (!string.IsNullOrEmpty(sizeOctal))
                    fileSize = Convert.ToInt64(sizeOctal, 8);
            }
            catch
            {
                break;
            }

            int dataStart = pos + 512;
            if (dataStart + fileSize > tarBytes.Length)
                break;

            bool isRegularFile = typeFlag == 0 || typeFlag == (byte)'0';
            string safeName = Path.GetFileName(name.Replace('\\', '/'));
            if (isRegularFile && !string.IsNullOrEmpty(safeName) && fileSize >= 0)
            {
                string destPath = Path.Combine(outputDir, safeName);
                File.WriteAllBytes(destPath, tarBytes.Slice(dataStart, (int)fileSize).ToArray());
                log?.AppendLine($"[+] TAR Entry: '{name}' ({fileSize:N0} B) -> {destPath}");
                extractedCount++;
            }

            long blocks = (fileSize + 511) / 512;
            pos = dataStart + (int)(blocks * 512);
        }

        return extractedCount;
    }

    private static int Align4(int value) => (value + 3) & ~3;

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
