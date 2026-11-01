using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using HexCraft.Core.Buffers;

namespace HexCraft.Core.Analysis;

public sealed record FileMagicMatch(
    string FormatName,
    string Category,
    string MimeType,
    string Extension,
    string RecommendedTemplate,
    string Details);

public sealed record FileAnalysisReport(
    string FileName,
    string? FullPath,
    long FileSize,
    string FormattedSize,
    IReadOnlyList<FileMagicMatch> MagicMatches,
    IReadOnlyList<MetadataTagEntry> ExifAndFormatTags,
    string Crc32Hex,
    string Md5Hex,
    string Sha1Hex,
    string Sha256Hex,
    double OverallEntropy,
    string EntropyAssessment,
    double[] BlockEntropies,
    long[] ByteHistogram,
    int PrintableAsciiPercent,
    int NullBytePercent);

/// <summary>
/// Identifies file formats via magic byte signatures, calculates cryptographic hashes/checksums,
/// and computes Shannon entropy and byte distribution histograms.
/// </summary>
public static class FileAnalyzer
{
    private sealed record MagicRule(
        int Offset,
        byte[] Signature,
        string FormatName,
        string Category,
        string MimeType,
        string Extension,
        string RecommendedTemplate,
        Func<ReadOnlySpan<byte>, string>? DetailExtractor = null);

    private static readonly List<MagicRule> Rules = new()
    {
        new(0, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
            "PNG Image (Portable Network Graphics)", "Image", "image/png", ".png", "PNG.bt",
            span => span.Length >= 24
                ? $"Dimensions: {ReadBE32(span, 16)}x{ReadBE32(span, 20)}, BitDepth: {span[24]}"
                : "Valid PNG signature"),

        new(0, new byte[] { 0x7F, 0x45, 0x4C, 0x46 },
            "ELF Executable / Shared Object", "Executable", "application/x-elf", ".elf", "ELF.bt",
            span =>
            {
                if (span.Length < 18) return "ELF Binary";
                string bits = span[4] == 2 ? "64-bit" : span[4] == 1 ? "32-bit" : "Unknown class";
                string endian = span[5] == 1 ? "Little Endian" : "Big Endian";
                return $"{bits}, {endian}";
            }),

        new(0, new byte[] { 0x4D, 0x5A },
            "Windows PE / DOS Executable (MZ)", "Executable", "application/vnd.microsoft.portable-executable", ".exe/.dll", "PE.bt",
            span =>
            {
                if (span.Length >= 0x40)
                {
                    uint peOffset = BitConverter.ToUInt32(span.Slice(0x3C, 4));
                    return $"DOS MZ Header, e_lfanew = 0x{peOffset:X}";
                }
                return "DOS MZ Header";
            }),

        new(0, new byte[] { 0x50, 0x4B, 0x03, 0x04 },
            "ZIP Archive (PKZIP / JAR / APK / DOCX)", "Archive", "application/zip", ".zip", "ZIP.bt",
            _ => "PKZIP Local File Header (0x04034B50)"),

        new(0, new byte[] { 0x68, 0x73, 0x71, 0x73 },
            "SquashFS Filesystem (Little Endian v4.0)", "Firmware / Filesystem", "application/x-squashfs", ".sqsh", "SquashFS.bt",
            span => span.Length >= 16
                ? $"Inodes: {BitConverter.ToUInt32(span.Slice(4, 4))}, BlockSize: {BitConverter.ToUInt32(span.Slice(12, 4))} bytes"
                : "SquashFS LE Superblock"),

        new(0, new byte[] { 0x73, 0x71, 0x73, 0x68 },
            "SquashFS Filesystem (Big Endian)", "Firmware / Filesystem", "application/x-squashfs", ".sqsh", "SquashFS.bt",
            _ => "SquashFS BE Superblock"),

        new(0, new byte[] { 0x27, 0x05, 0x19, 0x56 },
            "Das U-Boot uImage Firmware Header", "Firmware", "application/x-uboot", ".uimage", "UImage.bt",
            _ => "U-Boot Legacy Image"),

        new(0, new byte[] { 0xD0, 0x0D, 0xFE, 0xED },
            "Flattened Device Tree Blob (DTB / FDT)", "Firmware", "application/x-dtb", ".dtb", "DTB.bt",
            span => span.Length >= 8 ? $"Total Size: {ReadBE32(span, 4)} bytes" : "DTB Header"),

        new(0, new byte[] { 0x45, 0x3D, 0xCD, 0x28 },
            "CramFS Compressed ROM Filesystem (LE)", "Firmware / Filesystem", "application/x-cramfs", ".cramfs", "",
            _ => "Linux CramFS Image"),

        new(0, new byte[] { 0x1F, 0x8B, 0x08 },
            "GZip Compressed Stream (DEFLATE)", "Archive", "application/gzip", ".gz", "",
            _ => "GZip DEFLATE Archive"),

        new(0, new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 },
            "XZ Compressed Archive (LZMA2)", "Archive", "application/x-xz", ".xz", "",
            _ => "XZ Stream Header"),

        new(0, new byte[] { 0x28, 0xB5, 0x2F, 0xFD },
            "Zstandard (Zstd) Compressed Stream", "Archive", "application/zstd", ".zst", "",
            _ => "Zstd Frame"),

        new(0, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },
            "7-Zip Archive", "Archive", "application/x-7z-compressed", ".7z", "",
            _ => "7z Signature Header"),

        new(0, new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D },
            "PDF Document", "Document", "application/pdf", ".pdf", "",
            _ => "Adobe Portable Document Format"),

        new(0, new byte[] { 0xFF, 0xD8, 0xFF },
            "JPEG Image", "Image", "image/jpeg", ".jpg", "",
            _ => "JPEG/JFIF SOI Marker"),

        new(0, new byte[] { 0x47, 0x49, 0x46, 0x38 },
            "GIF Image", "Image", "image/gif", ".gif", "",
            _ => "GIF87a / GIF89a"),

        new(0, new byte[] { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 },
            "SQLite 3.x Database", "Database", "application/vnd.sqlite3", ".sqlite", "",
            _ => "SQLite 3 Database Header"),

        new(0, new byte[] { 0xFE, 0xED, 0xFA, 0xCF },
            "Mach-O 64-bit Binary (Big Endian)", "Executable", "application/x-mach-binary", ".macho", "",
            _ => "macOS / iOS Mach-O 64-bit"),

        new(0, new byte[] { 0xCF, 0xFA, 0xED, 0xFE },
            "Mach-O 64-bit Binary (Little Endian)", "Executable", "application/x-mach-binary", ".macho", "",
            _ => "macOS / iOS Mach-O 64-bit LE"),

        new(257, new byte[] { 0x75, 0x73, 0x74, 0x61, 0x72 },
            "POSIX ustar TAR Archive", "Archive", "application/x-tar", ".tar", "",
            _ => "USTAR magic at offset 257")
    };

    public static FileAnalysisReport Analyze(BinaryDocument doc, int entropyBlockCount = 64)
    {
        long length = doc.Length;
        byte[] header = doc.ReadBytes(0, (int)Math.Min(1024, length));

        var matches = IdentifyMagic(header);

        // Compute hashes, CRC32, and byte histogram in a single streaming pass (up to 64 MB for instant UI responsiveness)
        long maxHashLength = Math.Min(length, 64L * 1024 * 1024);
        long[] histogram = new long[256];
        long printableCount = 0;

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        uint crc = 0xFFFFFFFFu;
        byte[] chunk = new byte[64 * 1024];
        long offset = 0;

        while (offset < maxHashLength)
        {
            int toRead = (int)Math.Min(chunk.Length, maxHashLength - offset);
            int read = doc.ReadBytes(offset, chunk.AsSpan(0, toRead));
            if (read <= 0) break;

            ReadOnlySpan<byte> span = chunk.AsSpan(0, read);
            md5.AppendData(span);
            sha1.AppendData(span);
            sha256.AppendData(span);

            for (int i = 0; i < read; i++)
            {
                byte b = span[i];
                histogram[b]++;
                if ((b >= 32 && b < 127) || b == '\r' || b == '\n' || b == '\t')
                    printableCount++;
                crc = UpdateCrc32(crc, b);
            }

            offset += read;
        }
        crc ^= 0xFFFFFFFFu;

        double overallEntropy = CalculateShannonEntropy(histogram, maxHashLength);
        string assessment = overallEntropy switch
        {
            >= 7.85 => "Very High (Encrypted or Compressed)",
            >= 6.80 => "High (Packed / Compiled Native Code or Media)",
            >= 4.50 => "Moderate (Structured Binary / Mixed Code & Data)",
            >= 2.00 => "Low (Text / Sparse Structures)",
            _ => "Very Low (Repetitive / Zero-padded)"
        };

        if (matches.Count == 0)
        {
            if (maxHashLength > 0 && (double)printableCount / maxHashLength > 0.85)
            {
                matches.Add(new FileMagicMatch(
                    "Plain Text / Source File (Heuristic)",
                    "Text",
                    "text/plain",
                    ".txt",
                    "",
                    $"{(double)printableCount / maxHashLength:P1} printable ASCII characters"));
            }
            else
            {
                matches.Add(new FileMagicMatch(
                    "Unknown / Raw Binary Data",
                    "Binary",
                    "application/octet-stream",
                    ".bin",
                    "",
                    "No known magic header at offset 0x00, inspect with Binwalk or custom .bt template"));
            }
        }

        double[] blockEntropies = ComputeBlockEntropies(doc, entropyBlockCount);

        int printablePct = maxHashLength > 0 ? (int)Math.Round(printableCount * 100.0 / maxHashLength) : 0;
        int nullPct = maxHashLength > 0 ? (int)Math.Round(histogram[0] * 100.0 / maxHashLength) : 0;

        var exifTags = ExifMetadataExtractor.Extract(doc, tryExternalExifTool: true);

        return new FileAnalysisReport(
            FileName: doc.DisplayName,
            FullPath: doc.FilePath,
            FileSize: length,
            FormattedSize: FormatBytes(length),
            MagicMatches: matches,
            ExifAndFormatTags: exifTags,
            Crc32Hex: $"{crc:X8}",
            Md5Hex: Convert.ToHexString(md5.GetHashAndReset()),
            Sha1Hex: Convert.ToHexString(sha1.GetHashAndReset()),
            Sha256Hex: Convert.ToHexString(sha256.GetHashAndReset()),
            OverallEntropy: Math.Round(overallEntropy, 4),
            EntropyAssessment: assessment,
            BlockEntropies: blockEntropies,
            ByteHistogram: histogram,
            PrintableAsciiPercent: printablePct,
            NullBytePercent: nullPct);
    }

    public static List<FileMagicMatch> IdentifyMagic(ReadOnlySpan<byte> headerBytes)
    {
        var matches = new List<FileMagicMatch>();
        foreach (var rule in Rules)
        {
            if (headerBytes.Length >= rule.Offset + rule.Signature.Length)
            {
                var slice = headerBytes.Slice(rule.Offset, rule.Signature.Length);
                if (slice.SequenceEqual(rule.Signature))
                {
                    string details = rule.DetailExtractor?.Invoke(headerBytes) ?? "";
                    matches.Add(new FileMagicMatch(
                        rule.FormatName,
                        rule.Category,
                        rule.MimeType,
                        rule.Extension,
                        rule.RecommendedTemplate,
                        details));
                }
            }
        }
        return matches;
    }

    public static double CalculateShannonEntropy(ReadOnlySpan<long> histogram, long totalBytes)
    {
        if (totalBytes <= 0) return 0.0;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            long count = histogram[i];
            if (count > 0)
            {
                double p = (double)count / totalBytes;
                entropy -= p * Math.Log2(p);
            }
        }
        return entropy;
    }

    private static double[] ComputeBlockEntropies(BinaryDocument doc, int blockCount)
    {
        if (doc.Length == 0 || blockCount <= 0)
            return Array.Empty<double>();

        int actualBlocks = (int)Math.Min(blockCount, Math.Max(1, doc.Length / 16));
        double[] results = new double[actualBlocks];
        long blockSize = Math.Max(1, doc.Length / actualBlocks);
        int sampleCap = (int)Math.Min(blockSize, 4096);
        byte[] sampleBuf = new byte[sampleCap];
        long[] hist = new long[256];

        for (int b = 0; b < actualBlocks; b++)
        {
            Array.Clear(hist);
            long start = b * blockSize;
            int read = doc.ReadBytes(start, sampleBuf);
            for (int i = 0; i < read; i++)
                hist[sampleBuf[i]]++;
            results[b] = Math.Round(CalculateShannonEntropy(hist, read), 3);
        }

        return results;
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double val = bytes;
        int unitIdx = 0;
        while (val >= 1024 && unitIdx < units.Length - 1)
        {
            val /= 1024;
            unitIdx++;
        }
        return unitIdx == 0 ? $"{bytes:N0} B" : $"{val:F2} {units[unitIdx]} ({bytes:N0} bytes)";
    }

    private static uint ReadBE32(ReadOnlySpan<byte> s, int offset)
    {
        return ((uint)s[offset] << 24) | ((uint)s[offset + 1] << 16) | ((uint)s[offset + 2] << 8) | s[offset + 3];
    }

    private static readonly uint[] Crc32Table = BuildCrc32Table();

    private static uint[] BuildCrc32Table()
    {
        uint[] table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        return table;
    }

    private static uint UpdateCrc32(uint crc, byte b)
    {
        return Crc32Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
}

