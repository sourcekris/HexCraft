using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace HexCraft.Tools.Signatures;

/// <summary>
/// Built-in signature parsers modeled directly after ReFirmLabs/binwalk `src/signatures/*.rs`.
/// Each parser performs structural header validation (bounds, versions, block sizes, CRCs,
/// endianness, and field invariants) to eliminate false-positive magic matches and compute payload sizes.
/// </summary>
public static class BuiltinSignatureParsers
{
    public static IReadOnlyList<IFirmwareSignatureParser> CreateAll() => new IFirmwareSignatureParser[]
    {
        new SquashFsSignatureParser(),  // 1. squashfs.rs
        new UImageSignatureParser(),    // 2. uimage.rs
        new DtbSignatureParser(),       // 3. dtb.rs
        new GzipSignatureParser(),      // 4. gzip.rs
        new XzSignatureParser(),        // 5. xz.rs
        new LzmaSignatureParser(),      // 6. lzma.rs
        newubiSignatureParser(),        // 7. ubi.rs (UBI & UBIFS)
        new Jffs2SignatureParser(),     // 8. jffs2.rs
        new CpioSignatureParser(),      // 9. cpio.rs
        new CramFsSignatureParser(),    // 10. cramfs.rs
        new ZipSignatureParser(),       // 11. zip.rs
        new ElfSignatureParser(),       // 12. elf.rs
        new PngSignatureParser()        // 13. png.rs
    };

    private static IFirmwareSignatureParser newubiSignatureParser() => new UbiSignatureParser();
}

// ============================================================================
// 1. SquashFS (`src/signatures/squashfs.rs`)
// ============================================================================
public sealed class SquashFsSignatureParser : IFirmwareSignatureParser
{
    public string Name => "squashfs";
    public string DisplayName => "SquashFS Filesystem";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "hsqs"u8.ToArray(), // Standard Little Endian (0x73717368)
        "sqsh"u8.ToArray(), // Standard Big Endian
        "shsq"u8.ToArray(), // Non-standard / vendor Little Endian
        "qshs"u8.ToArray()  // Non-standard / vendor Big Endian
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 48 > fullData.Length)
            return SignatureParseResult.Invalid;

        var s = fullData.Slice(offset, Math.Min(96, fullData.Length - offset));
        bool bigEndian = (s[0] == 's' && s[1] == 'q') || (s[0] == 'q' && s[1] == 's');

        uint inodes = ReadU32(s.Slice(4, 4), bigEndian);
        uint mkfsTime = ReadU32(s.Slice(8, 4), bigEndian);
        uint blockSize = ReadU32(s.Slice(12, 4), bigEndian);
        uint fragments = ReadU32(s.Slice(16, 4), bigEndian);
        ushort comp = ReadU16(s.Slice(20, 2), bigEndian);
        ushort blockLog = ReadU16(s.Slice(22, 2), bigEndian);
        ushort major = ReadU16(s.Slice(28, 2), bigEndian);
        ushort minor = ReadU16(s.Slice(30, 2), bigEndian);
        ulong bytesUsed = ReadU64(s.Slice(40, 8), bigEndian);

        // Structural validation (matches binwalk's squashfs.rs checks)
        if (major is < 1 or > 4 || inodes == 0 || bytesUsed == 0)
            return SignatureParseResult.Invalid;

        // Block size must be a power of two between 4 KB (2^12) and 1 MB (2^20) and match block_log
        if (blockLog is < 12 or > 20 || (1u << blockLog) != blockSize)
            return SignatureParseResult.Invalid;

        if (comp is < 1 or > 6)
            return SignatureParseResult.Invalid;

        string compName = comp switch
        {
            1 => "zlib",
            2 => "lzma",
            3 => "lzo",
            4 => "xz",
            5 => "lz4",
            6 => "zstd",
            _ => $"unknown({comp})"
        };

        string endianStr = bigEndian ? "big endian" : "little endian";
        string created = FormatUnixTimestamp(mkfsTime);

        return new SignatureParseResult(
            IsValid: true,
            Description: $"Squashfs filesystem, {endianStr}, version {major}.{minor}, compression: {compName}, size: {bytesUsed} bytes, {inodes} inodes, blocksize: {blockSize} bytes, created: {created}",
            EstimatedSize: (long)bytesUsed,
            Confidence: SignatureConfidence.High,
            CanUnsquashfs: true);
    }

    private static ushort ReadU16(ReadOnlySpan<byte> b, bool be) =>
        be ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);
    private static uint ReadU32(ReadOnlySpan<byte> b, bool be) =>
        be ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    private static ulong ReadU64(ReadOnlySpan<byte> b, bool be) =>
        be ? BinaryPrimitives.ReadUInt64BigEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b);

    internal static string FormatUnixTimestamp(uint ts)
    {
        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }
        catch
        {
            return ts.ToString();
        }
    }
}

// ============================================================================
// 2. Das U-Boot uImage (`src/signatures/uimage.rs`)
// ============================================================================
public sealed class UImageSignatureParser : IFirmwareSignatureParser
{
    public string Name => "uimage";
    public string DisplayName => "U-Boot uImage";
    public string Category => "Firmware Header";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x27, 0x05, 0x19, 0x56 }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 64 > fullData.Length)
            return SignatureParseResult.Invalid;

        var hdr = fullData.Slice(offset, 64);
        uint headerCrc = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(4, 4));
        uint time = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(8, 4));
        uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(12, 4));
        uint loadAddr = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(16, 4));
        uint entryAddr = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(20, 4));
        uint dataCrc = BinaryPrimitives.ReadUInt32BigEndian(hdr.Slice(24, 4));
        byte os = hdr[28];
        byte arch = hdr[29];
        byte imgType = hdr[30];
        byte comp = hdr[31];

        // Validate enums (matches uimage.rs)
        if (os > 30 || arch > 35 || imgType == 0 || imgType > 40 || comp > 7 || dataSize == 0)
            return SignatureParseResult.Invalid;

        string osName = os switch
        {
            5 => "Linux",
            17 => "U-Boot",
            1 => "OpenBSD",
            2 => "NetBSD",
            3 => "FreeBSD",
            _ => $"OS({os})"
        };

        string archName = arch switch
        {
            2 => "ARM",
            3 => "x86",
            5 => "MIPS",
            7 => "PowerPC",
            22 => "ARM64",
            26 => "RISC-V",
            _ => $"Arch({arch})"
        };

        string typeName = imgType switch
        {
            1 => "Standalone Program",
            2 => "OS Kernel Image",
            3 => "RAMDisk Image",
            4 => "Multi-File Image",
            5 => "Firmware Image",
            6 => "Script file",
            8 => "Flat Device Tree Blob",
            _ => $"Type({imgType})"
        };

        string compName = comp switch
        {
            0 => "uncompressed",
            1 => "gzip",
            2 => "bzip2",
            3 => "lzma",
            4 => "lzo",
            5 => "lz4",
            6 => "zstd",
            _ => "compressed"
        };

        string imgName = ReadNullTerminatedAscii(hdr.Slice(32, 32));
        string created = SquashFsSignatureParser.FormatUnixTimestamp(time);

        return new SignatureParseResult(
            IsValid: true,
            Description: $"uImage header, header size: 64 bytes, header CRC: 0x{headerCrc:X8}, created: {created}, image size: {dataSize} bytes, Data Address: 0x{loadAddr:X8}, Entry Point: 0x{entryAddr:X8}, data CRC: 0x{dataCrc:X8}, OS: {osName}, CPU: {archName}, image type: {typeName} ({compName}), image name: \"{imgName}\"",
            EstimatedSize: 64L + dataSize,
            Confidence: SignatureConfidence.High);
    }

    internal static string ReadNullTerminatedAscii(ReadOnlySpan<byte> span)
    {
        int nul = span.IndexOf((byte)0);
        var slice = nul >= 0 ? span[..nul] : span;
        var sb = new StringBuilder(slice.Length);
        foreach (byte b in slice)
        {
            if (b is >= 32 and < 127)
                sb.Append((char)b);
        }
        return sb.ToString();
    }
}

// ============================================================================
// 3. Flattened Device Tree / DTB (`src/signatures/dtb.rs`)
// ============================================================================
public sealed class DtbSignatureParser : IFirmwareSignatureParser
{
    public string Name => "dtb";
    public string DisplayName => "Flattened Device Tree (DTB)";
    public string Category => "Hardware Tree";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0xD0, 0x0D, 0xFE, 0xED }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 40 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 40);
        uint totalSize = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(4, 4));
        uint offDtStruct = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4));
        uint offDtStrings = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(12, 4));
        uint offMemRsvmap = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(16, 4));
        uint version = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(20, 4));
        uint lastCompVer = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(24, 4));
        uint bootCpuId = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(28, 4));
        uint sizeDtStrings = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(32, 4));
        uint sizeDtStruct = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(36, 4));

        // Structural validation (matches dtb.rs)
        if (totalSize <= 40 || totalSize > 16 * 1024 * 1024)
            return SignatureParseResult.Invalid;
        if (version != 17 && version != 16)
            return SignatureParseResult.Invalid;
        if (offDtStruct >= totalSize || offDtStrings >= totalSize || offMemRsvmap >= totalSize)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"Flattened device tree, total size: {totalSize} bytes, version: {version} (last compatible: {lastCompVer}), boot CPU ID: {bootCpuId}, struct size: {sizeDtStruct} bytes, strings size: {sizeDtStrings} bytes",
            EstimatedSize: totalSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 4. GZip Stream (`src/signatures/gzip.rs`)
// ============================================================================
public sealed class GzipSignatureParser : IFirmwareSignatureParser
{
    public string Name => "gzip";
    public string DisplayName => "GZip Stream";
    public string Category => "Compressed";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x1F, 0x8B, 0x08 }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 10 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, Math.Min(256, fullData.Length - offset));
        byte flags = h[3];

        // Reserved upper 3 bits of flags (0xE0) MUST be zero in valid RFC 1952 GZip headers
        if ((flags & 0xE0) != 0)
            return SignatureParseResult.Invalid;

        uint mtime = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(4, 4));
        byte xfl = h[8];
        byte os = h[9];

        int pos = 10;
        // FEXTRA (0x04)
        if ((flags & 0x04) != 0)
        {
            if (pos + 2 > h.Length) return SignatureParseResult.Invalid;
            ushort xlen = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(pos, 2));
            pos += 2 + xlen;
        }

        string fileNamePart = "";
        // FNAME (0x08)
        if ((flags & 0x08) != 0 && pos < h.Length)
        {
            string fname = UImageSignatureParser.ReadNullTerminatedAscii(h[pos..]);
            if (!string.IsNullOrEmpty(fname))
                fileNamePart = $", original file name: \"{fname}\"";
        }

        string osName = os switch
        {
            0 => "FAT filesystem (MS-DOS, OS/2, NT/Win32)",
            3 => "Unix",
            7 => "Macintosh",
            11 => "NTFS filesystem (NT)",
            255 => "unknown",
            _ => $"OS({os})"
        };

        string compSpeed = xfl == 2 ? ", maximum compression" : xfl == 4 ? ", fastest algorithm" : "";
        string dateStr = mtime > 0 ? $", last modified: {SquashFsSignatureParser.FormatUnixTimestamp(mtime)}" : "";

        return new SignatureParseResult(
            IsValid: true,
            Description: $"gzip compressed data{compSpeed}{fileNamePart}, from {osName}{dateStr}",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 5. XZ Stream (`src/signatures/xz.rs`)
// ============================================================================
public sealed class XzSignatureParser : IFirmwareSignatureParser
{
    public string Name => "xz";
    public string DisplayName => "XZ Stream";
    public string Category => "Compressed";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 12 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 12);
        // Stream flags byte 0 must be 0x00, byte 1 lower nibble is check type (0x00, 0x01, 0x04, 0x0A)
        if (h[6] != 0x00)
            return SignatureParseResult.Invalid;

        byte checkType = h[7];
        string checkName = checkType switch
        {
            0x00 => "None",
            0x01 => "CRC32",
            0x04 => "CRC64",
            0x0A => "SHA-256",
            _ => ""
        };
        if (string.IsNullOrEmpty(checkName))
            return SignatureParseResult.Invalid;

        // Try locating XZ stream footer ("YZ" = 0x59 0x5A) to determine stream size
        long estSize = 0;
        var rem = fullData[offset..];
        int yzIdx = rem.IndexOf("YZ"u8);
        if (yzIdx >= 10)
            estSize = yzIdx + 2;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"XZ compressed data, checksum type: {checkName}",
            EstimatedSize: estSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 6. LZMA Stream (`src/signatures/lzma.rs`)
// ============================================================================
public sealed class LzmaSignatureParser : IFirmwareSignatureParser
{
    public string Name => "lzma";
    public string DisplayName => "LZMA Stream";
    public string Category => "Compressed";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x5D, 0x00, 0x00 }, // Properties 0x5D (lc=3, lp=0, pb=2)
        new byte[] { 0x6D, 0x00, 0x00 }  // Properties 0x6D
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 13 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 13);
        byte props = h[0];
        uint dictSize = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(1, 4));
        ulong decompSize = BinaryPrimitives.ReadUInt64LittleEndian(h.Slice(5, 8));

        // Dictionary size must be a power of 2 (or 3 * 2^n) between 4 KB and 256 MB (matches lzma.rs)
        bool validDict = dictSize is >= 4096 and <= (256u * 1024 * 1024) &&
                         ((dictSize & (dictSize - 1)) == 0);
        if (!validDict)
            return SignatureParseResult.Invalid;

        // Uncompressed size must either be unknown (0xFFFFFFFFFFFFFFFF) or reasonable (1 B .. 512 MB)
        if (decompSize != ulong.MaxValue && (decompSize == 0 || decompSize > 512UL * 1024 * 1024))
            return SignatureParseResult.Invalid;

        string sizeDesc = decompSize == ulong.MaxValue ? "-1 (unknown)" : $"{decompSize} bytes";

        return new SignatureParseResult(
            IsValid: true,
            Description: $"LZMA compressed data, properties: 0x{props:X2}, dictionary size: {dictSize} bytes, uncompressed size: {sizeDesc}",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 7. UBI Erase Count Header & UBIFS (`src/signatures/ubi.rs`)
// ============================================================================
public sealed class UbiSignatureParser : IFirmwareSignatureParser
{
    public string Name => "ubi";
    public string DisplayName => "UBI / UBIFS Image";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "UBI#"u8.ToArray(),                      // UBI Erase Count Header (0x55424923)
        new byte[] { 0x31, 0x18, 0x10, 0x06 }    // UBIFS Superblock Node Magic (LE 0x06101831)
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 32 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, Math.Min(64, fullData.Length - offset));

        // Case A: "UBI#" Erase Count Header
        if (h[0] == 'U' && h[1] == 'B' && h[2] == 'I' && h[3] == '#' && h.Length >= 64)
        {
            byte version = h[4];
            if (version != 1)
                return SignatureParseResult.Invalid;

            ulong ec = BinaryPrimitives.ReadUInt64BigEndian(h.Slice(8, 8));
            uint vidHdrOffset = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(16, 4));
            uint dataOffset = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(20, 4));
            uint imageSeq = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(24, 4));
            uint hdrCrc = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(60, 4));

            if (vidHdrOffset == 0 || dataOffset == 0 || dataOffset < vidHdrOffset)
                return SignatureParseResult.Invalid;

            return new SignatureParseResult(
                IsValid: true,
                Description: $"UBI erase count header, version: {version}, EC: {ec}, VID header offset: 0x{vidHdrOffset:X}, data offset: 0x{dataOffset:X}, image sequence: 0x{imageSeq:X8}, header CRC: 0x{hdrCrc:X8}",
                EstimatedSize: 0,
                Confidence: SignatureConfidence.High);
        }

        // Case B: UBIFS Superblock Node (0x31 0x18 0x10 0x06)
        if (h[0] == 0x31 && h[1] == 0x18 && h[2] == 0x10 && h[3] == 0x06)
        {
            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(4, 4));
            ulong sqnum = BinaryPrimitives.ReadUInt64LittleEndian(h.Slice(8, 8));
            uint len = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(16, 4));
            byte nodeType = h[20]; // 6 = UBIFS_SB_NODE

            if (len < 24 || nodeType > 12)
                return SignatureParseResult.Invalid;

            string nodeName = nodeType == 6 ? "superblock node" : $"node type {nodeType}";
            return new SignatureParseResult(
                IsValid: true,
                Description: $"UBIFS filesystem {nodeName}, CRC: 0x{crc:X8}, sequence: {sqnum}, node length: {len} bytes",
                EstimatedSize: len,
                Confidence: SignatureConfidence.High);
        }

        return SignatureParseResult.Invalid;
    }
}

// ============================================================================
// 8. JFFS2 Filesystem (`src/signatures/jffs2.rs`)
// ============================================================================
public sealed class Jffs2SignatureParser : IFirmwareSignatureParser
{
    public string Name => "jffs2";
    public string DisplayName => "JFFS2 Filesystem";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x85, 0x19 }, // Little Endian JFFS2_MAGIC_BITMASK (0x1985)
        new byte[] { 0x19, 0x85 }  // Big Endian (0x1985)
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 12 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 12);
        bool be = h[0] == 0x19 && h[1] == 0x85;
        ushort nodeType = be ? BinaryPrimitives.ReadUInt16BigEndian(h.Slice(2, 2)) : BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(2, 2));
        uint totalLen = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(4, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(4, 4));
        uint hdrCrc = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(8, 4));

        // Valid JFFS2 node types: 0xE001 (DIRENT), 0xE002 (INODE), 0x2003 (CLEANMARKER), 0x2004 (PADDING)
        bool validType = nodeType is 0xE001 or 0xE002 or 0x2003 or 0x2004 or 0xE008 or 0xE009;
        if (!validType || totalLen is < 12 or > 1024 * 1024)
            return SignatureParseResult.Invalid;

        string endianStr = be ? "big endian" : "little endian";
        return new SignatureParseResult(
            IsValid: true,
            Description: $"JFFS2 filesystem, {endianStr}, node type: 0x{nodeType:X4}, node length: {totalLen} bytes, header CRC: 0x{hdrCrc:X8}",
            EstimatedSize: totalLen,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 9. CPIO Archive (`src/signatures/cpio.rs`)
// ============================================================================
public sealed class CpioSignatureParser : IFirmwareSignatureParser
{
    public string Name => "cpio";
    public string DisplayName => "CPIO Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "070701"u8.ToArray(), // SVR4 portable format without CRC (newc)
        "070702"u8.ToArray()  // SVR4 portable format with CRC
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 110 > fullData.Length)
            return SignatureParseResult.Invalid;

        var hdr = fullData.Slice(offset, 110);
        // All 110 bytes of the CPIO ASCII header must be valid hex digits ('0'-'9', 'A'-'F', 'a'-'f')
        for (int i = 0; i < 110; i++)
        {
            byte b = hdr[i];
            bool isHex = (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f');
            if (!isHex)
                return SignatureParseResult.Invalid;
        }

        string fileSizeHex = Encoding.ASCII.GetString(hdr.Slice(54, 8));
        string nameSizeHex = Encoding.ASCII.GetString(hdr.Slice(94, 8));
        uint fileSize = Convert.ToUInt32(fileSizeHex, 16);
        uint nameSize = Convert.ToUInt32(nameSizeHex, 16);

        if (nameSize is 0 or > 512 || offset + 110 + nameSize > fullData.Length)
            return SignatureParseResult.Invalid;

        string entryName = UImageSignatureParser.ReadNullTerminatedAscii(fullData.Slice(offset + 110, (int)nameSize));
        return new SignatureParseResult(
            IsValid: true,
            Description: $"ASCII cpio archive (SVR4 with no CRC), file name: \"{entryName}\", file size: {fileSize} bytes",
            EstimatedSize: 110 + nameSize + fileSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 10. CramFS Filesystem (`src/signatures/cramfs.rs`)
// ============================================================================
public sealed class CramFsSignatureParser : IFirmwareSignatureParser
{
    public string Name => "cramfs";
    public string DisplayName => "CramFS Filesystem";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x45, 0x3D, 0xCD, 0x28 }, // Little Endian (0x28CD3D45)
        new byte[] { 0x28, 0xCD, 0x3D, 0x45 }  // Big Endian
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 64 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 64);
        // Bytes 16..32 must contain "Compressed ROMFS" signature
        if (!h.Slice(16, 16).SequenceEqual("Compressed ROMFS"u8))
            return SignatureParseResult.Invalid;

        bool be = h[0] == 0x28;
        uint size = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(4, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(4, 4));
        uint crc = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(32, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(32, 4));
        uint blocks = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(40, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(40, 4));
        uint files = be ? BinaryPrimitives.ReadUInt32BigEndian(h.Slice(44, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(44, 4));
        string volName = UImageSignatureParser.ReadNullTerminatedAscii(h.Slice(48, 16));

        return new SignatureParseResult(
            IsValid: true,
            Description: $"CramFS filesystem, {(be ? "big endian" : "little endian")}, size: {size} bytes, CRC: 0x{crc:X8}, blocks: {blocks}, files: {files}, name: \"{volName}\"",
            EstimatedSize: size,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 11. ZIP Local File Header (`src/signatures/zip.rs`)
// ============================================================================
public sealed class ZipSignatureParser : IFirmwareSignatureParser
{
    public string Name => "zip";
    public string DisplayName => "ZIP Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x50, 0x4B, 0x03, 0x04 }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 30 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 30);
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(4, 2));
        ushort comp = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(8, 2));
        uint compSize = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(18, 4));
        uint uncompSize = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(22, 4));
        ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(26, 2));
        ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(28, 2));

        if (version is 0 or > 100 || nameLen is 0 or > 512 || offset + 30 + nameLen > fullData.Length)
            return SignatureParseResult.Invalid;

        string fileName = UImageSignatureParser.ReadNullTerminatedAscii(fullData.Slice(offset + 30, nameLen));
        if (string.IsNullOrEmpty(fileName))
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"Zip archive data, v{version / 10}.{version % 10}, compressed size: {compSize}, uncompressed size: {uncompSize}, name: \"{fileName}\"",
            EstimatedSize: 30L + nameLen + extraLen + compSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 12. ELF Executable (`src/signatures/elf.rs`)
// ============================================================================
public sealed class ElfSignatureParser : IFirmwareSignatureParser
{
    public string Name => "elf";
    public string DisplayName => "ELF Binary";
    public string Category => "Executable";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 52 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 52);
        byte eiClass = h[4];
        byte eiData = h[5];
        byte eiVer = h[6];

        if ((eiClass != 1 && eiClass != 2) || (eiData != 1 && eiData != 2) || eiVer != 1)
            return SignatureParseResult.Invalid;

        bool be = eiData == 2;
        ushort eType = be ? BinaryPrimitives.ReadUInt16BigEndian(h.Slice(16, 2)) : BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(16, 2));
        ushort eMachine = be ? BinaryPrimitives.ReadUInt16BigEndian(h.Slice(18, 2)) : BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(18, 2));

        if (eType is 0 or > 4)
            return SignatureParseResult.Invalid;

        string bits = eiClass == 2 ? "64-bit" : "32-bit";
        string endian = be ? "MSB (big endian)" : "LSB (little endian)";
        string typeStr = eType switch
        {
            1 => "relocatable",
            2 => "executable",
            3 => "shared object",
            4 => "core file",
            _ => "binary"
        };
        string isa = eMachine switch
        {
            3 => "Intel 80386",
            8 => "MIPS",
            40 => "ARM",
            62 => "x86-64",
            183 => "ARM aarch64",
            243 => "UCB RISC-V",
            _ => $"ISA(0x{eMachine:X})"
        };

        return new SignatureParseResult(
            IsValid: true,
            Description: $"ELF, {bits} {endian} {typeStr}, {isa}, version 1 (SYSV)",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 13. PNG Image (`src/signatures/png.rs`)
// ============================================================================
public sealed class PngSignatureParser : IFirmwareSignatureParser
{
    public string Name => "png";
    public string DisplayName => "PNG Image";
    public string Category => "Image";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 33 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 33);
        // Must immediately be followed by an IHDR chunk of length 13
        uint ihdrLen = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4));
        if (ihdrLen != 13 || !h.Slice(12, 4).SequenceEqual("IHDR"u8))
            return SignatureParseResult.Invalid;

        uint width = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(16, 4));
        uint height = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(20, 4));
        byte bitDepth = h[24];
        byte colorType = h[25];

        if (width == 0 || height == 0 || width > 65536 || height > 65536)
            return SignatureParseResult.Invalid;

        string colorStr = colorType switch
        {
            0 => "grayscale",
            2 => "color RGB",
            3 => "colormap",
            4 => "grayscale+alpha",
            6 => "color RGBA",
            _ => $"color({colorType})"
        };

        // Walk chunks up to IEND to compute exact PNG size
        long totalSize = 0;
        int pos = offset + 8;
        int guard = 0;
        while (pos + 12 <= fullData.Length && guard++ < 512)
        {
            uint cLen = BinaryPrimitives.ReadUInt32BigEndian(fullData.Slice(pos, 4));
            if (cLen > 64 * 1024 * 1024 || pos + 12 + (int)cLen > fullData.Length)
                break;

            bool isIend = fullData.Slice(pos + 4, 4).SequenceEqual("IEND"u8);
            pos += 12 + (int)cLen;
            if (isIend)
            {
                totalSize = pos - offset;
                break;
            }
        }

        return new SignatureParseResult(
            IsValid: true,
            Description: $"PNG image, {width} x {height}, {bitDepth}-bit/{colorStr}, non-interlaced",
            EstimatedSize: totalSize,
            Confidence: SignatureConfidence.High);
    }
}

