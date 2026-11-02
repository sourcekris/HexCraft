using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace HexCraft.Tools.Signatures;

/// <summary>
/// Extended Binwalk signature parsers modeled after ReFirmLabs/binwalk `src/signatures/*.rs`:
///   - trx.rs (Broadcom / Asus TRX Firmware Header)
///   - seama.rs (SEAMA D-Link / EnGenius Firmware Header)
///   - dlob.rs (D-Link DLOB Firmware Header)
///   - tar.rs (POSIX ustar TAR Archive)
///   - sevenzip.rs (7-Zip Archive)
///   - bzip2.rs (BZip2 Compressed Stream)
///   - zstd.rs (Zstandard Compressed Stream)
///   - pem.rs (PEM Certificates & Private Keys)
///   - openssl.rs (OpenSSL Salted__ Encrypted Data)
///   - ext.rs (Linux EXT2 / EXT3 / EXT4 Filesystem Superblock)
///   - romfs.rs (romfs v1 Filesystem)
/// </summary>
public static class ExtendedSignatureParsers
{
    public static IReadOnlyList<IFirmwareSignatureParser> CreateAll() => new IFirmwareSignatureParser[]
    {
        new TrxSignatureParser(),       // 14. trx.rs
        new SeamaSignatureParser(),     // 15. seama.rs
        new DlobSignatureParser(),      // 16. dlob.rs
        new TarSignatureParser(),       // 17. tar.rs
        new SevenZipSignatureParser(),  // 18. sevenzip.rs
        new Bzip2SignatureParser(),     // 19. bzip2.rs
        new ZstdSignatureParser(),      // 20. zstd.rs
        new PemSignatureParser(),       // 21. pem.rs
        new OpenSslCryptSignatureParser(), // 22. openssl.rs
        new ExtFsSignatureParser(),     // 23. ext.rs
        new RomFsSignatureParser()      // 24. romfs.rs
    };
}

// ============================================================================
// 14. Broadcom / Asus TRX Firmware Header (`src/signatures/trx.rs`)
// ============================================================================
public sealed class TrxSignatureParser : IFirmwareSignatureParser
{
    public string Name => "trx";
    public string DisplayName => "Broadcom TRX Firmware";
    public string Category => "Firmware Header";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "HDR0"u8.ToArray() // 0x30524448 LE
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 28 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 28);
        uint totalLen = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(4, 4));
        uint crc32 = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(8, 4));
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(12, 2));
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(h.Slice(14, 2));
        uint part0 = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(16, 4));
        uint part1 = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(20, 4));
        uint part2 = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(24, 4));

        // Structural validation (matches trx.rs: version 1 or 2, totalLen > 28, partition offsets within totalLen)
        if ((version != 1 && version != 2) || totalLen <= 28 || totalLen > 512 * 1024 * 1024)
            return SignatureParseResult.Invalid;
        if (part0 >= totalLen || part1 >= totalLen || part2 >= totalLen)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"TRX firmware header, little endian, image size: {totalLen} bytes, CRC32: 0x{crc32:X8}, flags: 0x{flags:X4}, version: {version}, partition offsets: [0x{part0:X}, 0x{part1:X}, 0x{part2:X}]",
            EstimatedSize: totalLen,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 15. SEAMA Firmware Header (`src/signatures/seama.rs`)
// ============================================================================
public sealed class SeamaSignatureParser : IFirmwareSignatureParser
{
    public string Name => "seama";
    public string DisplayName => "SEAMA Firmware Header";
    public string Category => "Firmware Header";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x5E, 0xA3, 0xA4, 0x17 } // SEAMA magic (0x5EA3A417 BE)
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 28 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, Math.Min(128, fullData.Length - offset));
        ushort reserved = BinaryPrimitives.ReadUInt16BigEndian(h.Slice(4, 2));
        ushort metaSize = BinaryPrimitives.ReadUInt16BigEndian(h.Slice(6, 2));
        uint imageSize = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4));

        if (reserved != 0 || metaSize > 1024 || imageSize > 512 * 1024 * 1024)
            return SignatureParseResult.Invalid;

        string md5Hex = Convert.ToHexString(h.Slice(12, 16));
        long totalSize = 28L + metaSize + imageSize;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"SEAMA firmware header, big endian, meta size: {metaSize} bytes, image size: {imageSize} bytes, MD5: {md5Hex}",
            EstimatedSize: totalSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 16. D-Link DLOB Firmware Header (`src/signatures/dlob.rs`)
// ============================================================================
public sealed class DlobSignatureParser : IFirmwareSignatureParser
{
    public string Name => "dlob";
    public string DisplayName => "D-Link DLOB Header";
    public string Category => "Firmware Header";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x5E, 0xA3, 0xA4, 0x17 },
        "<<>>"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        // Standard DLOB header starts with 0x5EA3A417 followed by secondary 0x5EA3A417 at offset +0x10 or "dlob.sbin"
        if (offset + 0x2C > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, Math.Min(128, fullData.Length - offset));
        if (h[0] == 0x5E && h[1] == 0xA3 && h[2] == 0xA4 && h[3] == 0x17)
        {
            // Distinguish DLOB from SEAMA: DLOB has a second 0x5EA3A417 magic at +0x1C or +0x24
            int secondMagic = h[12..].IndexOf(new byte[] { 0x5E, 0xA3, 0xA4, 0x17 });
            if (secondMagic < 0)
                return SignatureParseResult.Invalid;

            uint headerMetaSize = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(4, 4));
            uint payloadSize = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4));
            return new SignatureParseResult(
                IsValid: true,
                Description: $"D-Link DLOB firmware header, meta size: {headerMetaSize} bytes, data size: {payloadSize} bytes",
                EstimatedSize: 0x2C + headerMetaSize + payloadSize,
                Confidence: SignatureConfidence.High);
        }

        return SignatureParseResult.Invalid;
    }
}

// ============================================================================
// 17. POSIX ustar TAR Archive (`src/signatures/tar.rs`)
// ============================================================================
public sealed class TarSignatureParser : IFirmwareSignatureParser
{
    public string Name => "tar";
    public string DisplayName => "POSIX TAR Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "ustar\0"u8.ToArray(),
        "ustar  \0"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        // "ustar" magic is located at offset +257 inside a 512-byte TAR block header
        int headerStart = offset - 257;
        if (headerStart < 0 || headerStart + 512 > fullData.Length)
            return SignatureParseResult.Invalid;

        var block = fullData.Slice(headerStart, 512);
        string entryName = UImageSignatureParser.ReadNullTerminatedAscii(block[..100]);
        if (string.IsNullOrEmpty(entryName))
            return SignatureParseResult.Invalid;

        // Parse octal size field at 124..136
        string sizeOctal = UImageSignatureParser.ReadNullTerminatedAscii(block.Slice(124, 12)).Trim();
        long entrySize = 0;
        if (!string.IsNullOrEmpty(sizeOctal))
        {
            try
            {
                entrySize = Convert.ToInt64(sizeOctal, 8);
            }
            catch
            {
                return SignatureParseResult.Invalid;
            }
        }

        // Verify TAR header checksum (bytes 148..156 treated as spaces ' ')
        string chkOctal = UImageSignatureParser.ReadNullTerminatedAscii(block.Slice(148, 8)).Trim();
        if (string.IsNullOrEmpty(chkOctal))
            return SignatureParseResult.Invalid;

        int expectedChk;
        try
        {
            expectedChk = Convert.ToInt32(chkOctal, 8);
        }
        catch
        {
            return SignatureParseResult.Invalid;
        }

        int computedUnsigned = 0;
        for (int i = 0; i < 512; i++)
        {
            computedUnsigned += (i >= 148 && i < 156) ? (byte)' ' : block[i];
        }
        if (computedUnsigned != expectedChk)
            return SignatureParseResult.Invalid;

        // Calculate total TAR archive size by walking 512-byte blocks
        long totalArchiveBytes = 512 + ((entrySize + 511) / 512) * 512;
        int cur = headerStart + (int)totalArchiveBytes;
        int entriesCount = 1;
        while (cur + 512 <= fullData.Length && entriesCount < 4096)
        {
            var nextBlk = fullData.Slice(cur, 512);
            // Two consecutive zero blocks mark end of archive
            if (IsAllZero(nextBlk))
            {
                totalArchiveBytes += 512;
                if (cur + 1024 <= fullData.Length && IsAllZero(fullData.Slice(cur + 512, 512)))
                    totalArchiveBytes += 512;
                break;
            }

            if (!nextBlk.Slice(257, 5).SequenceEqual("ustar"u8))
                break;

            string nextSizeStr = UImageSignatureParser.ReadNullTerminatedAscii(nextBlk.Slice(124, 12)).Trim();
            long nextSize = 0;
            try { if (!string.IsNullOrEmpty(nextSizeStr)) nextSize = Convert.ToInt64(nextSizeStr, 8); }
            catch { break; }

            long step = 512 + ((nextSize + 511) / 512) * 512;
            totalArchiveBytes += step;
            cur += (int)step;
            entriesCount++;
        }

        return new SignatureParseResult(
            IsValid: true,
            Description: $"POSIX tar archive, first entry: \"{entryName}\", {entriesCount} entries, total size: {totalArchiveBytes} bytes (header starts at 0x{headerStart:X})",
            EstimatedSize: totalArchiveBytes,
            Confidence: SignatureConfidence.High);
    }

    private static bool IsAllZero(ReadOnlySpan<byte> span)
    {
        for (int i = 0; i < span.Length; i++)
        {
            if (span[i] != 0) return false;
        }
        return true;
    }
}

// ============================================================================
// 18. 7-Zip Archive (`src/signatures/sevenzip.rs`)
// ============================================================================
public sealed class SevenZipSignatureParser : IFirmwareSignatureParser
{
    public string Name => "7z";
    public string DisplayName => "7-Zip Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 32 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 32);
        byte major = h[6];
        byte minor = h[7];
        uint startHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(h.Slice(8, 4));
        ulong nextHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(h.Slice(12, 8));
        ulong nextHeaderSize = BinaryPrimitives.ReadUInt64LittleEndian(h.Slice(20, 8));

        if (major != 0 || minor > 10 || startHeaderCrc == 0)
            return SignatureParseResult.Invalid;

        ulong totalSize = 32UL + nextHeaderOffset + nextHeaderSize;
        if (totalSize > 2UL * 1024 * 1024 * 1024)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"7-zip archive data, version {major}.{minor}, total archive size: {totalSize} bytes, header CRC: 0x{startHeaderCrc:X8}",
            EstimatedSize: (long)totalSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 19. BZip2 Compressed Stream (`src/signatures/bzip2.rs`)
// ============================================================================
public sealed class Bzip2SignatureParser : IFirmwareSignatureParser
{
    public string Name => "bzip2";
    public string DisplayName => "BZip2 Stream";
    public string Category => "Compressed";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "BZh"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 10 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, 10);
        // Byte 3 is block size '1'..'9' (100k .. 900k)
        byte level = h[3];
        if (level < (byte)'1' || level > (byte)'9')
            return SignatureParseResult.Invalid;

        // Bytes 4..10 must be the compressed block magic 0x314159265359 (pi digits)
        ReadOnlySpan<byte> piMagic = new byte[] { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
        if (!h.Slice(4, 6).SequenceEqual(piMagic))
            return SignatureParseResult.Invalid;

        int blockKb = (level - '0') * 100;
        return new SignatureParseResult(
            IsValid: true,
            Description: $"bzip2 compressed data, block size = {blockKb}k",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 20. Zstandard Stream (`src/signatures/zstd.rs`)
// ============================================================================
public sealed class ZstdSignatureParser : IFirmwareSignatureParser
{
    public string Name => "zstd";
    public string DisplayName => "Zstandard (Zstd) Stream";
    public string Category => "Compressed";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x28, 0xB5, 0x2F, 0xFD }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 6 > fullData.Length)
            return SignatureParseResult.Invalid;

        byte fhd = fullData[offset + 4];
        // Bit 3 (0x08) of Frame_Header_Descriptor is reserved and must be 0 per RFC 8878
        if ((fhd & 0x08) != 0)
            return SignatureParseResult.Invalid;

        bool hasChecksum = (fhd & 0x04) != 0;
        bool singleSegment = (fhd & 0x20) != 0;
        int dictIdFlag = fhd & 0x03;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"Zstandard compressed data, single segment: {singleSegment}, content checksum: {hasChecksum}, dictionary ID flag: {dictIdFlag}",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 21. PEM Certificates & Private Keys (`src/signatures/pem.rs`)
// ============================================================================
public sealed class PemSignatureParser : IFirmwareSignatureParser
{
    public string Name => "pem";
    public string DisplayName => "PEM Certificate / Key";
    public string Category => "Crypto / Keys";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "-----BEGIN CERTIFICATE-----"u8.ToArray(),
        "-----BEGIN RSA PRIVATE KEY-----"u8.ToArray(),
        "-----BEGIN PRIVATE KEY-----"u8.ToArray(),
        "-----BEGIN EC PRIVATE KEY-----"u8.ToArray(),
        "-----BEGIN PUBLIC KEY-----"u8.ToArray(),
        "-----BEGIN OPENSSH PRIVATE KEY-----"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var rem = fullData.Slice(offset, Math.Min(16384, fullData.Length - offset));
        int lineEnd = rem.IndexOf((byte)'\n');
        string headerLine = lineEnd > 0
            ? Encoding.ASCII.GetString(rem[..lineEnd]).Trim()
            : Encoding.ASCII.GetString(rem[..Math.Min(40, rem.Length)]).Trim();

        int endMarker = rem.IndexOf("-----END "u8);
        long size = 0;
        if (endMarker > 0)
        {
            int endLine = rem[endMarker..].IndexOf((byte)'\n');
            size = endLine > 0 ? endMarker + endLine + 1 : endMarker + 25;
        }

        return new SignatureParseResult(
            IsValid: true,
            Description: $"PEM cryptographic block: {headerLine}",
            EstimatedSize: size,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 22. OpenSSL Salted Encrypted Stream (`src/signatures/openssl.rs`)
// ============================================================================
public sealed class OpenSslCryptSignatureParser : IFirmwareSignatureParser
{
    public string Name => "openssl";
    public string DisplayName => "OpenSSL Encrypted Data";
    public string Category => "Crypto / Keys";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "Salted__"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 16 > fullData.Length)
            return SignatureParseResult.Invalid;

        ulong salt = BinaryPrimitives.ReadUInt64BigEndian(fullData.Slice(offset + 8, 8));
        if (salt == 0 || salt == ulong.MaxValue)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"OpenSSL encryption, salted, salt: 0x{salt:X16}",
            EstimatedSize: 0,
            Confidence: SignatureConfidence.Medium);
    }
}

// ============================================================================
// 23. Linux EXT2 / EXT3 / EXT4 Filesystem (`src/signatures/ext.rs`)
// ============================================================================
public sealed class ExtFsSignatureParser : IFirmwareSignatureParser
{
    public string Name => "extfs";
    public string DisplayName => "Linux EXT2/3/4 Filesystem";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x53, 0xEF } // EXT_SUPER_MAGIC (0xEF53 LE at superblock offset +0x38, i.e. image offset +1080)
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        // In an EXT2/3/4 image:
        //   0..1024 = boot block padding
        //   1024..2048 = Superblock, with s_magic (0xEF53) at superblock+0x38 (offset 1080)
        int sbStart = offset - 0x38;
        if (sbStart < 0 || sbStart + 256 > fullData.Length)
            return SignatureParseResult.Invalid;

        var sb = fullData.Slice(sbStart, 256);
        uint inodesCount = BinaryPrimitives.ReadUInt32LittleEndian(sb[..4]);
        uint blocksCount = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(4, 4));
        uint freeBlocks = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(12, 4));
        uint freeInodes = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(16, 4));
        uint logBlockSize = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(24, 4));
        ushort state = BinaryPrimitives.ReadUInt16LittleEndian(sb.Slice(58, 2));
        uint revLevel = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(76, 4));

        // Strict structural validation to eliminate 2-byte 0x53 0xEF false positives!
        if (inodesCount == 0 || blocksCount == 0 || freeBlocks > blocksCount || freeInodes > inodesCount)
            return SignatureParseResult.Invalid;
        if (logBlockSize > 6 || revLevel > 2 || (state != 1 && state != 2 && state != 4))
            return SignatureParseResult.Invalid;

        long blockSize = 1024L << (int)logBlockSize;
        long fsSize = blocksCount * blockSize;
        int imgStart = sbStart >= 1024 ? sbStart - 1024 : sbStart;
        string volName = UImageSignatureParser.ReadNullTerminatedAscii(sb.Slice(120, 16));
        string volPart = string.IsNullOrEmpty(volName) ? "" : $", volume name: \"{volName}\"";

        return new SignatureParseResult(
            IsValid: true,
            Description: $"Linux EXT filesystem, rev {revLevel}.0, block size: {blockSize}, blocks: {blocksCount}, inodes: {inodesCount}, image size: {fsSize} bytes{volPart} (image starts at 0x{imgStart:X})",
            EstimatedSize: fsSize,
            Confidence: SignatureConfidence.High);
    }
}

// ============================================================================
// 24. ROMFS v1 Filesystem (`src/signatures/romfs.rs`)
// ============================================================================
public sealed class RomFsSignatureParser : IFirmwareSignatureParser
{
    public string Name => "romfs";
    public string DisplayName => "ROMFS v1 Filesystem";
    public string Category => "Filesystem";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "-rom1fs-"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        if (offset + 32 > fullData.Length)
            return SignatureParseResult.Invalid;

        var h = fullData.Slice(offset, Math.Min(64, fullData.Length - offset));
        uint fullSize = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(8, 4));
        uint checksum = BinaryPrimitives.ReadUInt32BigEndian(h.Slice(12, 4));

        if (fullSize is < 32 or > 512 * 1024 * 1024)
            return SignatureParseResult.Invalid;

        string volName = UImageSignatureParser.ReadNullTerminatedAscii(h[16..]);

        return new SignatureParseResult(
            IsValid: true,
            Description: $"romfs filesystem, version 1, size: {fullSize} bytes, CRC: 0x{checksum:X8}, volume name: \"{volName}\"",
            EstimatedSize: fullSize,
            Confidence: SignatureConfidence.High);
    }
}

