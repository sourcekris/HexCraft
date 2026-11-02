using System.Buffers.Binary;
using System.Text;

namespace HexCraft.Tools.Signatures;

/// <summary>
/// Structural signature &amp; exact-size carving parsers ported from and inspired by
/// <c>sourcekris/idarc</c> (IDArc archive identification &amp; SFX overlay analysis):
/// <list type="bullet">
/// <item><description><see cref="CabSignatureParser"/> (IDArc #79) — Microsoft Cabinet (<c>MSCF</c>)</description></item>
/// <item><description><see cref="RarSignatureParser"/> (IDArc #15) — RAR v1.5–v5.0 (<c>Rar!</c>) with Multi-Volume &amp; AV-Lock detection</description></item>
/// <item><description><see cref="ArjSignatureParser"/> (IDArc #8/#143) — ARJ / SARJ (<c>0x60 0xEA</c>)</description></item>
/// <item><description><see cref="LzhSignatureParser"/> (IDArc #4/#62/#142) — LZH / LHA / LHark (<c>-lh0-</c>..<c>-lh7-</c>)</description></item>
/// <item><description><see cref="ArcSignatureParser"/> (IDArc #1/#9/#16/#17) — SEA ARC / NoGate PAK / Hyper / ARC+ (<c>0x1A</c> header chain)</description></item>
/// <item><description><see cref="ZooSignatureParser"/> (IDArc #3) — ZOO Archive (<c>0xFDC4A7DC</c> at <c>+20</c>)</description></item>
/// <item><description><see cref="AceSignatureParser"/> (IDArc #90) — ACE Archive (<c>**ACE**</c> at <c>+7</c>)</description></item>
/// <item><description><see cref="RpmSignatureParser"/> (IDArc #162) — RPM Package (<c>0xEDABEEDB</c>)</description></item>
/// <item><description><see cref="MsCompressSignatureParser"/> (IDArc #84) — MS Compress <c>SZDD</c> / <c>KWAJ</c> (<c>\x88\xF0\x27</c>)</description></item>
/// <item><description><see cref="LzopSignatureParser"/> (IDArc #101) — LZOP Stream (<c>\x89LZO</c>)</description></item>
/// <item><description><see cref="MzSfxOverlaySignatureParser"/> (IDArc <c>exe.go</c>) — DOS/Win MZ Self-Extracting Archive (SFX) Overlay</description></item>
/// </list>
/// </summary>
public static class IdArcSignatureParsers
{
    public static IReadOnlyList<IFirmwareSignatureParser> CreateAll() => new IFirmwareSignatureParser[]
    {
        new CabSignatureParser(),
        new RarSignatureParser(),
        new ArjSignatureParser(),
        new LzhSignatureParser(),
        new ArcSignatureParser(),
        new ZooSignatureParser(),
        new AceSignatureParser(),
        new RpmSignatureParser(),
        new MsCompressSignatureParser(),
        new LzopSignatureParser(),
        new MzSfxOverlaySignatureParser(),
    };
}

// ============================================================================
// 1. Microsoft Cabinet (CAB) — IDArc Type #79 ("MSCF")
// ============================================================================
public sealed class CabSignatureParser : IFirmwareSignatureParser
{
    public string Name => "cab";
    public string DisplayName => "Microsoft Cabinet (CAB)";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "MSCF\0\0\0\0"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 36 || !window[..8].SequenceEqual("MSCF\0\0\0\0"u8))
            return SignatureParseResult.Invalid;

        uint cbCabinet = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(8, 4));
        uint reserved2 = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(12, 4));
        uint coffFiles = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(16, 4));
        uint reserved3 = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(20, 4));
        byte verMinor = window[24];
        byte verMajor = window[25];
        ushort cFolders = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(26, 2));
        ushort cFiles = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(28, 2));
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(30, 2));
        ushort setId = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(32, 2));

        if (reserved2 != 0 || reserved3 != 0 || cbCabinet < 36 || coffFiles < 36 || coffFiles >= cbCabinet)
            return SignatureParseResult.Invalid;
        if (cFolders == 0 || cFiles == 0 || verMajor is < 1 or > 5)
            return SignatureParseResult.Invalid;

        bool multiVol = (flags & 0x0003) != 0;
        string volNote = multiVol ? ", multi-volume" : "";
        return new SignatureParseResult(
            IsValid: true,
            Description: $"Microsoft CAB v{verMajor}.{verMinor} (IDArc #79), {cFiles} files in {cFolders} folder(s), set ID 0x{setId:X4}{volNote}, size: {cbCabinet} bytes",
            EstimatedSize: cbCabinet);
    }
}

// ============================================================================
// 2. RAR Archive — IDArc Type #15 ("Rar!")
// ============================================================================
public sealed class RarSignatureParser : IFirmwareSignatureParser
{
    public string Name => "rar";
    public string DisplayName => "RAR Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 },       // RAR v1.5 - v4.x
        new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 }, // RAR v5.0+
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 14)
            return SignatureParseResult.Invalid;

        bool isRar5 = window.Length >= 8 && window[..8].SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 });
        bool isRar4 = !isRar5 && window[..7].SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 });
        if (!isRar4 && !isRar5)
            return SignatureParseResult.Invalid;

        if (isRar5)
        {
            return new SignatureParseResult(
                IsValid: true,
                Description: "RAR v5.0 Archive (IDArc #15)",
                EstimatedSize: 0);
        }

        // RAR v4 block walker to compute exact archive size & IDArc flags
        if (window.Length < 20 || window[9] != 0x73)
            return SignatureParseResult.Invalid;

        ushort mhdFlags = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(10, 2));
        bool isVolume = (mhdFlags & 0x0001) != 0;
        bool isLocked = (mhdFlags & 0x0004) != 0;
        bool isSolid  = (mhdFlags & 0x0008) != 0;
        bool hasAv    = (mhdFlags & 0x0020) != 0;

        int pos = 7;
        int fileCount = 0;
        while (pos + 7 <= window.Length)
        {
            byte headType = window[pos + 2];
            ushort headFlags = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(pos + 3, 2));
            ushort headSize = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(pos + 5, 2));
            if (headSize < 7)
                break;

            uint addSize = 0;
            if ((headFlags & 0x8000) != 0 || headType == 0x74)
            {
                if (pos + 11 > window.Length) break;
                addSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(pos + 7, 4));
            }

            if (headType == 0x74)
                fileCount++;

            long nextPos = pos + headSize + addSize;
            if (nextPos > window.Length || nextPos <= pos)
            {
                pos = (int)Math.Min(window.Length, nextPos);
                break;
            }
            pos = (int)nextPos;

            if (headType == 0x7B) // ENDARC_HEAD
                break;
        }

        var tags = new List<string>();
        if (isVolume) tags.Add("multi-volume");
        if (hasAv) tags.Add("AV-protected");
        if (isLocked) tags.Add("locked");
        if (isSolid) tags.Add("solid");
        string flagStr = tags.Count > 0 ? $" [{string.Join(", ", tags)}]" : "";

        return new SignatureParseResult(
            IsValid: true,
            Description: $"RAR v4.x Archive (IDArc #15){flagStr}, {fileCount} file(s), size: {pos} bytes",
            EstimatedSize: pos);
    }
}

// ============================================================================
// 3. ARJ Archive — IDArc Type #8 (0x60 0xEA)
// ============================================================================
public sealed class ArjSignatureParser : IFirmwareSignatureParser
{
    public string Name => "arj";
    public string DisplayName => "ARJ Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x60, 0xEA }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 34 || window[0] != 0x60 || window[1] != 0xEA)
            return SignatureParseResult.Invalid;

        ushort basicHdrSize = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(2, 2));
        if (basicHdrSize < 30 || basicHdrSize > 2600 || 4 + basicHdrSize + 4 > window.Length)
            return SignatureParseResult.Invalid;

        byte firstHdrSize = window[4];
        byte archiverVer = window[5];
        byte minVer = window[6];
        byte hostOs = window[7];
        byte arjFlags = window[8];
        byte fileType = window[10];

        if (fileType != 2 || firstHdrSize < 30 || firstHdrSize > basicHdrSize || hostOs > 11 || archiverVer == 0 || minVer > archiverVer)
            return SignatureParseResult.Invalid;

        uint expectedCrc = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(4 + basicHdrSize, 4));
        uint actualCrc = ComputeCrc32(window.Slice(4, basicHdrSize));
        if (actualCrc != expectedCrc)
            return SignatureParseResult.Invalid;

        int pos = 0;
        int memberCount = 0;
        while (pos + 4 <= window.Length)
        {
            if (window[pos] != 0x60 || window[pos + 1] != 0xEA)
                break;

            ushort bhs = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(pos + 2, 2));
            pos += 4;
            if (bhs == 0)
                break;

            if (bhs > 2600 || pos + bhs + 6 > window.Length)
                break;

            byte fType = window[pos + 6];
            uint compSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(pos + 12, 4));
            pos += bhs + 4;

            while (pos + 2 <= window.Length)
            {
                ushort extSize = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(pos, 2));
                pos += 2;
                if (extSize == 0) break;
                pos += extSize + 4;
            }

            if (fType != 2)
            {
                pos += (int)compSize;
                memberCount++;
            }
        }

        bool isVolume = (arjFlags & 0x04) != 0;
        bool isSecured = (arjFlags & 0x48) != 0;
        string flagsDesc = (isVolume ? ", multi-volume" : "") + (isSecured ? ", AV-secured" : "");

        return new SignatureParseResult(
            IsValid: true,
            Description: $"ARJ Archive v{archiverVer} (IDArc #8{flagsDesc}), {memberCount} file(s), size: {pos} bytes",
            EstimatedSize: pos);
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }
}

// ============================================================================
// 4. LZH / LHA / LHark Archive — IDArc Type #4 / #62 ("-lh0-".."-lh7-")
// ============================================================================
public sealed class LzhSignatureParser : IFirmwareSignatureParser
{
    public string Name => "lzh";
    public string DisplayName => "LZH / LHA Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "-lh0-"u8.ToArray(),
        "-lh1-"u8.ToArray(),
        "-lh4-"u8.ToArray(),
        "-lh5-"u8.ToArray(),
        "-lh6-"u8.ToArray(),
        "-lh7-"u8.ToArray(),
        "-lzs-"u8.ToArray(),
        "-lz5-"u8.ToArray(),
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 22 || window[0] != (byte)'-' || window[4] != (byte)'-')
            return SignatureParseResult.Invalid;

        string method = Encoding.ASCII.GetString(window[..5]);
        uint packedSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(5, 4));
        uint origSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(9, 4));
        byte level = window[18];

        if (level > 2 || packedSize > 256 * 1024 * 1024 || origSize > 512 * 1024 * 1024)
            return SignatureParseResult.Invalid;

        string fileName = "";
        int firstEntryTotal;
        if (level is 0 or 1)
        {
            byte nameLen = window[19];
            if (nameLen == 0 || nameLen > 128 || 20 + nameLen > window.Length)
                return SignatureParseResult.Invalid;

            var nameBytes = window.Slice(20, nameLen);
            foreach (byte b in nameBytes)
            {
                if (b < 0x20 || b > 0x7E) return SignatureParseResult.Invalid;
            }
            fileName = Encoding.ASCII.GetString(nameBytes);
            firstEntryTotal = 20 + nameLen + 2 + (level == 1 ? 3 : 0) + (int)packedSize;
        }
        else
        {
            firstEntryTotal = 24 + (int)packedSize;
        }

        string subType = method == "-lh7-" ? "LHark / LZH v7 (IDArc #62)" : $"LZH / LHA ({method}, IDArc #4)";
        return new SignatureParseResult(
            IsValid: true,
            Description: $"{subType}, Level {level}, first entry: \"{fileName}\" ({packedSize} B packed -> {origSize} B)",
            EstimatedSize: firstEntryTotal);
    }
}

// ============================================================================
// 5. SEA ARC / PAK / Hyper Archive — IDArc Type #1 / #9 / #16 / #17 (`ArcMethod`)
// ============================================================================
public sealed class ArcSignatureParser : IFirmwareSignatureParser
{
    public string Name => "arc";
    public string DisplayName => "SEA ARC / PAK Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x1A, 0x02 },
        new byte[] { 0x1A, 0x03 },
        new byte[] { 0x1A, 0x08 },
        new byte[] { 0x1A, 0x09 },
        new byte[] { 0x1A, 0x0A },
        new byte[] { 0x1A, 0x0B },
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 31 || window[0] != 0x1A)
            return SignatureParseResult.Invalid;

        byte method = window[1];
        if (method is 0 or > 20)
            return SignatureParseResult.Invalid;

        var nameField = window.Slice(2, 13);
        int nullIdx = nameField.IndexOf((byte)0);
        if (nullIdx <= 0 || nullIdx > 12)
            return SignatureParseResult.Invalid;

        for (int i = 0; i < nullIdx; i++)
        {
            byte c = nameField[i];
            if (c < 0x21 || c > 0x7E) return SignatureParseResult.Invalid;
        }
        for (int i = nullIdx + 1; i < 12; i++)
        {
            if (nameField[i] != 0 && method < 0x0A)
                return SignatureParseResult.Invalid;
        }

        string firstFileName = Encoding.ASCII.GetString(nameField[..nullIdx]);
        uint firstCompSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(15, 4));
        uint firstOrigSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(25, 4));

        if (firstCompSize > 64 * 1024 * 1024 || firstOrigSize > 128 * 1024 * 1024)
            return SignatureParseResult.Invalid;
        if (method == 2 && firstCompSize != firstOrigSize)
            return SignatureParseResult.Invalid;

        long nextHeaderPos = 29L + firstCompSize;
        if (nextHeaderPos + 2 > window.Length || window[(int)nextHeaderPos] != 0x1A)
            return SignatureParseResult.Invalid;

        int pos = 0;
        int count = 0;
        while (pos + 2 <= window.Length && window[pos] == 0x1A)
        {
            byte m = window[pos + 1];
            if (m == 0)
            {
                pos += 2;
                break;
            }
            if (pos + 29 > window.Length)
                break;

            uint cSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(pos + 15, 4));
            if (pos + 29L + cSize > window.Length)
                break;

            pos += 29 + (int)cSize;
            count++;
        }

        string variant = method >= 0x0A ? "NoGate PAK (IDArc #16)" : "SEA ARC (IDArc #1)";
        return new SignatureParseResult(
            IsValid: true,
            Description: $"{variant}, {count} file(s), first: \"{firstFileName}\", size: {pos} bytes",
            EstimatedSize: pos);
    }
}

// ============================================================================
// 6. ZOO Archive — IDArc Type #3 (0xFDC4A7DC at +20)
// ============================================================================
public sealed class ZooSignatureParser : IFirmwareSignatureParser
{
    public string Name => "zoo";
    public string DisplayName => "ZOO Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0xDC, 0xA7, 0xC4, 0xFD }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 16 || BinaryPrimitives.ReadUInt32LittleEndian(window[..4]) != 0xFDC4A7DC)
            return SignatureParseResult.Invalid;

        uint zooStart = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(4, 4));
        uint zooMinus = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(8, 4));
        byte majorVer = window[12];
        byte minorVer = window[13];

        if (zooStart < 34 || unchecked(zooStart + zooMinus) != 0 || majorVer is 0 or > 10)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"ZOO v{majorVer}.{minorVer} Archive (IDArc #3), first entry @ 0x{zooStart:X}",
            EstimatedSize: 0);
    }
}

// ============================================================================
// 7. ACE Archive — IDArc Type #90 ("**ACE**" at +7)
// ============================================================================
public sealed class AceSignatureParser : IFirmwareSignatureParser
{
    public string Name => "ace";
    public string DisplayName => "ACE Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "**ACE**"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 24 || !window[..7].SequenceEqual("**ACE**"u8))
            return SignatureParseResult.Invalid;

        byte verExtract = window[7];
        byte verCreated = window[8];
        byte hostOs = window[9];
        byte volNum = window[10];

        if (verExtract is 0 or > 50 || verCreated is 0 or > 50 || hostOs > 15)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"ACE v{verCreated / 10}.{verCreated % 10} Archive (IDArc #90), volume #{volNum}, host OS={hostOs}",
            EstimatedSize: 0);
    }
}

// ============================================================================
// 8. RPM Package — IDArc Type #162 (0xEDABEEDB)
// ============================================================================
public sealed class RpmSignatureParser : IFirmwareSignatureParser
{
    public string Name => "rpm";
    public string DisplayName => "RPM Package Archive";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 96 || !window[..4].SequenceEqual(new byte[] { 0xED, 0xAB, 0xEE, 0xDB }))
            return SignatureParseResult.Invalid;

        byte major = window[4];
        byte minor = window[5];
        ushort rpmType = BinaryPrimitives.ReadUInt16BigEndian(window.Slice(6, 2));
        if (major is < 2 or > 6 || rpmType > 1)
            return SignatureParseResult.Invalid;

        string pkgName = Encoding.UTF8.GetString(window.Slice(10, 66)).TrimEnd('\0').Trim();
        if (string.IsNullOrEmpty(pkgName))
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"RPM v{major}.{minor} {(rpmType == 0 ? "Binary" : "Source")} Package (IDArc #162), name: \"{pkgName}\"",
            EstimatedSize: 0);
    }
}

// ============================================================================
// 9. Microsoft Compress (SZDD / KWAJ) — IDArc Type #84 ("\x88\xF0\x27")
// ============================================================================
public sealed class MsCompressSignatureParser : IFirmwareSignatureParser
{
    public string Name => "mscompress";
    public string DisplayName => "MS Compress (SZDD/KWAJ)";
    public string Category => "Compression";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33 }, // SZDD
        new byte[] { 0x4B, 0x57, 0x41, 0x4A, 0x88, 0xF0, 0x27, 0xD1 }, // KWAJ
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 14)
            return SignatureParseResult.Invalid;

        bool isSzdd = window[..8].SequenceEqual(new byte[] { 0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33 });
        bool isKwaj = !isSzdd && window[..8].SequenceEqual(new byte[] { 0x4B, 0x57, 0x41, 0x4A, 0x88, 0xF0, 0x27, 0xD1 });
        if (!isSzdd && !isKwaj)
            return SignatureParseResult.Invalid;

        if (isSzdd)
        {
            byte compMode = window[8];
            char missingChar = window[9] is >= 0x20 and <= 0x7E ? (char)window[9] : '?';
            uint uncompSize = BinaryPrimitives.ReadUInt32LittleEndian(window.Slice(10, 4));
            if (compMode != (byte)'A' || uncompSize == 0 || uncompSize > 256 * 1024 * 1024)
                return SignatureParseResult.Invalid;

            return new SignatureParseResult(
                IsValid: true,
                Description: $"MS Compress SZDD LZSS Stream (IDArc #84), missing ext char: '{missingChar}', uncompressed: {uncompSize} bytes",
                EstimatedSize: 0);
        }
        else
        {
            ushort compMethod = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(8, 2));
            ushort dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(10, 2));
            if (compMethod > 4 || dataOffset < 14)
                return SignatureParseResult.Invalid;

            return new SignatureParseResult(
                IsValid: true,
                Description: $"MS Compress KWAJ Stream (IDArc #84), method={compMethod}, data offset: 0x{dataOffset:X}",
                EstimatedSize: 0);
        }
    }
}

// ============================================================================
// 10. LZOP Stream — IDArc Type #101 ("\x89LZO\r\n\x1A\n")
// ============================================================================
public sealed class LzopSignatureParser : IFirmwareSignatureParser
{
    public string Name => "lzop";
    public string DisplayName => "LZOP Compressed Stream";
    public string Category => "Compression";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        new byte[] { 0x89, (byte)'L', (byte)'Z', (byte)'O', 0x00, 0x0D, 0x0A, 0x1A, 0x0A }
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 34 || !window[..9].SequenceEqual(new byte[] { 0x89, (byte)'L', (byte)'Z', (byte)'O', 0x00, 0x0D, 0x0A, 0x1A, 0x0A }))
            return SignatureParseResult.Invalid;

        ushort version = BinaryPrimitives.ReadUInt16BigEndian(window.Slice(9, 2));
        ushort libVersion = BinaryPrimitives.ReadUInt16BigEndian(window.Slice(11, 2));
        byte method = window[15];
        byte level = window[16];

        if (method is 0 or > 3 || level > 9)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"LZOP v{version >> 8}.{(version >> 4) & 0xF} Stream (IDArc #101, LZO lib 0x{libVersion:X4}), method={method}, level={level}",
            EstimatedSize: 0);
    }
}

// ============================================================================
// 11. DOS/Win MZ Self-Extracting Archive (SFX) Stub Overlay — IDArc exe.go
// ============================================================================
public sealed class MzSfxOverlaySignatureParser : IFirmwareSignatureParser
{
    public string Name => "sfx_overlay";
    public string DisplayName => "MZ Self-Extracting Archive (SFX)";
    public string Category => "Archive";

    public IReadOnlyList<byte[]> MagicPatterns { get; } = new[]
    {
        "MZ"u8.ToArray()
    };

    public SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset)
    {
        var window = fullData[offset..];
        if (window.Length < 64 || window[0] != (byte)'M' || window[1] != (byte)'Z')
            return SignatureParseResult.Invalid;

        ushort lastPageSize = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(2, 2));
        ushort pages = BinaryPrimitives.ReadUInt16LittleEndian(window.Slice(4, 2));
        if (pages == 0 || lastPageSize > 512)
            return SignatureParseResult.Invalid;

        long exeStubSize = (pages - 1L) * 512L + lastPageSize;
        if (exeStubSize < 64 || exeStubSize + 16 > window.Length)
            return SignatureParseResult.Invalid;

        var overlay = window.Slice((int)exeStubSize);
        string? detectedOverlayType = IdentifyIdArcOverlay(overlay);
        if (detectedOverlayType is null)
            return SignatureParseResult.Invalid;

        return new SignatureParseResult(
            IsValid: true,
            Description: $"MZ Self-Extracting Archive (IDArc SFX), stub={exeStubSize} B, appended payload: {detectedOverlayType}",
            EstimatedSize: window.Length);
    }

    internal static string? IdentifyIdArcOverlay(ReadOnlySpan<byte> overlay)
    {
        if (overlay.Length < 8) return null;
        if (overlay[..4].SequenceEqual("PK\x03\x04"u8)) return "ZIP Archive";
        if (overlay[..4].SequenceEqual("Rar!"u8)) return "RAR Archive";
        if (overlay[..4].SequenceEqual("MSCF"u8)) return "Microsoft CAB";
        if (overlay[0] == 0x60 && overlay[1] == 0xEA) return "ARJ Archive";
        if (overlay[..6].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return "7-Zip Archive";
        if (overlay.Length >= 7 && overlay.Slice(2, 3).SequenceEqual("-lh"u8)) return "LZH Archive";
        if (overlay.Length >= 14 && overlay.Slice(7, 7).SequenceEqual("**ACE**"u8)) return "ACE Archive";
        if (overlay[0] == 0x1A && overlay[1] is >= 1 and <= 20) return "SEA ARC / PAK Archive";
        return null;
    }
}
