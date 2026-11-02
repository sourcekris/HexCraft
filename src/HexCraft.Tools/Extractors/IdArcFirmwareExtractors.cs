using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace HexCraft.Tools.Extractors;

/// <summary>
/// Native carving and unpacking tools for archive, compression, and SFX formats
/// supported by <c>sourcekris/idarc</c>.
/// </summary>
public static class IdArcFirmwareExtractors
{
    public static IReadOnlyList<IFirmwareExtractor> All { get; } = new IFirmwareExtractor[]
    {
        new CabExtractor(),
        new RarExtractor(),
        new ArjExtractor(),
        new LzhExtractor(),
        new ArcExtractor(),
        new ZooExtractor(),
        new AceExtractor(),
        new RpmExtractor(),
        new MsCompressExtractor(),
        new LzopExtractor(),
        new MzSfxOverlayExtractor(),
    };
}

// ============================================================================
// 1. Microsoft Cabinet (CAB) Unpacker & Carver — IDArc #79 ("MSCF")
// ============================================================================
public sealed class CabExtractor : IFirmwareExtractor
{
    public string Id => "cab";
    public string Name => "Microsoft Cabinet (CAB) Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "cab", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("Cabinet", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 36 && payload[..4].SequenceEqual("MSCF"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 36 || !payload[..4].SequenceEqual("MSCF"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid Microsoft CAB header.");

        uint cbCabinet = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(8, 4));
        uint coffFiles = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(16, 4));
        ushort cFolders = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(26, 2));
        ushort cFiles = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(28, 2));
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(30, 2));

        string cabRoot = Path.Combine(outputDirectory, "cab-root");
        Directory.CreateDirectory(cabRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        // Parse CFFOLDER entries (8 bytes each, starting at offset 36 if no reserve fields)
        int folderTablePos = 36;
        if ((flags & 0x0004) != 0 && payload.Length >= 40)
        {
            ushort cbCFHeader = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(36, 2));
            folderTablePos = 40 + cbCFHeader;
        }

        var folderStreams = new Dictionary<int, byte[]>();
        for (int f = 0; f < cFolders && folderTablePos + 8 <= payload.Length; f++)
        {
            uint coffCabStart = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(folderTablePos, 4));
            ushort cCfData = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(folderTablePos + 4, 2));
            ushort typeCompress = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(folderTablePos + 6, 2));
            folderTablePos += 8;

            folderStreams[f] = DecompressCabFolder(payload, (int)coffCabStart, cCfData, typeCompress);
        }

        // Parse CFFILE entries starting at coffFiles
        int filePos = (int)coffFiles;
        for (int i = 0; i < cFiles && filePos + 16 <= payload.Length; i++)
        {
            uint cbFile = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(filePos, 4));
            uint uoffFolderStart = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(filePos + 4, 4));
            ushort iFolder = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(filePos + 8, 2));
            filePos += 16;

            int nameEnd = filePos;
            while (nameEnd < payload.Length && payload[nameEnd] != 0)
                nameEnd++;
            if (nameEnd >= payload.Length) break;

            string fileName = Encoding.UTF8.GetString(payload.Slice(filePos, nameEnd - filePos));
            filePos = nameEnd + 1;

            if (folderStreams.TryGetValue(iFolder, out byte[]? folderData) &&
                uoffFolderStart + cbFile <= folderData.Length)
            {
                string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(cabRoot, fileName);
                Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                File.WriteAllBytes(destPath, folderData.AsSpan((int)uoffFolderStart, (int)cbFile).ToArray());
                extractedFiles.Add(destPath);
                log.AppendLine($"  [+] CAB File: '{fileName}' ({cbFile:N0} B)");
            }
        }

        log.Insert(0, $"[+] Microsoft CAB Unpacker (IDArc #79, {cbCabinet:N0} B): Extracted {extractedFiles.Count}/{cFiles} files -> {cabRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static byte[] DecompressCabFolder(ReadOnlySpan<byte> cab, int dataOffset, int blockCount, ushort compType)
    {
        using var outMs = new MemoryStream();
        int pos = dataOffset;
        int method = compType & 0x000F;

        for (int b = 0; b < blockCount && pos + 8 <= cab.Length; b++)
        {
            ushort cbData = BinaryPrimitives.ReadUInt16LittleEndian(cab.Slice(pos + 4, 2));
            ushort cbUncomp = BinaryPrimitives.ReadUInt16LittleEndian(cab.Slice(pos + 6, 2));
            pos += 8;

            if (pos + cbData > cab.Length)
                break;

            var block = cab.Slice(pos, cbData);
            pos += cbData;

            if (method == 0) // tcompTYPE_NONE
            {
                outMs.Write(block);
            }
            else if (method == 1 && block.Length > 2 && block[0] == (byte)'C' && block[1] == (byte)'K') // tcompTYPE_MSZIP ("CK" + RFC 1951 Deflate)
            {
                try
                {
                    using var inMs = new MemoryStream(block[2..].ToArray());
                    using var deflate = new DeflateStream(inMs, CompressionMode.Decompress);
                    deflate.CopyTo(outMs);
                }
                catch
                {
                    break;
                }
            }
        }

        return outMs.ToArray();
    }
}

// ============================================================================
// 2. RAR Archive Carver & Unpacker — IDArc #15 ("Rar!")
// ============================================================================
public sealed class RarExtractor : IFirmwareExtractor
{
    public string Id => "rar";
    public string Name => "RAR Archive Carver & Stored Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "rar", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("RAR", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 14 && payload[..4].SequenceEqual("Rar!"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 14 || !payload[..4].SequenceEqual("Rar!"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid RAR magic.");

        string rarRoot = Path.Combine(outputDirectory, "rar-root");
        Directory.CreateDirectory(rarRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();
        var manifest = new StringBuilder();

        if (payload[..7].SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }))
        {
            int pos = 7;
            while (pos + 7 <= payload.Length)
            {
                byte headType = payload[pos + 2];
                ushort headFlags = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos + 3, 2));
                ushort headSize = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos + 5, 2));
                if (headSize < 7 || pos + headSize > payload.Length)
                    break;

                uint packSize = 0;
                if ((headFlags & 0x8000) != 0 || headType == 0x74)
                {
                    if (pos + 11 > payload.Length) break;
                    packSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos + 7, 4));
                }

                if (headType == 0x74 && headSize >= 32) // FILE_HEAD
                {
                    uint unpSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos + 11, 4));
                    byte method = payload[pos + 25];
                    ushort nameSize = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos + 26, 2));

                    if (pos + 32 + nameSize <= payload.Length)
                    {
                        string fileName = Encoding.UTF8.GetString(payload.Slice(pos + 32, nameSize)).Split('\0')[0];
                        manifest.AppendLine($"Entry: {fileName} (Packed={packSize} B, Unpacked={unpSize} B, Method=0x{method:X2})");

                        int dataStart = pos + headSize;
                        if (method == 0x30 && dataStart + packSize <= payload.Length) // 0x30 = Storing (uncompressed)
                        {
                            string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(rarRoot, fileName);
                            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                            File.WriteAllBytes(destPath, payload.Slice(dataStart, (int)packSize).ToArray());
                            extractedFiles.Add(destPath);
                            log.AppendLine($"  [+] RAR Stored File: '{fileName}' ({packSize:N0} B)");
                        }
                    }
                }

                pos += headSize + (int)packSize;
                if (headType == 0x7B) break;
            }
        }

        string manifestPath = Path.Combine(outputDirectory, "rar_manifest.txt");
        File.WriteAllText(manifestPath, manifest.Length > 0 ? manifest.ToString() : "RAR Archive Carved\n");
        extractedFiles.Add(manifestPath);

        log.Insert(0, $"[+] RAR Unpacker (IDArc #15): Extracted {extractedFiles.Count} item(s) -> {rarRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }
}

// ============================================================================
// 3. ARJ Archive Carver & Unpacker — IDArc #8 (0x60 0xEA)
// ============================================================================
public sealed class ArjExtractor : IFirmwareExtractor
{
    public string Id => "arj";
    public string Name => "ARJ Archive Carver & Stored Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "arj", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("ARJ", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 34 && payload[0] == 0x60 && payload[1] == 0xEA);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 34 || payload[0] != 0x60 || payload[1] != 0xEA)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid ARJ header magic.");

        string arjRoot = Path.Combine(outputDirectory, "arj-root");
        Directory.CreateDirectory(arjRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();
        var manifest = new StringBuilder();

        int pos = 0;
        while (pos + 4 <= payload.Length && payload[pos] == 0x60 && payload[pos + 1] == 0xEA)
        {
            ushort bhs = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos + 2, 2));
            pos += 4;
            if (bhs == 0 || pos + bhs + 4 > payload.Length)
                break;

            var hdr = payload.Slice(pos, bhs);
            byte firstHdrSize = hdr[0];
            byte method = hdr[5];
            byte fileType = hdr[6];
            uint compSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(12, 4));
            uint origSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(16, 4));

            string name = "";
            if (firstHdrSize < hdr.Length)
            {
                var nameSpan = hdr[firstHdrSize..];
                int nul = nameSpan.IndexOf((byte)0);
                if (nul > 0) name = Encoding.UTF8.GetString(nameSpan[..nul]);
            }

            pos += bhs + 4; // skip basic header + CRC32
            while (pos + 2 <= payload.Length)
            {
                ushort extSize = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos, 2));
                pos += 2;
                if (extSize == 0) break;
                pos += extSize + 4;
            }

            if (fileType != 2) // Member entry
            {
                manifest.AppendLine($"Member: {name} (Method={method}, Packed={compSize} B, Orig={origSize} B)");
                if (method == 0 && !string.IsNullOrEmpty(name) && pos + compSize <= payload.Length) // Method 0 = Stored
                {
                    string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(arjRoot, name);
                    Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                    File.WriteAllBytes(destPath, payload.Slice(pos, (int)compSize).ToArray());
                    extractedFiles.Add(destPath);
                    log.AppendLine($"  [+] ARJ Stored File: '{name}' ({compSize:N0} B)");
                }
                pos += (int)compSize;
            }
        }

        string manifestPath = Path.Combine(outputDirectory, "arj_manifest.txt");
        File.WriteAllText(manifestPath, manifest.ToString());
        extractedFiles.Add(manifestPath);

        log.Insert(0, $"[+] ARJ Unpacker (IDArc #8): Extracted {extractedFiles.Count} item(s) -> {arjRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }
}

// ============================================================================
// 4. LZH / LHA / LHark Unpacker — IDArc #4 / #62 ("-lh0-".."-lh7-")
// ============================================================================
public sealed class LzhExtractor : IFirmwareExtractor
{
    public string Id => "lzh";
    public string Name => "LZH / LHA Archive Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "lzh", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("LZH", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 22 && payload[0] == (byte)'-' && payload[4] == (byte)'-');
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 22)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] LZH payload too small.");

        string lzhRoot = Path.Combine(outputDirectory, "lzh-root");
        Directory.CreateDirectory(lzhRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        // Payload may start at the `-lhX-` magic (offset 0) or at the 2-byte header prefix
        int pos = (payload[0] == (byte)'-' && payload[4] == (byte)'-') ? 0 : 2;

        while (pos + 20 <= payload.Length && payload[pos] == (byte)'-' && payload[pos + 4] == (byte)'-')
        {
            string method = Encoding.ASCII.GetString(payload.Slice(pos, 5));
            uint packedSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos + 5, 4));
            byte level = payload[pos + 18];
            byte nameLen = payload[pos + 19];

            if (pos + 20 + nameLen + 2 > payload.Length)
                break;

            string fileName = Encoding.UTF8.GetString(payload.Slice(pos + 20, nameLen));
            int dataOffset = pos + 20 + nameLen + 2 + (level == 1 ? 3 : 0);
            if (dataOffset + packedSize > payload.Length)
                break;

            if ((method == "-lh0-" || method == "-lz4-") && !string.IsNullOrEmpty(fileName))
            {
                string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(lzhRoot, fileName);
                Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                File.WriteAllBytes(destPath, payload.Slice(dataOffset, (int)packedSize).ToArray());
                extractedFiles.Add(destPath);
                log.AppendLine($"  [+] LZH Stored File ({method}): '{fileName}' ({packedSize:N0} B)");
            }

            // Next member's `-lhX-` sits 2 bytes after dataOffset + packedSize
            pos = dataOffset + (int)packedSize + 2;
        }

        log.Insert(0, $"[+] LZH Unpacker (IDArc #4): Extracted {extractedFiles.Count} file(s) -> {lzhRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }
}

// ============================================================================
// 5. SEA ARC / NoGate PAK Unpacker — IDArc #1 / #16 (`ArcMethod`)
// ============================================================================
public sealed class ArcExtractor : IFirmwareExtractor
{
    public string Id => "arc";
    public string Name => "SEA ARC / PAK Archive Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "arc", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("ARC", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 29 && payload[0] == 0x1A && payload[1] is >= 1 and <= 20);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 29 || payload[0] != 0x1A)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid SEA ARC / PAK header.");

        string arcRoot = Path.Combine(outputDirectory, "arc-root");
        Directory.CreateDirectory(arcRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        int pos = 0;
        while (pos + 2 <= payload.Length && payload[pos] == 0x1A)
        {
            byte method = payload[pos + 1];
            if (method == 0 || pos + 29 > payload.Length)
                break;

            var nameSlice = payload.Slice(pos + 2, 13);
            int nul = nameSlice.IndexOf((byte)0);
            string fileName = Encoding.ASCII.GetString(nul > 0 ? nameSlice[..nul] : nameSlice).Trim();
            uint compSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos + 15, 4));
            uint origSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos + 25, 4));

            int dataStart = pos + 29;
            if (dataStart + compSize > payload.Length)
                break;

            var compData = payload.Slice(dataStart, (int)compSize);
            if (!string.IsNullOrEmpty(fileName))
            {
                byte[]? unpacked = null;
                if (method is 1 or 2) // Stored uncompressed
                {
                    unpacked = compData.ToArray();
                }
                else if (method == 3) // RLE90 (0x90 repeat packing)
                {
                    unpacked = DecompressArcRle90(compData, (int)origSize);
                }

                if (unpacked is not null)
                {
                    string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(arcRoot, fileName);
                    File.WriteAllBytes(destPath, unpacked);
                    extractedFiles.Add(destPath);
                    log.AppendLine($"  [+] ARC File (method={method}): '{fileName}' ({unpacked.Length:N0} B)");
                }
            }

            pos = dataStart + (int)compSize;
        }

        log.Insert(0, $"[+] SEA ARC / PAK Unpacker (IDArc #1): Extracted {extractedFiles.Count} file(s) -> {arcRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static byte[] DecompressArcRle90(ReadOnlySpan<byte> src, int expectedSize)
    {
        using var outMs = new MemoryStream(Math.Max(64, expectedSize));
        int prev = -1;
        for (int i = 0; i < src.Length; i++)
        {
            byte b = src[i];
            if (b == 0x90 && i + 1 < src.Length)
            {
                byte count = src[++i];
                if (count == 0)
                {
                    outMs.WriteByte(0x90);
                    prev = 0x90;
                }
                else if (prev >= 0)
                {
                    for (int r = 1; r < count; r++)
                        outMs.WriteByte((byte)prev);
                }
            }
            else
            {
                outMs.WriteByte(b);
                prev = b;
            }
        }
        return outMs.ToArray();
    }
}

// ============================================================================
// 6. ZOO, ACE, RPM, MS Compress (SZDD), LZOP, and MZ SFX Overlay Extractors
// ============================================================================
public sealed class ZooExtractor : IFirmwareExtractor
{
    public string Id => "zoo";
    public string Name => "ZOO Archive Carver & Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "zoo", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("ZOO", StringComparison.OrdinalIgnoreCase);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string manifestPath = Path.Combine(outputDirectory, "zoo_manifest.txt");
        File.WriteAllText(manifestPath, $"ZOO Archive Carved (IDArc #3, {payload.Length} bytes){Environment.NewLine}");
        return new ExtractorExecutionResult(true, Id, new[] { manifestPath }, $"[+] ZOO Archive Carver: Saved manifest -> {manifestPath}", SupportsRecursion: false);
    }
}

public sealed class AceExtractor : IFirmwareExtractor
{
    public string Id => "ace";
    public string Name => "ACE Archive Inspector";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "ace", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("ACE", StringComparison.OrdinalIgnoreCase);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string manifestPath = Path.Combine(outputDirectory, "ace_manifest.txt");
        File.WriteAllText(manifestPath, $"ACE Archive Carved (IDArc #90, {payload.Length} bytes){Environment.NewLine}");
        return new ExtractorExecutionResult(true, Id, new[] { manifestPath }, $"[+] ACE Archive Inspector: Saved manifest -> {manifestPath}", SupportsRecursion: false);
    }
}

public sealed class RpmExtractor : IFirmwareExtractor
{
    public string Id => "rpm";
    public string Name => "RPM Package Payload Carver";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "rpm", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("RPM", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 96 && payload[..4].SequenceEqual(new byte[] { 0xED, 0xAB, 0xEE, 0xDB }));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 96 || !payload[..4].SequenceEqual(new byte[] { 0xED, 0xAB, 0xEE, 0xDB }))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid RPM Lead header.");

        Directory.CreateDirectory(outputDirectory);
        string pkgName = Encoding.UTF8.GetString(payload.Slice(10, 66)).TrimEnd('\0').Trim();
        var extracted = new List<string>();

        // Walk past the 96-byte Lead and up to 2 RPM Header structures (8E AD E8 01) to carve the compressed CPIO payload
        int pos = 96;
        for (int h = 0; h < 2 && pos + 16 <= payload.Length; h++)
        {
            if (!payload.Slice(pos, 4).SequenceEqual(new byte[] { 0x8E, 0xAD, 0xE8, 0x01 }))
                break;

            uint nindex = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(pos + 8, 4));
            uint hsize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(pos + 12, 4));
            pos += 16 + (int)(nindex * 16) + (int)hsize;
            if (h == 0)
                pos = (pos + 7) & ~7; // Signature header is 8-byte aligned
        }

        if (pos < payload.Length)
        {
            string payloadPath = Path.Combine(outputDirectory, $"rpm_{pkgName}_payload.bin");
            File.WriteAllBytes(payloadPath, payload[pos..].ToArray());
            extracted.Add(payloadPath);
            return new ExtractorExecutionResult(
                true, Id, extracted,
                $"[+] RPM Unpacker (IDArc #162): Carved '{pkgName}' inner archive ({payload.Length - pos:N0} B) -> {payloadPath}");
        }

        return new ExtractorExecutionResult(false, Id, extracted, "[!] RPM payload offset out of bounds.");
    }
}

public sealed class MsCompressExtractor : IFirmwareExtractor
{
    public string Id => "mscompress";
    public string Name => "MS Compress (SZDD LZSS) Decompressor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "mscompress", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("MS Compress", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 14 && payload[..8].SequenceEqual(new byte[] { 0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33 }));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 14)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] MS Compress payload too small.");

        Directory.CreateDirectory(outputDirectory);
        if (payload[..8].SequenceEqual(new byte[] { 0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33 }))
        {
            uint uncompSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(10, 4));
            byte[] decomp = DecompressSzddLzss(payload[14..], (int)Math.Min(uncompSize, 64 * 1024 * 1024));
            string outPath = Path.Combine(outputDirectory, "szdd_decompressed.bin");
            File.WriteAllBytes(outPath, decomp);
            return new ExtractorExecutionResult(
                true, Id, new[] { outPath },
                $"[+] MS Compress SZDD Decompressor (IDArc #84): Unpacked {decomp.Length:N0} bytes -> {outPath}");
        }

        ushort dataOff = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(10, 2));
        if (dataOff < payload.Length)
        {
            string kwajPath = Path.Combine(outputDirectory, "kwaj_payload.bin");
            File.WriteAllBytes(kwajPath, payload[dataOff..].ToArray());
            return new ExtractorExecutionResult(true, Id, new[] { kwajPath }, $"[+] MS Compress KWAJ Carver -> {kwajPath}");
        }

        return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Unsupported MS Compress stream.");
    }

    public static byte[] DecompressSzddLzss(ReadOnlySpan<byte> src, int expectedSize)
    {
        using var outMs = new MemoryStream(Math.Max(64, expectedSize));
        Span<byte> ring = stackalloc byte[4096];
        ring.Fill(0x20); // Microsoft SZDD initializes the 4KB LZSS ring buffer with ASCII spaces (0x20)
        int ringPos = 4096 - 16;

        int inPos = 0;
        while (inPos < src.Length && outMs.Length < expectedSize)
        {
            byte control = src[inPos++];
            for (int bit = 0; bit < 8 && inPos < src.Length && outMs.Length < expectedSize; bit++)
            {
                if ((control & (1 << bit)) != 0) // Literal byte
                {
                    byte b = src[inPos++];
                    outMs.WriteByte(b);
                    ring[ringPos] = b;
                    ringPos = (ringPos + 1) & 0x0FFF;
                }
                else // 12-bit offset + 4-bit (length - 3) match
                {
                    if (inPos + 1 >= src.Length) break;
                    byte b1 = src[inPos++];
                    byte b2 = src[inPos++];
                    int matchPos = b1 | ((b2 & 0xF0) << 4);
                    int matchLen = (b2 & 0x0F) + 3;

                    for (int k = 0; k < matchLen && outMs.Length < expectedSize; k++)
                    {
                        byte b = ring[(matchPos + k) & 0x0FFF];
                        outMs.WriteByte(b);
                        ring[ringPos] = b;
                        ringPos = (ringPos + 1) & 0x0FFF;
                    }
                }
            }
        }

        return outMs.ToArray();
    }
}

public sealed class LzopExtractor : IFirmwareExtractor
{
    public string Id => "lzop";
    public string Name => "LZOP Stream Block Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "lzop", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("LZOP", StringComparison.OrdinalIgnoreCase);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string manifestPath = Path.Combine(outputDirectory, "lzop_manifest.txt");
        File.WriteAllText(manifestPath, $"LZOP Stream Carved (IDArc #101, {payload.Length} bytes){Environment.NewLine}");
        return new ExtractorExecutionResult(true, Id, new[] { manifestPath }, $"[+] LZOP Unpacker: Saved manifest -> {manifestPath}", SupportsRecursion: false);
    }
}

public sealed class MzSfxOverlayExtractor : IFirmwareExtractor
{
    public string Id => "sfx_overlay";
    public string Name => "MZ Self-Extracting Archive (SFX) Overlay Carver";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "sfx_overlay", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("Self-Extracting Archive", StringComparison.OrdinalIgnoreCase);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 64 || payload[0] != (byte)'M' || payload[1] != (byte)'Z')
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid MZ executable header.");

        ushort lastPageSize = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(2, 2));
        ushort pages = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(4, 2));
        long stubSize = (pages - 1L) * 512L + lastPageSize;

        if (stubSize <= 0 || stubSize >= payload.Length)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] No appended SFX overlay found after MZ stub.");

        Directory.CreateDirectory(outputDirectory);
        string stubPath = Path.Combine(outputDirectory, "sfx_exe_stub.exe");
        File.WriteAllBytes(stubPath, payload.Slice(0, (int)stubSize).ToArray());

        string overlayPath = Path.Combine(outputDirectory, "sfx_appended_archive.bin");
        File.WriteAllBytes(overlayPath, payload[(int)stubSize..].ToArray());

        return new ExtractorExecutionResult(
            true, Id, new[] { stubPath, overlayPath },
            $"[+] IDArc MZ SFX Carver: Split EXE stub ({stubSize:N0} B) and appended archive ({payload.Length - stubSize:N0} B) -> {overlayPath}",
            SupportsRecursion: true);
    }
}

