using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using HexCraft.Core.Analysis;

namespace HexCraft.Tools.Extractors;

/// <summary>
/// Built-in native firmware extractors modeled after Binwalk v3's <c>src/extractors/</c> modules:
/// <list type="bullet">
/// <item><description><see cref="CramFsExtractor"/> (<c>cramfs.rs</c>) — Linux CramFS filesystem unpacker with zlib page decompression</description></item>
/// <item><description><see cref="RomFsExtractor"/> (<c>romfs.rs</c>) — Linux ROMFS (<c>-rom1fs-</c>) directory &amp; file hierarchy unpacker</description></item>
/// <item><description><see cref="DtbExtractor"/> (<c>dtb.rs</c>) — Flattened Device Tree (<c>.dtb</c> to <c>.dts</c>) native decompiler</description></item>
/// <item><description><see cref="UImageExtractor"/> (<c>uimage.rs</c>) — Das U-Boot <c>uImage</c> single &amp; multi-file unpacker with CRC32 verification</description></item>
/// <item><description><see cref="TrxExtractor"/> &amp; <see cref="SeamaExtractor"/> (<c>trx.rs</c>, <c>seama.rs</c>) — Broadcom TRX &amp; D-Link SEAMA partition splitters</description></item>
/// <item><description><see cref="CpioExtractor"/>, <see cref="TarExtractor"/>, <see cref="GzipExtractor"/>, <see cref="ZlibExtractor"/>, <see cref="ZipExtractor"/>, <see cref="PemExtractor"/></description></item>
/// </list>
/// </summary>
public static class BuiltinFirmwareExtractors
{
    public static IReadOnlyList<IFirmwareExtractor> All { get; } = new IFirmwareExtractor[]
    {
        new SquashFsExtractor(),
        new CramFsExtractor(),
        new RomFsExtractor(),
        new Jffs2Extractor(),
        new ExtFsExtractor(),
        new UbiExtractor(),
        new DtbExtractor(),
        new UImageExtractor(),
        new TrxExtractor(),
        new SeamaExtractor(),
        new DlobExtractor(),
        new CpioExtractor(),
        new TarExtractor(),
        new SevenZipExtractor(),
        new ZipExtractor(),
        new GzipExtractor(),
        new ZlibExtractor(),
        new Bzip2Extractor(),
        new LzmaExtractor(),
        new XzExtractor(),
        new ZstdExtractor(),
        new PemExtractor(),
        new OpenSslExtractor(),
        new ElfExtractor(),
        new PngExtractor(),
    };
}

// ============================================================================
// 1. CramFS Filesystem Extractor (binwalk/src/extractors/cramfs.rs)
// ============================================================================
public sealed class CramFsExtractor : IFirmwareExtractor
{
    public string Id => "cramfs";
    public string Name => "CramFS Filesystem Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        if (string.Equals(signatureId, "cramfs", StringComparison.OrdinalIgnoreCase) ||
            signatureType.Contains("CramFS", StringComparison.OrdinalIgnoreCase))
            return true;

        if (payload.Length >= 64)
        {
            uint magicLe = BinaryPrimitives.ReadUInt32LittleEndian(payload);
            uint magicBe = BinaryPrimitives.ReadUInt32BigEndian(payload);
            return magicLe == 0x28CD3D45 || magicBe == 0x28CD3D45;
        }
        return false;
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 64)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] CramFS payload too small (< 64 bytes).");

        bool littleEndian = BinaryPrimitives.ReadUInt32LittleEndian(payload) == 0x28CD3D45;
        bool bigEndian = BinaryPrimitives.ReadUInt32BigEndian(payload) == 0x28CD3D45;
        if (!littleEndian && !bigEndian)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid CramFS superblock magic.");

        string cramRoot = Path.Combine(outputDirectory, "cramfs-root");
        Directory.CreateDirectory(cramRoot);

        var extractedFiles = new List<string>();
        var log = new StringBuilder();
        var visitedOffsets = new HashSet<int>();

        // Root inode sits at offset 0x20 (32) in the 64-byte CramFS superblock
        var rootInode = DecodeInode(payload.Slice(32, 12), littleEndian);
        UnpackDirectory(payload, rootInode, cramRoot, littleEndian, extractedFiles, log, visitedOffsets, depth: 0);

        log.Insert(0, $"[+] CramFS Unpacker ({(littleEndian ? "LE" : "BE")}): Extracted {extractedFiles.Count} files -> {cramRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private readonly record struct CramFsInode(ushort Mode, ushort Uid, int Size, byte Gid, int NameLenBytes, int DataOffset);

    private static CramFsInode DecodeInode(ReadOnlySpan<byte> raw, bool le)
    {
        if (le)
        {
            ushort mode = BinaryPrimitives.ReadUInt16LittleEndian(raw[..2]);
            ushort uid = BinaryPrimitives.ReadUInt16LittleEndian(raw.Slice(2, 2));
            uint sizeGid = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(4, 4));
            uint namelenOffset = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(8, 4));

            int size = (int)(sizeGid & 0x00FFFFFF);
            byte gid = (byte)(sizeGid >> 24);
            int nameLenBytes = (int)(namelenOffset & 0x3F) * 4;
            int dataOffset = (int)(namelenOffset >> 6) * 4;
            return new CramFsInode(mode, uid, size, gid, nameLenBytes, dataOffset);
        }
        else
        {
            ushort mode = BinaryPrimitives.ReadUInt16BigEndian(raw[..2]);
            ushort uid = BinaryPrimitives.ReadUInt16BigEndian(raw.Slice(2, 2));
            uint sizeGid = BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(4, 4));
            uint namelenOffset = BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(8, 4));

            int size = (int)(sizeGid >> 8);
            byte gid = (byte)(sizeGid & 0xFF);
            int nameLenBytes = (int)(namelenOffset >> 26) * 4;
            int dataOffset = (int)(namelenOffset & 0x03FFFFFF) * 4;
            return new CramFsInode(mode, uid, size, gid, nameLenBytes, dataOffset);
        }
    }

    private static void UnpackDirectory(
        ReadOnlySpan<byte> image,
        CramFsInode dirInode,
        string currentDir,
        bool le,
        List<string> extractedFiles,
        StringBuilder log,
        HashSet<int> visited,
        int depth)
    {
        if (depth > 32 || dirInode.DataOffset <= 0 || dirInode.Size <= 0)
            return;
        if (!visited.Add(dirInode.DataOffset))
            return;

        int pos = dirInode.DataOffset;
        int end = Math.Min(image.Length, dirInode.DataOffset + dirInode.Size);

        while (pos + 12 <= end)
        {
            var child = DecodeInode(image.Slice(pos, 12), le);
            pos += 12;

            if (child.NameLenBytes <= 0 || pos + child.NameLenBytes > end)
                break;

            string name = Encoding.UTF8.GetString(image.Slice(pos, child.NameLenBytes)).TrimEnd('\0');
            pos += child.NameLenBytes;

            if (string.IsNullOrEmpty(name) || name == "." || name == "..")
                continue;

            ushort fileType = (ushort)(child.Mode & 0xF000);
            string targetPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(currentDir, name);

            if (fileType == 0x4000) // S_IFDIR
            {
                Directory.CreateDirectory(targetPath);
                UnpackDirectory(image, child, targetPath, le, extractedFiles, log, visited, depth + 1);
            }
            else if (fileType == 0x8000) // S_IFREG
            {
                byte[] fileData = DecompressRegularFile(image, child, le);
                Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                File.WriteAllBytes(targetPath, fileData);
                extractedFiles.Add(targetPath);
                log.AppendLine($"  [+] CramFS File: '{name}' ({fileData.Length:N0} B)");
            }
        }
    }

    private static byte[] DecompressRegularFile(ReadOnlySpan<byte> image, CramFsInode inode, bool le)
    {
        if (inode.Size == 0 || inode.DataOffset <= 0 || inode.DataOffset >= image.Length)
            return Array.Empty<byte>();

        int numBlocks = (inode.Size + 4095) / 4096;
        int pointerTableBytes = numBlocks * 4;
        if (inode.DataOffset + pointerTableBytes > image.Length)
            return Array.Empty<byte>();

        using var outMs = new MemoryStream(inode.Size);
        int blockStart = inode.DataOffset + pointerTableBytes;

        for (int i = 0; i < numBlocks; i++)
        {
            var ptrSlice = image.Slice(inode.DataOffset + i * 4, 4);
            int blockEnd = (int)(le
                ? BinaryPrimitives.ReadUInt32LittleEndian(ptrSlice)
                : BinaryPrimitives.ReadUInt32BigEndian(ptrSlice));

            if (blockEnd < blockStart || blockEnd > image.Length)
                break;

            int compressedLen = blockEnd - blockStart;
            if (compressedLen > 0)
            {
                byte[] compSlice = image.Slice(blockStart, compressedLen).ToArray();
                using var inMs = new MemoryStream(compSlice);
                using var zlib = new ZLibStream(inMs, CompressionMode.Decompress);
                zlib.CopyTo(outMs);
            }

            blockStart = blockEnd;
        }

        return outMs.ToArray();
    }
}

// ============================================================================
// 2. Linux ROMFS Filesystem Extractor (binwalk/src/extractors/romfs.rs)
// ============================================================================
public sealed class RomFsExtractor : IFirmwareExtractor
{
    public string Id => "romfs";
    public string Name => "Linux ROMFS Filesystem Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "romfs", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("ROMFS", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 32 && payload[..8].SequenceEqual("-rom1fs-"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 32 || !payload[..8].SequenceEqual("-rom1fs-"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid ROMFS header.");

        // Volume name starts at offset 16 and is null-terminated, padded to 16-byte boundary
        int volNameEnd = 16;
        while (volNameEnd < payload.Length && payload[volNameEnd] != 0)
            volNameEnd++;

        int rootNodeOffset = Align16(volNameEnd + 1);
        string romRoot = Path.Combine(outputDirectory, "romfs-root");
        Directory.CreateDirectory(romRoot);

        var extractedFiles = new List<string>();
        var log = new StringBuilder();
        var visited = new HashSet<int>();

        WalkNodes(payload, rootNodeOffset, romRoot, extractedFiles, log, visited, depth: 0);

        log.Insert(0, $"[+] ROMFS Unpacker: Extracted {extractedFiles.Count} files -> {romRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static void WalkNodes(
        ReadOnlySpan<byte> image,
        int startOffset,
        string currentDir,
        List<string> extractedFiles,
        StringBuilder log,
        HashSet<int> visited,
        int depth)
    {
        if (depth > 32)
            return;

        int curr = startOffset;
        while (curr >= 16 && curr + 16 <= image.Length && visited.Add(curr))
        {
            uint nextFh = BinaryPrimitives.ReadUInt32BigEndian(image.Slice(curr, 4));
            uint specInfo = BinaryPrimitives.ReadUInt32BigEndian(image.Slice(curr + 4, 4));
            uint fileSize = BinaryPrimitives.ReadUInt32BigEndian(image.Slice(curr + 8, 4));

            int nextOffset = (int)(nextFh & 0xFFFFFFF0);
            int fileType = (int)(nextFh & 0x07);

            int nameStart = curr + 16;
            int nameEnd = nameStart;
            while (nameEnd < image.Length && image[nameEnd] != 0)
                nameEnd++;

            if (nameEnd >= image.Length)
                break;

            string name = Encoding.UTF8.GetString(image.Slice(nameStart, nameEnd - nameStart));
            int dataOffset = Align16(nameEnd + 1);

            if (!string.IsNullOrEmpty(name) && name != "." && name != "..")
            {
                string targetPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(currentDir, name);

                if (fileType == 1) // Directory
                {
                    Directory.CreateDirectory(targetPath);
                    if (specInfo >= 16 && specInfo < image.Length && specInfo != curr)
                    {
                        WalkNodes(image, (int)specInfo, targetPath, extractedFiles, log, visited, depth + 1);
                    }
                }
                else if (fileType == 2 && dataOffset + fileSize <= image.Length) // Regular file
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                    byte[] data = image.Slice(dataOffset, (int)fileSize).ToArray();
                    File.WriteAllBytes(targetPath, data);
                    extractedFiles.Add(targetPath);
                    log.AppendLine($"  [+] ROMFS File: '{name}' ({fileSize:N0} B)");
                }
            }

            curr = nextOffset;
        }
    }

    private static int Align16(int value) => (value + 15) & ~15;
}

// ============================================================================
// 3. Flattened Device Tree (.dtb -> .dts) Decompiler (binwalk/src/extractors/dtb.rs)
// ============================================================================
public sealed class DtbExtractor : IFirmwareExtractor
{
    private const uint FDT_BEGIN_NODE = 0x00000001;
    private const uint FDT_END_NODE   = 0x00000002;
    private const uint FDT_PROP       = 0x00000003;
    private const uint FDT_NOP        = 0x00000004;
    private const uint FDT_END        = 0x00000009;

    public string Id => "dtb";
    public string Name => "Flattened Device Tree (.dtb -> .dts) Decompiler";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "dtb", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("Device Tree", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 40 && BinaryPrimitives.ReadUInt32BigEndian(payload) == 0xD00DFEED);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 40 || BinaryPrimitives.ReadUInt32BigEndian(payload) != 0xD00DFEED)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid FDT header magic.");

        uint totalSize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(4, 4));
        uint offDtStruct = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(8, 4));
        uint offDtStrings = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(12, 4));
        uint version = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(20, 4));
        uint sizeDtStrings = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(32, 4));
        uint sizeDtStruct = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(36, 4));

        if (offDtStruct >= payload.Length || offDtStrings >= payload.Length)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] FDT structure/string offsets out of bounds.");

        var dts = new StringBuilder();
        dts.AppendLine("/dts-v1/;");
        dts.AppendLine($"// Decompiled by HexCraft Internal FDT Decompiler (FDT v{version}, {totalSize} bytes)");
        dts.AppendLine();

        int pos = (int)offDtStruct;
        int structEnd = (int)Math.Min(payload.Length, offDtStruct + (sizeDtStruct > 0 ? sizeDtStruct : payload.Length - offDtStruct));
        int indent = 0;
        int nodeCount = 0;
        int propCount = 0;

        while (pos + 4 <= structEnd)
        {
            uint token = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(pos, 4));
            pos += 4;

            if (token == FDT_BEGIN_NODE)
            {
                int nameEnd = pos;
                while (nameEnd < structEnd && payload[nameEnd] != 0)
                    nameEnd++;

                string nodeName = Encoding.UTF8.GetString(payload.Slice(pos, nameEnd - pos));
                pos = Align4(nameEnd + 1);

                string pad = new string(' ', indent * 4);
                dts.AppendLine($"{pad}{(string.IsNullOrEmpty(nodeName) ? "/" : nodeName)} {{");
                indent++;
                nodeCount++;
            }
            else if (token == FDT_END_NODE)
            {
                indent = Math.Max(0, indent - 1);
                string pad = new string(' ', indent * 4);
                dts.AppendLine($"{pad}}};");
            }
            else if (token == FDT_PROP)
            {
                if (pos + 8 > structEnd)
                    break;

                uint propLen = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(pos, 4));
                uint nameOff = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(pos + 4, 4));
                pos += 8;

                if (pos + propLen > structEnd)
                    break;

                var propVal = payload.Slice(pos, (int)propLen);
                pos = Align4(pos + (int)propLen);

                string propName = ReadNullTerminatedString(payload, (int)(offDtStrings + nameOff), (int)(offDtStrings + sizeDtStrings));
                string pad = new string(' ', indent * 4);

                if (propLen == 0)
                {
                    dts.AppendLine($"{pad}{propName};");
                }
                else
                {
                    string formatted = FormatPropertyValue(propName, propVal);
                    dts.AppendLine($"{pad}{propName} = {formatted};");
                }
                propCount++;
            }
            else if (token == FDT_NOP)
            {
                continue;
            }
            else if (token == FDT_END)
            {
                break;
            }
            else
            {
                break;
            }
        }

        Directory.CreateDirectory(outputDirectory);
        string dtsPath = Path.Combine(outputDirectory, "device_tree.dts");
        File.WriteAllText(dtsPath, dts.ToString());

        string log = $"[+] DTB Decompiler: Decompiled {nodeCount} nodes and {propCount} properties -> {dtsPath}";
        return new ExtractorExecutionResult(true, Id, new[] { dtsPath }, log, SupportsRecursion: false);
    }

    private static string ReadNullTerminatedString(ReadOnlySpan<byte> buf, int offset, int maxEnd)
    {
        if (offset < 0 || offset >= buf.Length)
            return "unknown";
        int limit = Math.Min(buf.Length, maxEnd > offset ? maxEnd : buf.Length);
        int end = offset;
        while (end < limit && buf[end] != 0)
            end++;
        return Encoding.UTF8.GetString(buf.Slice(offset, end - offset));
    }

    private static string FormatPropertyValue(string propName, ReadOnlySpan<byte> val)
    {
        // Check if value is a printable null-terminated string (or string list)
        if (val[^1] == 0 && val.Length > 1 && IsPrintableStringList(val))
        {
            var strings = new List<string>();
            int start = 0;
            for (int i = 0; i < val.Length; i++)
            {
                if (val[i] == 0)
                {
                    if (i > start)
                        strings.Add($"\"{Encoding.UTF8.GetString(val.Slice(start, i - start))}\"");
                    start = i + 1;
                }
            }
            if (strings.Count > 0)
                return string.Join(", ", strings);
        }

        // If multiple of 4 bytes, format as 32-bit big-endian cells <0x...>
        if (val.Length % 4 == 0 && val.Length <= 64)
        {
            var cells = new List<string>(val.Length / 4);
            for (int i = 0; i < val.Length; i += 4)
            {
                uint cell = BinaryPrimitives.ReadUInt32BigEndian(val.Slice(i, 4));
                cells.Add($"0x{cell:x}");
            }
            return $"<{string.Join(" ", cells)}>";
        }

        // Otherwise format as byte array [00 11 22 ...]
        var hex = new List<string>(Math.Min(val.Length, 32));
        for (int i = 0; i < Math.Min(val.Length, 32); i++)
            hex.Add($"{val[i]:x2}");
        if (val.Length > 32)
            hex.Add("...");
        return $"[{string.Join(" ", hex)}]";
    }

    private static bool IsPrintableStringList(ReadOnlySpan<byte> val)
    {
        int consecutiveNulls = 0;
        for (int i = 0; i < val.Length; i++)
        {
            byte b = val[i];
            if (b == 0)
            {
                consecutiveNulls++;
                if (consecutiveNulls > 1) return false;
            }
            else
            {
                consecutiveNulls = 0;
                if (b < 0x20 || b > 0x7E) return false;
            }
        }
        return true;
    }

    private static int Align4(int value) => (value + 3) & ~3;
}

// ============================================================================
// 4. Das U-Boot uImage Extractor (binwalk/src/extractors/uimage.rs)
// ============================================================================
public sealed class UImageExtractor : IFirmwareExtractor
{
    public string Id => "uimage";
    public string Name => "U-Boot uImage Container Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "uimage", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("U-Boot uImage", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 64 && BinaryPrimitives.ReadUInt32BigEndian(payload) == 0x27051956);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 64 || BinaryPrimitives.ReadUInt32BigEndian(payload) != 0x27051956)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid U-Boot uImage magic.");

        Directory.CreateDirectory(outputDirectory);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        uint headerCrcExpected = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(4, 4));
        uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(8, 4));
        uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(12, 4));
        uint loadAddr = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(16, 4));
        uint entryPoint = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(20, 4));
        uint dataCrcExpected = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(24, 4));
        byte osType = payload[28];
        byte archType = payload[29];
        byte imageType = payload[30];
        byte compType = payload[31];
        string name = Encoding.UTF8.GetString(payload.Slice(32, 32)).TrimEnd('\0').Trim();

        // Verify Header CRC32 with bytes 4..8 zeroed
        Span<byte> hdrCopy = stackalloc byte[64];
        payload[..64].CopyTo(hdrCopy);
        hdrCopy.Slice(4, 4).Clear();
        uint headerCrcActual = ComputeCrc32(hdrCopy);
        bool hdrCrcOk = headerCrcActual == headerCrcExpected;

        int availablePayload = (int)Math.Min(payload.Length - 64, dataSize);
        var body = payload.Slice(64, Math.Max(0, availablePayload));
        uint dataCrcActual = ComputeCrc32(body);
        bool dataCrcOk = dataCrcActual == dataCrcExpected;

        string manifestPath = Path.Combine(outputDirectory, "uimage_manifest.txt");
        File.WriteAllText(manifestPath,
            $"Image Name   : {name}{Environment.NewLine}" +
            $"Created      : {DateTimeOffset.FromUnixTimeSeconds(timestamp):u}{Environment.NewLine}" +
            $"Data Size    : {dataSize} bytes{Environment.NewLine}" +
            $"Load Address : 0x{loadAddr:X8}{Environment.NewLine}" +
            $"Entry Point  : 0x{entryPoint:X8}{Environment.NewLine}" +
            $"Header CRC32 : 0x{headerCrcActual:X8} (Expected 0x{headerCrcExpected:X8}, Valid={hdrCrcOk}){Environment.NewLine}" +
            $"Data CRC32   : 0x{dataCrcActual:X8} (Expected 0x{dataCrcExpected:X8}, Valid={dataCrcOk}){Environment.NewLine}");
        extractedFiles.Add(manifestPath);

        if (imageType == 4 && body.Length >= 8) // IH_TYPE_MULTI (Multi-File Image)
        {
            var partSizes = new List<uint>();
            int tablePos = 0;
            while (tablePos + 4 <= body.Length)
            {
                uint sz = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(tablePos, 4));
                tablePos += 4;
                if (sz == 0) break;
                partSizes.Add(sz);
            }

            int dataPos = tablePos;
            for (int i = 0; i < partSizes.Count; i++)
            {
                int sz = (int)partSizes[i];
                if (dataPos + sz > body.Length) break;

                string partPath = Path.Combine(outputDirectory, $"uimage_part{i}.bin");
                File.WriteAllBytes(partPath, body.Slice(dataPos, sz).ToArray());
                extractedFiles.Add(partPath);
                log.AppendLine($"  [+] uImage Multi-Part #{i}: {sz:N0} bytes -> {partPath}");

                dataPos = (dataPos + sz + 3) & ~3;
            }
        }
        else if (body.Length > 0)
        {
            string rawPayloadPath = Path.Combine(outputDirectory, "uimage_payload.bin");
            File.WriteAllBytes(rawPayloadPath, body.ToArray());
            extractedFiles.Add(rawPayloadPath);
            log.AppendLine($"[+] uImage Unpacker: Extracted payload ({body.Length:N0} B, HeaderCRC={hdrCrcOk}, DataCRC={dataCrcOk}) -> {rawPayloadPath}");

            // If compressed with GZip (compType == 1), automatically decompress the inner image
            if (compType == 1 && body.Length >= 10 && body[0] == 0x1F && body[1] == 0x8B)
            {
                try
                {
                    using var inMs = new MemoryStream(body.ToArray());
                    using var gz = new GZipStream(inMs, CompressionMode.Decompress);
                    using var outMs = new MemoryStream();
                    gz.CopyTo(outMs);
                    byte[] decomp = outMs.ToArray();
                    string decompPath = Path.Combine(outputDirectory, "uimage_decompressed.bin");
                    File.WriteAllBytes(decompPath, decomp);
                    extractedFiles.Add(decompPath);
                    log.AppendLine($"  [+] uImage GZip Decompressor: Unpacked inner image ({decomp.Length:N0} B) -> {decompPath}");
                }
                catch (Exception ex)
                {
                    log.AppendLine($"  [!] uImage inner GZip note: {ex.Message}");
                }
            }
        }

        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString());
    }

    public static uint ComputeCrc32(ReadOnlySpan<byte> data)
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
// 5. Broadcom TRX & D-Link SEAMA Partition Extractors (trx.rs & seama.rs)
// ============================================================================
public sealed class TrxExtractor : IFirmwareExtractor
{
    public string Id => "trx";
    public string Name => "Broadcom TRX Partition Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "trx", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("Broadcom TRX", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 28 && payload[..4].SequenceEqual("HDR0"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 28 || !payload[..4].SequenceEqual("HDR0"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid Broadcom TRX header.");

        Directory.CreateDirectory(outputDirectory);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        uint totalLen = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(4, 4));
        uint crcExpected = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(8, 4));
        uint flagsVer = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(12, 4));
        ushort version = (ushort)(flagsVer >> 16);

        int maxPartitions = version >= 2 && payload.Length >= 32 ? 4 : 3;
        var offsets = new List<uint>();
        for (int i = 0; i < maxPartitions; i++)
        {
            uint off = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(16 + i * 4, 4));
            if (off > 0 && off < payload.Length)
                offsets.Add(off);
        }

        uint effectiveEnd = (uint)Math.Min(payload.Length, totalLen);
        for (int i = 0; i < offsets.Count; i++)
        {
            uint start = offsets[i];
            uint end = (i + 1 < offsets.Count) ? offsets[i + 1] : effectiveEnd;
            if (end <= start || start >= payload.Length) continue;

            int len = (int)Math.Min(end - start, payload.Length - start);
            string partPath = Path.Combine(outputDirectory, $"trx_partition_{i}.bin");
            File.WriteAllBytes(partPath, payload.Slice((int)start, len).ToArray());
            extractedFiles.Add(partPath);
            log.AppendLine($"[+] TRX Partition #{i}: offset 0x{start:X} ({len:N0} bytes) -> {partPath}");
        }

        string manifestPath = Path.Combine(outputDirectory, "trx_manifest.txt");
        File.WriteAllText(manifestPath, $"TRX v{version}, TotalSize={totalLen}, CRC32=0x{crcExpected:X8}, Partitions={offsets.Count}{Environment.NewLine}");
        extractedFiles.Add(manifestPath);

        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString());
    }

    public static uint ComputeCrc32(ReadOnlySpan<byte> data)
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

public sealed class SeamaExtractor : IFirmwareExtractor
{
    public string Id => "seama";
    public string Name => "D-Link SEAMA Firmware Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "seama", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("SEAMA", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 28 && BinaryPrimitives.ReadUInt32BigEndian(payload) == 0x5EA3A417);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 28 || BinaryPrimitives.ReadUInt32BigEndian(payload) != 0x5EA3A417)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid SEAMA header.");

        Directory.CreateDirectory(outputDirectory);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        ushort metaSize = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6, 2));
        uint imageSize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(8, 4));
        string md5Expected = Convert.ToHexString(payload.Slice(12, 16));

        int metaStart = 28;
        int payloadStart = 28 + metaSize;

        if (metaSize > 0 && payloadStart <= payload.Length)
        {
            string metaText = Encoding.UTF8.GetString(payload.Slice(metaStart, metaSize)).Replace('\0', '\n').Trim();
            string metaPath = Path.Combine(outputDirectory, "seama_meta.txt");
            File.WriteAllText(metaPath, metaText + Environment.NewLine + $"ExpectedMD5={md5Expected}" + Environment.NewLine);
            extractedFiles.Add(metaPath);
            log.AppendLine($"[+] SEAMA Metadata ({metaSize} B): {metaText.Replace('\n', ';')}");
        }

        if (imageSize > 0 && payloadStart < payload.Length)
        {
            int actualSize = (int)Math.Min(imageSize, payload.Length - payloadStart);
            byte[] imageBytes = payload.Slice(payloadStart, actualSize).ToArray();
            string imgPath = Path.Combine(outputDirectory, "seama_payload.bin");
            File.WriteAllBytes(imgPath, imageBytes);
            extractedFiles.Add(imgPath);
            log.AppendLine($"[+] SEAMA Payload: {actualSize:N0} bytes -> {imgPath}");
        }

        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString());
    }

    public static uint ComputeCrc32(ReadOnlySpan<byte> data)
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
// 6. CPIO, TAR, GZip, Zlib, ZIP, and PEM Native Extractors
// ============================================================================
public sealed class CpioExtractor : IFirmwareExtractor
{
    public string Id => "cpio";
    public string Name => "SVR4 ASCII CPIO Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "cpio", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("CPIO", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 110 && (payload[..6].SequenceEqual("070701"u8) || payload[..6].SequenceEqual("070702"u8)));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        string cpioDir = Path.Combine(outputDirectory, "cpio-root");
        var log = new StringBuilder();
        int count = FirmwareToolService.ExtractCpioNewcArchive(payload, cpioDir, log);
        var files = Directory.Exists(cpioDir)
            ? Directory.GetFiles(cpioDir, "*", SearchOption.AllDirectories)
            : Array.Empty<string>();
        log.Insert(0, $"[+] Built-in CPIO Unpacker: Extracted {count} files -> {cpioDir}{Environment.NewLine}");
        return new ExtractorExecutionResult(count > 0, Id, files, log.ToString(), SupportsRecursion: false);
    }
}

public sealed class TarExtractor : IFirmwareExtractor
{
    public string Id => "tar";
    public string Name => "POSIX ustar TAR Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "tar", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("TAR", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 512 && payload.Slice(257, 5).SequenceEqual("ustar"u8));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        string tarDir = Path.Combine(outputDirectory, "tar-root");
        var log = new StringBuilder();
        int count = FirmwareToolService.ExtractPosixTarArchive(payload, tarDir, log);
        var files = Directory.Exists(tarDir)
            ? Directory.GetFiles(tarDir, "*", SearchOption.AllDirectories)
            : Array.Empty<string>();
        log.Insert(0, $"[+] Built-in TAR Unpacker: Extracted {count} files -> {tarDir}{Environment.NewLine}");
        return new ExtractorExecutionResult(count > 0, Id, files, log.ToString(), SupportsRecursion: false);
    }
}

public sealed class GzipExtractor : IFirmwareExtractor
{
    public string Id => "gzip";
    public string Name => "GZip Stream Decompressor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "gzip", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("GZip", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 10 && payload[0] == 0x1F && payload[1] == 0x8B && payload[2] == 0x08);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        try
        {
            using var inMs = new MemoryStream(payload.ToArray());
            using var gz = new GZipStream(inMs, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            gz.CopyTo(outMs);
            byte[] decomp = outMs.ToArray();
            string outPath = Path.Combine(outputDirectory, "decompressed_payload.bin");
            File.WriteAllBytes(outPath, decomp);
            return new ExtractorExecutionResult(
                true, Id, new[] { outPath },
                $"[+] Built-in GZip Decompressor: Unpacked {decomp.Length:N0} bytes -> {outPath}");
        }
        catch (Exception ex)
        {
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), $"[!] GZip decompression note: {ex.Message}");
        }
    }
}

public sealed class ZlibExtractor : IFirmwareExtractor
{
    public string Id => "zlib";
    public string Name => "Zlib RFC 1950 Stream Decompressor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "zlib", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("Zlib", StringComparison.OrdinalIgnoreCase);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        try
        {
            using var inMs = new MemoryStream(payload.ToArray());
            using var zl = new ZLibStream(inMs, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            zl.CopyTo(outMs);
            byte[] decomp = outMs.ToArray();
            string outPath = Path.Combine(outputDirectory, "zlib_decompressed.bin");
            File.WriteAllBytes(outPath, decomp);
            return new ExtractorExecutionResult(
                true, Id, new[] { outPath },
                $"[+] Built-in Zlib Decompressor: Unpacked {decomp.Length:N0} bytes -> {outPath}");
        }
        catch (Exception ex)
        {
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), $"[!] Zlib decompression note: {ex.Message}");
        }
    }
}

public sealed class ZipExtractor : IFirmwareExtractor
{
    public string Id => "zip";
    public string Name => "ZIP Archive Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "zip", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("ZIP", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 30 && payload[..4].SequenceEqual("PK\x03\x04"u8));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        string zipOutDir = Path.Combine(outputDirectory, "zip-root");
        Directory.CreateDirectory(zipOutDir);
        var extracted = new List<string>();
        var log = new StringBuilder();

        try
        {
            using var zipMs = new MemoryStream(payload.ToArray());
            using var archive = new ZipArchive(zipMs, ZipArchiveMode.Read);
            foreach (var zipEntry in archive.Entries)
            {
                if (string.IsNullOrEmpty(zipEntry.Name)) continue;
                string targetFile = FirmwareExtractorRegistry.SanitizeSafeOutputPath(zipOutDir, zipEntry.FullName);
                Directory.CreateDirectory(Path.GetDirectoryName(targetFile)!);
                zipEntry.ExtractToFile(targetFile, overwrite: true);
                extracted.Add(targetFile);
                log.AppendLine($"  [+] ZIP Entry: '{zipEntry.FullName}' ({zipEntry.Length:N0} B)");
            }
            log.Insert(0, $"[+] Built-in ZIP Unpacker: Extracted {extracted.Count} files -> {zipOutDir}{Environment.NewLine}");
            return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString(), SupportsRecursion: false);
        }
        catch (Exception ex)
        {
            return new ExtractorExecutionResult(false, Id, extracted, $"[!] ZIP extraction note: {ex.Message}");
        }
    }
}

public sealed class PemExtractor : IFirmwareExtractor
{
    public string Id => "pem";
    public string Name => "PEM Certificate & Key Carve Extractor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
        => string.Equals(signatureId, "pem", StringComparison.OrdinalIgnoreCase) ||
           signatureType.Contains("PEM", StringComparison.OrdinalIgnoreCase) ||
           (payload.Length >= 32 && payload[..11].SequenceEqual("-----BEGIN "u8));

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string ext = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 48)]).Contains("KEY", StringComparison.OrdinalIgnoreCase)
            ? ".key.pem"
            : ".crt.pem";
        string outPath = Path.Combine(outputDirectory, $"extracted_credential{ext}");
        File.WriteAllBytes(outPath, payload.ToArray());
        return new ExtractorExecutionResult(
            true, Id, new[] { outPath },
            $"[+] PEM Credential Extractor: Saved {payload.Length:N0} bytes -> {outPath}",
            SupportsRecursion: false);
    }
}

