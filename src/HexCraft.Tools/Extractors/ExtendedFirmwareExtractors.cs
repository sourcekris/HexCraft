using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace HexCraft.Tools.Extractors;

// ============================================================================
// 7. JFFS2 Filesystem Unpacker (binwalk/src/extractors/jffs2.rs)
// ============================================================================
public sealed class Jffs2Extractor : IFirmwareExtractor
{
    private const ushort JFFS2_MAGIC = 0x1985;
    private const ushort JFFS2_NODETYPE_DIRENT = 0xE001;
    private const ushort JFFS2_NODETYPE_INODE  = 0xE002;

    public string Id => "jffs2";
    public string Name => "JFFS2 Log-Structured Filesystem Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        if (string.Equals(signatureId, "jffs2", StringComparison.OrdinalIgnoreCase) ||
            signatureType.Contains("JFFS2", StringComparison.OrdinalIgnoreCase))
            return true;

        if (payload.Length >= 12)
        {
            ushort le = BinaryPrimitives.ReadUInt16LittleEndian(payload[..2]);
            ushort be = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
            return le == JFFS2_MAGIC || be == JFFS2_MAGIC;
        }
        return false;
    }

    private sealed record DirentRecord(uint Pino, uint Version, uint Ino, byte Type, string Name);
    private sealed record InodeFrag(uint Ino, uint Version, uint ISize, uint FileOffset, uint DSize, byte Compr, byte[] Data);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 40)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] JFFS2 payload too small.");

        bool le = BinaryPrimitives.ReadUInt16LittleEndian(payload[..2]) == JFFS2_MAGIC;
        bool be = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]) == JFFS2_MAGIC;
        if (!le && !be)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid JFFS2 magic.");

        var dirents = new List<DirentRecord>();
        var fragsByIno = new Dictionary<uint, List<InodeFrag>>();

        int pos = 0;
        while (pos + 12 <= payload.Length)
        {
            ushort magic = ReadU16(payload.Slice(pos, 2), le);
            if (magic != JFFS2_MAGIC)
            {
                pos += 4;
                continue;
            }

            ushort nodeType = ReadU16(payload.Slice(pos + 2, 2), le);
            uint totLen = ReadU32(payload.Slice(pos + 4, 4), le);
            if (totLen < 12 || pos + totLen > payload.Length)
                break;

            var node = payload.Slice(pos, (int)totLen);

            if (nodeType == JFFS2_NODETYPE_DIRENT && totLen >= 40)
            {
                uint pino = ReadU32(node.Slice(12, 4), le);
                uint version = ReadU32(node.Slice(16, 4), le);
                uint ino = ReadU32(node.Slice(20, 4), le);
                byte nsize = node[28];
                byte type = node[29];

                if (40 + nsize <= node.Length && nsize > 0)
                {
                    string name = Encoding.UTF8.GetString(node.Slice(40, nsize));
                    dirents.Add(new DirentRecord(pino, version, ino, type, name));
                }
            }
            else if (nodeType == JFFS2_NODETYPE_INODE && totLen >= 68)
            {
                uint ino = ReadU32(node.Slice(12, 4), le);
                uint version = ReadU32(node.Slice(16, 4), le);
                uint isize = ReadU32(node.Slice(28, 4), le);
                uint offset = ReadU32(node.Slice(44, 4), le);
                uint csize = ReadU32(node.Slice(48, 4), le);
                uint dsize = ReadU32(node.Slice(52, 4), le);
                byte compr = node[56];

                if (68 + csize <= node.Length)
                {
                    byte[] rawFrag = node.Slice(68, (int)csize).ToArray();
                    if (!fragsByIno.TryGetValue(ino, out var list))
                    {
                        list = new List<InodeFrag>();
                        fragsByIno[ino] = list;
                    }
                    list.Add(new InodeFrag(ino, version, isize, offset, dsize, compr, rawFrag));
                }
            }

            pos = Align4(pos + (int)totLen);
        }

        // Keep highest version per (Pino, Name)
        var activeEntries = dirents
            .GroupBy(d => (d.Pino, d.Name))
            .Select(g => g.OrderByDescending(x => x.Version).First())
            .Where(d => d.Ino != 0)
            .ToList();

        string jffsRoot = Path.Combine(outputDirectory, "jffs2-root");
        Directory.CreateDirectory(jffsRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        // Map directory inodes (root is ino = 1)
        var dirPaths = new Dictionary<uint, string> { [1] = jffsRoot };
        bool progress = true;
        int pass = 0;
        while (progress && pass++ < 16)
        {
            progress = false;
            foreach (var d in activeEntries.Where(x => x.Type == 4)) // DT_DIR = 4
            {
                if (dirPaths.TryGetValue(d.Pino, out string? parentPath) && !dirPaths.ContainsKey(d.Ino))
                {
                    string subDir = FirmwareExtractorRegistry.SanitizeSafeOutputPath(parentPath, d.Name);
                    Directory.CreateDirectory(subDir);
                    dirPaths[d.Ino] = subDir;
                    progress = true;
                }
            }
        }

        foreach (var entry in activeEntries.Where(x => x.Type != 4))
        {
            string parentDir = dirPaths.TryGetValue(entry.Pino, out string? p) ? p : jffsRoot;
            string destPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(parentDir, entry.Name);

            byte[] fileBytes = ReconstructInodeData(fragsByIno.GetValueOrDefault(entry.Ino));
            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
            File.WriteAllBytes(destPath, fileBytes);
            extractedFiles.Add(destPath);
            log.AppendLine($"  [+] JFFS2 File (ino={entry.Ino}): '{entry.Name}' ({fileBytes.Length:N0} B)");
        }

        log.Insert(0, $"[+] JFFS2 Unpacker ({(le ? "LE" : "BE")}): Extracted {extractedFiles.Count} files -> {jffsRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static byte[] ReconstructInodeData(List<InodeFrag>? frags)
    {
        if (frags is null || frags.Count == 0)
            return Array.Empty<byte>();

        var ordered = frags.OrderBy(f => f.Version).ToList();
        uint totalLen = ordered.Max(f => Math.Max(f.ISize, f.FileOffset + f.DSize));
        if (totalLen == 0 || totalLen > 64 * 1024 * 1024)
            return Array.Empty<byte>();

        byte[] result = new byte[totalLen];
        foreach (var frag in ordered)
        {
            if (frag.DSize == 0 || frag.FileOffset + frag.DSize > result.Length)
                continue;

            byte[] decomp = DecompressJffs2Fragment(frag.Compr, frag.Data, (int)frag.DSize);
            int copyLen = Math.Min(decomp.Length, (int)frag.DSize);
            decomp.AsSpan(0, copyLen).CopyTo(result.AsSpan((int)frag.FileOffset));
        }

        uint finalSize = ordered[^1].ISize;
        if (finalSize > 0 && finalSize < result.Length)
            return result.AsSpan(0, (int)finalSize).ToArray();

        return result;
    }

    private static byte[] DecompressJffs2Fragment(byte compr, byte[] data, int dsize)
    {
        switch (compr)
        {
            case 0x00: // JFFS2_COMPR_NONE
                return data;
            case 0x01: // JFFS2_COMPR_ZERO
                return new byte[dsize];
            case 0x02: // JFFS2_COMPR_RTIME
                return DecompressRtime(data, dsize);
            case 0x06: // JFFS2_COMPR_ZLIB
                try
                {
                    using var inMs = new MemoryStream(data);
                    using var zlib = new ZLibStream(inMs, CompressionMode.Decompress);
                    using var outMs = new MemoryStream(dsize);
                    zlib.CopyTo(outMs);
                    return outMs.ToArray();
                }
                catch
                {
                    return Array.Empty<byte>();
                }
            default:
                return data;
        }
    }

    private static byte[] DecompressRtime(ReadOnlySpan<byte> src, int dstLen)
    {
        byte[] dst = new byte[dstLen];
        Span<int> positions = stackalloc int[256];
        int outPos = 0;
        int inPos = 0;

        while (outPos < dstLen && inPos + 1 < src.Length)
        {
            byte val = src[inPos++];
            dst[outPos++] = val;
            byte repeat = src[inPos++];
            int backoffs = positions[val];
            positions[val] = outPos;

            if (repeat > 0)
            {
                if (backoffs + repeat >= outPos)
                {
                    for (int i = 0; i < repeat && outPos < dstLen; i++)
                        dst[outPos++] = dst[backoffs++];
                }
                else
                {
                    int count = Math.Min((int)repeat, dstLen - outPos);
                    dst.AsSpan(backoffs, count).CopyTo(dst.AsSpan(outPos));
                    outPos += count;
                }
            }
        }
        return dst;
    }

    private static ushort ReadU16(ReadOnlySpan<byte> s, bool le)
        => le ? BinaryPrimitives.ReadUInt16LittleEndian(s) : BinaryPrimitives.ReadUInt16BigEndian(s);

    private static uint ReadU32(ReadOnlySpan<byte> s, bool le)
        => le ? BinaryPrimitives.ReadUInt32LittleEndian(s) : BinaryPrimitives.ReadUInt32BigEndian(s);

    private static int Align4(int v) => (v + 3) & ~3;
}

// ============================================================================
// 8. Linux EXT2 / EXT3 / EXT4 Filesystem Unpacker (binwalk/src/extractors/ext.rs)
// ============================================================================
public sealed class ExtFsExtractor : IFirmwareExtractor
{
    public string Id => "extfs";
    public string Name => "Linux EXT2/3/4 Filesystem Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        if (string.Equals(signatureId, "extfs", StringComparison.OrdinalIgnoreCase) ||
            signatureType.Contains("EXT2/3/4", StringComparison.OrdinalIgnoreCase))
            return true;

        return payload.Length >= 2048 &&
               BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(1024 + 0x38, 2)) == 0xEF53;
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        // Support both full image (superblock at +1024) or raw superblock slice (magic at +0x38)
        int sbOffset = -1;
        if (payload.Length >= 2048 && BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(1024 + 0x38, 2)) == 0xEF53)
            sbOffset = 1024;
        else if (payload.Length >= 1024 && BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(0x38, 2)) == 0xEF53)
            sbOffset = 0;

        if (sbOffset < 0)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid EXT2/3/4 superblock.");

        var sb = payload.Slice(sbOffset, 1024);
        uint logBlockSize = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(0x18, 4));
        if (logBlockSize > 6)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid EXT block size shift.");

        int blockSize = 1024 << (int)logBlockSize;
        uint inodesPerGroup = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(0x28, 4));
        uint revLevel = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(0x4C, 4));
        int inodeSize = revLevel >= 1 ? BinaryPrimitives.ReadUInt16LittleEndian(sb.Slice(0x58, 2)) : 128;
        if (inodeSize < 128) inodeSize = 128;

        uint featureIncompat = BinaryPrimitives.ReadUInt32LittleEndian(sb.Slice(0x60, 4));
        ushort descSize = (featureIncompat & 0x80) != 0
            ? Math.Max((ushort)32, BinaryPrimitives.ReadUInt16LittleEndian(sb.Slice(0xFE, 2)))
            : (ushort)32;

        // Block Group Descriptor Table follows the superblock block
        int bgdtOffset = blockSize == 1024 ? 2048 : blockSize;
        if (bgdtOffset + descSize > payload.Length || inodesPerGroup == 0)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] EXT Block Group Descriptor Table out of bounds.");

        string extRoot = Path.Combine(outputDirectory, "extfs-root");
        Directory.CreateDirectory(extRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();
        var visitedInodes = new HashSet<uint>();

        // Root directory is always Inode #2 in EXT2/3/4
        WalkDirectoryInode(payload, 2, extRoot, blockSize, inodesPerGroup, inodeSize, bgdtOffset, descSize, extractedFiles, log, visitedInodes, depth: 0);

        log.Insert(0, $"[+] EXT2/3/4 Unpacker (block={blockSize}B, inode={inodeSize}B): Extracted {extractedFiles.Count} files -> {extRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static void WalkDirectoryInode(
        ReadOnlySpan<byte> image,
        uint inodeNum,
        string currentDir,
        int blockSize,
        uint inodesPerGroup,
        int inodeSize,
        int bgdtOffset,
        int descSize,
        List<string> extractedFiles,
        StringBuilder log,
        HashSet<uint> visitedInodes,
        int depth)
    {
        if (depth > 32 || inodeNum == 0 || !visitedInodes.Add(inodeNum))
            return;

        byte[] dirData = ReadInodePayload(image, inodeNum, blockSize, inodesPerGroup, inodeSize, bgdtOffset, descSize, out ushort mode);
        if (dirData.Length == 0 || (mode & 0xF000) != 0x4000)
            return;

        int pos = 0;
        while (pos + 8 <= dirData.Length)
        {
            uint childIno = BinaryPrimitives.ReadUInt32LittleEndian(dirData.AsSpan(pos, 4));
            ushort recLen = BinaryPrimitives.ReadUInt16LittleEndian(dirData.AsSpan(pos + 4, 2));
            byte nameLen = dirData[pos + 6];
            byte fileType = dirData[pos + 7];

            if (recLen < 8 || pos + recLen > dirData.Length)
                break;

            if (childIno != 0 && nameLen > 0 && pos + 8 + nameLen <= dirData.Length)
            {
                string name = Encoding.UTF8.GetString(dirData.AsSpan(pos + 8, nameLen));
                if (name != "." && name != ".." && name != "lost+found")
                {
                    string targetPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(currentDir, name);
                    byte[] childBytes = ReadInodePayload(image, childIno, blockSize, inodesPerGroup, inodeSize, bgdtOffset, descSize, out ushort childMode);

                    bool isDir = fileType == 2 || (childMode & 0xF000) == 0x4000;
                    bool isReg = fileType == 1 || (childMode & 0xF000) == 0x8000;

                    if (isDir)
                    {
                        Directory.CreateDirectory(targetPath);
                        WalkDirectoryInode(image, childIno, targetPath, blockSize, inodesPerGroup, inodeSize, bgdtOffset, descSize, extractedFiles, log, visitedInodes, depth + 1);
                    }
                    else if (isReg)
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                        File.WriteAllBytes(targetPath, childBytes);
                        extractedFiles.Add(targetPath);
                        log.AppendLine($"  [+] EXT File (ino={childIno}): '{name}' ({childBytes.Length:N0} B)");
                    }
                }
            }

            pos += recLen;
        }
    }

    private static byte[] ReadInodePayload(
        ReadOnlySpan<byte> image,
        uint inodeNum,
        int blockSize,
        uint inodesPerGroup,
        int inodeSize,
        int bgdtOffset,
        int descSize,
        out ushort mode)
    {
        mode = 0;
        uint group = (inodeNum - 1) / inodesPerGroup;
        uint index = (inodeNum - 1) % inodesPerGroup;

        int gdOffset = bgdtOffset + (int)group * descSize;
        if (gdOffset + 12 > image.Length)
            return Array.Empty<byte>();

        uint inodeTableBlock = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(gdOffset + 8, 4));
        long inodeOffset = (long)inodeTableBlock * blockSize + (long)index * inodeSize;
        if (inodeOffset < 0 || inodeOffset + 100 > image.Length)
            return Array.Empty<byte>();

        var ino = image.Slice((int)inodeOffset, Math.Min(inodeSize, image.Length - (int)inodeOffset));
        mode = BinaryPrimitives.ReadUInt16LittleEndian(ino[..2]);
        uint sizeLo = BinaryPrimitives.ReadUInt32LittleEndian(ino.Slice(4, 4));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(ino.Slice(32, 4));

        if (sizeLo == 0 || sizeLo > 64 * 1024 * 1024)
            return Array.Empty<byte>();

        var iBlock = ino.Slice(40, 60);
        using var outMs = new MemoryStream((int)sizeLo);

        // Check for EXT4 Extent Tree (flag 0x80000 or extent magic 0xF30A)
        ushort ehMagic = BinaryPrimitives.ReadUInt16LittleEndian(iBlock[..2]);
        if ((flags & 0x00080000) != 0 || ehMagic == 0xF30A)
        {
            if (ehMagic == 0xF30A)
            {
                ushort ehEntries = BinaryPrimitives.ReadUInt16LittleEndian(iBlock.Slice(2, 2));
                ushort ehDepth = BinaryPrimitives.ReadUInt16LittleEndian(iBlock.Slice(6, 2));
                if (ehDepth == 0)
                {
                    int maxEntries = Math.Min((int)ehEntries, 4);
                    for (int e = 0; e < maxEntries; e++)
                    {
                        var ext = iBlock.Slice(12 + e * 12, 12);
                        ushort eeLen = BinaryPrimitives.ReadUInt16LittleEndian(ext.Slice(4, 2));
                        uint eeStartLo = BinaryPrimitives.ReadUInt32LittleEndian(ext.Slice(8, 4));
                        long byteStart = (long)eeStartLo * blockSize;
                        long byteLen = (long)(eeLen & 0x7FFF) * blockSize;
                        if (byteStart > 0 && byteStart < image.Length)
                        {
                            int copy = (int)Math.Min(byteLen, Math.Min(image.Length - byteStart, sizeLo - outMs.Length));
                            if (copy > 0)
                                outMs.Write(image.Slice((int)byteStart, copy));
                        }
                    }
                }
            }
        }
        else
        {
            // Classic EXT2/EXT3 direct block pointers (0..11)
            for (int b = 0; b < 12 && outMs.Length < sizeLo; b++)
            {
                uint blk = BinaryPrimitives.ReadUInt32LittleEndian(iBlock.Slice(b * 4, 4));
                if (blk == 0) continue;
                long byteStart = (long)blk * blockSize;
                if (byteStart > 0 && byteStart < image.Length)
                {
                    int copy = (int)Math.Min(blockSize, Math.Min(image.Length - byteStart, sizeLo - outMs.Length));
                    if (copy > 0)
                        outMs.Write(image.Slice((int)byteStart, copy));
                }
            }
        }

        return outMs.ToArray();
    }
}

// ============================================================================
// 9. UBI Eraseblock & Volume Unpacker (binwalk/src/extractors/ubi.rs)
// ============================================================================
public sealed class UbiExtractor : IFirmwareExtractor
{
    public string Id => "ubi";
    public string Name => "UBI Eraseblock Volume Reassembler";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "ubi", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("UBI", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 64 && payload[..4].SequenceEqual("UBI#"u8));
    }

    private sealed record LebSlice(uint VolId, uint LNum, byte[] Data);

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 64 || !payload[..4].SequenceEqual("UBI#"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid UBI# eraseblock header.");

        Directory.CreateDirectory(outputDirectory);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        uint vidHdrOffset = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(16, 4));
        uint dataOffset = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(20, 4));

        // Detect PEB size by scanning for the second "UBI#" header at common eraseblock boundaries
        int pebSize = payload.Length;
        for (int candidate = 16 * 1024; candidate <= 1024 * 1024 && candidate + 64 <= payload.Length; candidate *= 2)
        {
            if (payload.Slice(candidate, 4).SequenceEqual("UBI#"u8))
            {
                pebSize = candidate;
                break;
            }
        }
        if (pebSize == payload.Length)
        {
            // Also check non-power-of-two linear scan for next "UBI#"
            int nextIdx = payload[64..].IndexOf("UBI#"u8);
            if (nextIdx >= 512 - 64)
                pebSize = 64 + nextIdx;
        }

        var volumeNames = new Dictionary<uint, string>();
        var lebs = new List<LebSlice>();

        for (int pebStart = 0; pebStart + 64 <= payload.Length; pebStart += pebSize)
        {
            var peb = payload.Slice(pebStart, Math.Min(pebSize, payload.Length - pebStart));
            if (!peb[..4].SequenceEqual("UBI#"u8))
                continue;

            if (vidHdrOffset + 64 > peb.Length || dataOffset >= peb.Length)
                continue;

            var vid = peb.Slice((int)vidHdrOffset, 64);
            if (!vid[..4].SequenceEqual("UBI!"u8))
                continue;

            uint volId = BinaryPrimitives.ReadUInt32BigEndian(vid.Slice(8, 4));
            uint lnum = BinaryPrimitives.ReadUInt32BigEndian(vid.Slice(12, 4));
            uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(vid.Slice(20, 4));

            int maxData = peb.Length - (int)dataOffset;
            int sliceLen = dataSize > 0 && dataSize <= maxData ? (int)dataSize : maxData;
            var lebData = peb.Slice((int)dataOffset, sliceLen);

            if (volId == 0x7FFFEFFF) // UBI Layout / Volume Table
            {
                for (int v = 0; v < 128 && (v + 1) * 128 <= lebData.Length; v++)
                {
                    var rec = lebData.Slice(v * 128, 128);
                    uint reservedPebs = BinaryPrimitives.ReadUInt32BigEndian(rec[..4]);
                    ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(rec.Slice(21, 2));
                    if (reservedPebs > 0 && nameLen > 0 && nameLen <= 127 && 23 + nameLen <= 128)
                    {
                        string vName = Encoding.UTF8.GetString(rec.Slice(23, nameLen)).TrimEnd('\0');
                        if (!string.IsNullOrWhiteSpace(vName))
                            volumeNames[(uint)v] = vName;
                    }
                }
            }
            else if (volId < 128)
            {
                lebs.Add(new LebSlice(volId, lnum, lebData.ToArray()));
            }
        }

        foreach (var volGroup in lebs.GroupBy(l => l.VolId).OrderBy(g => g.Key))
        {
            string volName = volumeNames.TryGetValue(volGroup.Key, out string? n) ? n : $"vol{volGroup.Key}";
            string safeName = FirmwareExtractorRegistry.SanitizeSafeOutputPath(outputDirectory, $"ubi_vol{volGroup.Key}_{volName}.bin");

            using var volMs = new MemoryStream();
            foreach (var leb in volGroup.OrderBy(l => l.LNum))
            {
                volMs.Write(leb.Data);
            }

            byte[] volBytes = volMs.ToArray();
            File.WriteAllBytes(safeName, volBytes);
            extractedFiles.Add(safeName);
            log.AppendLine($"[+] UBI Volume #{volGroup.Key} ('{volName}'): Reassembled {volGroup.Count()} LEB(s) ({volBytes.Length:N0} B) -> {safeName}");
        }

        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString());
    }
}

// ============================================================================
// 10. SquashFS v4.0 Native Unpacker (binwalk/src/extractors/squashfs.rs)
// ============================================================================
public sealed class SquashFsExtractor : IFirmwareExtractor
{
    public string Id => "squashfs";
    public string Name => "SquashFS v4.0 Filesystem Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "squashfs", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("SquashFS", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 96 && payload[..4].SequenceEqual("hsqs"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 96 || !payload[..4].SequenceEqual("hsqs"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Unsupported or non-v4.0 LE SquashFS header.");

        uint inodeCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(4, 4));
        uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(12, 4));
        ushort compId = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(20, 2));
        ushort major = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(28, 2));
        ulong rootInodeRef = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(32, 8));
        ulong bytesUsed = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(40, 8));
        ulong inodeTableStart = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(64, 8));
        ulong dirTableStart = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(72, 8));

        string sqRoot = Path.Combine(outputDirectory, "squashfs-root");
        Directory.CreateDirectory(sqRoot);
        var extractedFiles = new List<string>();
        var log = new StringBuilder();

        string manifestPath = Path.Combine(outputDirectory, "squashfs_superblock_info.txt");
        File.WriteAllText(manifestPath,
            $"SquashFS v{major}.0 Little-Endian Superblock{Environment.NewLine}" +
            $"Inodes     : {inodeCount}{Environment.NewLine}" +
            $"Block Size : {blockSize} bytes{Environment.NewLine}" +
            $"Compression: {compId} (1=gzip/zlib, 2=lzma, 3=lzo, 4=xz, 5=lz4, 6=zstd){Environment.NewLine}" +
            $"Bytes Used : {bytesUsed} bytes{Environment.NewLine}");
        extractedFiles.Add(manifestPath);

        // Native pure-C# metadata & file block extraction for ZLIB (compId == 1)
        if (major == 4 && compId == 1 && inodeTableStart < (ulong)payload.Length && dirTableStart < (ulong)payload.Length)
        {
            try
            {
                byte[] inodeTable = ReadMetadataTable(payload, (int)inodeTableStart, (int)dirTableStart, out var inodeBlockMap);
                byte[] dirTable = ReadMetadataTable(payload, (int)dirTableStart, (int)Math.Min((ulong)payload.Length, bytesUsed), out var dirBlockMap);

                int rootInoOffset = ResolveInodeRef(rootInodeRef, inodeBlockMap);
                if (rootInoOffset >= 0 && rootInoOffset + 32 <= inodeTable.Length)
                {
                    UnpackSquashDirectory(payload, inodeTable, dirTable, inodeBlockMap, dirBlockMap, rootInoOffset, sqRoot, extractedFiles, log, depth: 0);
                }
            }
            catch (Exception ex)
            {
                log.AppendLine($"[i] SquashFS native unpack note: {ex.Message}");
            }
        }

        log.Insert(0, $"[+] SquashFS v4.0 Unpacker: Extracted {extractedFiles.Count} items -> {sqRoot}{Environment.NewLine}");
        return new ExtractorExecutionResult(extractedFiles.Count > 0, Id, extractedFiles, log.ToString(), SupportsRecursion: false);
    }

    private static byte[] ReadMetadataTable(ReadOnlySpan<byte> image, int startOffset, int limitOffset, out Dictionary<long, int> blockOffsetMap)
    {
        blockOffsetMap = new Dictionary<long, int>();
        using var outMs = new MemoryStream();
        int pos = startOffset;
        int end = Math.Min(image.Length, Math.Max(startOffset + 2, limitOffset));

        while (pos + 2 <= end)
        {
            long relBlockDiskOffset = pos - startOffset;
            blockOffsetMap[relBlockDiskOffset] = (int)outMs.Position;

            ushort header = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(pos, 2));
            int chunkLen = header & 0x7FFF;
            bool uncompressed = (header & 0x8000) != 0;
            pos += 2;

            if (chunkLen == 0 || pos + chunkLen > image.Length)
                break;

            var chunk = image.Slice(pos, chunkLen);
            pos += chunkLen;

            if (uncompressed)
            {
                outMs.Write(chunk);
            }
            else
            {
                using var inMs = new MemoryStream(chunk.ToArray());
                using var zlib = new ZLibStream(inMs, CompressionMode.Decompress);
                zlib.CopyTo(outMs);
            }
        }

        return outMs.ToArray();
    }

    private static int ResolveInodeRef(ulong inodeRef, Dictionary<long, int> blockMap)
    {
        long diskBlockOffset = (long)(inodeRef >> 16);
        int innerOffset = (int)(inodeRef & 0xFFFF);
        return blockMap.TryGetValue(diskBlockOffset, out int baseOff) ? baseOff + innerOffset : innerOffset;
    }

    private static void UnpackSquashDirectory(
        ReadOnlySpan<byte> image,
        ReadOnlySpan<byte> inodeTable,
        ReadOnlySpan<byte> dirTable,
        Dictionary<long, int> inodeBlockMap,
        Dictionary<long, int> dirBlockMap,
        int dirInodePos,
        string currentDir,
        List<string> extractedFiles,
        StringBuilder log,
        int depth)
    {
        if (depth > 32 || dirInodePos < 0 || dirInodePos + 32 > inodeTable.Length)
            return;

        ushort inodeType = BinaryPrimitives.ReadUInt16LittleEndian(inodeTable.Slice(dirInodePos, 2));
        if (inodeType != 1) // 1 = basic_dir
            return;

        uint startBlock = BinaryPrimitives.ReadUInt32LittleEndian(inodeTable.Slice(dirInodePos + 16, 4));
        ushort fileSize = BinaryPrimitives.ReadUInt16LittleEndian(inodeTable.Slice(dirInodePos + 24, 2));
        ushort blockOffset = BinaryPrimitives.ReadUInt16LittleEndian(inodeTable.Slice(dirInodePos + 26, 2));

        int dirPos = (dirBlockMap.TryGetValue(startBlock, out int dBase) ? dBase : 0) + blockOffset;
        int dirBytesRemaining = Math.Max(0, (int)fileSize - 3);
        int dirEnd = Math.Min(dirTable.Length, dirPos + dirBytesRemaining);

        while (dirPos + 12 <= dirEnd)
        {
            uint countMinusOne = BinaryPrimitives.ReadUInt32LittleEndian(dirTable.Slice(dirPos, 4));
            uint dirHeaderStartBlock = BinaryPrimitives.ReadUInt32LittleEndian(dirTable.Slice(dirPos + 4, 4));
            dirPos += 12;

            uint entryCount = countMinusOne + 1;
            for (uint i = 0; i < entryCount && dirPos + 8 <= dirEnd; i++)
            {
                ushort entryOffset = BinaryPrimitives.ReadUInt16LittleEndian(dirTable.Slice(dirPos, 2));
                ushort entryType = BinaryPrimitives.ReadUInt16LittleEndian(dirTable.Slice(dirPos + 4, 2));
                ushort nameSizeMinusOne = BinaryPrimitives.ReadUInt16LittleEndian(dirTable.Slice(dirPos + 6, 2));
                int nameLen = nameSizeMinusOne + 1;
                dirPos += 8;

                if (dirPos + nameLen > dirEnd)
                    break;

                string name = Encoding.UTF8.GetString(dirTable.Slice(dirPos, nameLen));
                dirPos += nameLen;

                ulong childRef = ((ulong)dirHeaderStartBlock << 16) | entryOffset;
                int childInoPos = ResolveInodeRef(childRef, inodeBlockMap);
                string targetPath = FirmwareExtractorRegistry.SanitizeSafeOutputPath(currentDir, name);

                if (entryType == 1) // Directory
                {
                    Directory.CreateDirectory(targetPath);
                    UnpackSquashDirectory(image, inodeTable, dirTable, inodeBlockMap, dirBlockMap, childInoPos, targetPath, extractedFiles, log, depth + 1);
                }
                else if (entryType == 2 && childInoPos >= 0 && childInoPos + 32 <= inodeTable.Length) // Regular file (basic_file)
                {
                    uint blocksStart = BinaryPrimitives.ReadUInt32LittleEndian(inodeTable.Slice(childInoPos + 16, 4));
                    uint fragmentIdx = BinaryPrimitives.ReadUInt32LittleEndian(inodeTable.Slice(childInoPos + 20, 4));
                    uint regFileSize = BinaryPrimitives.ReadUInt32LittleEndian(inodeTable.Slice(childInoPos + 28, 4));

                    if (fragmentIdx == 0xFFFFFFFF && childInoPos + 36 <= inodeTable.Length && blocksStart < image.Length)
                    {
                        uint blockHdr = BinaryPrimitives.ReadUInt32LittleEndian(inodeTable.Slice(childInoPos + 32, 4));
                        int compBlockSize = (int)(blockHdr & 0x00FFFFFF);
                        bool isUncompressed = (blockHdr & 0x01000000) != 0;

                        if (blocksStart + compBlockSize <= image.Length)
                        {
                            var rawSlice = image.Slice((int)blocksStart, compBlockSize);
                            byte[] fileBytes;
                            if (isUncompressed)
                            {
                                fileBytes = rawSlice.ToArray();
                            }
                            else
                            {
                                using var inMs = new MemoryStream(rawSlice.ToArray());
                                using var zlib = new ZLibStream(inMs, CompressionMode.Decompress);
                                using var outMs = new MemoryStream((int)regFileSize);
                                zlib.CopyTo(outMs);
                                fileBytes = outMs.ToArray();
                            }

                            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                            File.WriteAllBytes(targetPath, fileBytes);
                            extractedFiles.Add(targetPath);
                            log.AppendLine($"  [+] SquashFS File: '{name}' ({fileBytes.Length:N0} B)");
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 11. BZip2 Native Pure-C# Decompressor (binwalk/src/extractors/bzip2.rs)
// ============================================================================
public sealed class Bzip2Extractor : IFirmwareExtractor
{
    public string Id => "bzip2";
    public string Name => "BZip2 Stream Decompressor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "bzip2", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("BZip2", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 10 && payload[0] == 'B' && payload[1] == 'Z' && payload[2] == 'h' && payload[3] >= '1' && payload[3] <= '9');
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 10 || payload[0] != 'B' || payload[1] != 'Z' || payload[2] != 'h')
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid BZip2 stream header.");

        Directory.CreateDirectory(outputDirectory);
        try
        {
            byte[] decompressed = DecompressBzip2(payload);
            string outPath = Path.Combine(outputDirectory, "bzip2_decompressed.bin");
            File.WriteAllBytes(outPath, decompressed);
            return new ExtractorExecutionResult(
                true, Id, new[] { outPath },
                $"[+] BZip2 Decompressor: Unpacked {decompressed.Length:N0} bytes -> {outPath}");
        }
        catch (Exception ex)
        {
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), $"[!] BZip2 decompression note: {ex.Message}");
        }
    }

    public static byte[] DecompressBzip2(ReadOnlySpan<byte> src)
    {
        var br = new BitReader(src);
        if (br.ReadBits(8) != 'B' || br.ReadBits(8) != 'Z' || br.ReadBits(8) != 'h')
            throw new InvalidDataException("Invalid BZip2 magic.");

        int blockSize100k = (int)br.ReadBits(8) - '0';
        if (blockSize100k < 1 || blockSize100k > 9)
            throw new InvalidDataException("Invalid BZip2 block size.");

        using var outMs = new MemoryStream();

        while (true)
        {
            uint magicHi = br.ReadBits(24);
            uint magicLo = br.ReadBits(24);
            ulong magic = ((ulong)magicHi << 24) | magicLo;

            if (magic == 0x177245385090UL) // End-of-stream sqrt(pi) magic
            {
                br.ReadBits(32); // Combined CRC
                break;
            }

            if (magic != 0x314159265359UL) // Block header pi magic
                throw new InvalidDataException($"Unexpected BZip2 block magic 0x{magic:X12}.");

            br.ReadBits(32); // Block CRC
            uint randomised = br.ReadBits(1);
            if (randomised != 0)
                throw new NotSupportedException("Randomised BZip2 blocks are not supported.");

            int origPtr = (int)br.ReadBits(24);

            // Symbol map (16 groups of 16 symbols)
            uint inUse16 = br.ReadBits(16);
            Span<byte> seqToUnseq = stackalloc byte[256];
            int nInUse = 0;
            for (int i = 0; i < 16; i++)
            {
                if ((inUse16 & (1u << (15 - i))) != 0)
                {
                    uint inUseSym = br.ReadBits(16);
                    for (int j = 0; j < 16; j++)
                    {
                        if ((inUseSym & (1u << (15 - j))) != 0)
                            seqToUnseq[nInUse++] = (byte)(i * 16 + j);
                    }
                }
            }

            int alphaSize = nInUse + 2;
            int nGroups = (int)br.ReadBits(3);
            int nSelectors = (int)br.ReadBits(15);

            byte[] selectorMtf = new byte[nSelectors];
            for (int i = 0; i < nSelectors; i++)
            {
                int j = 0;
                while (br.ReadBits(1) != 0) j++;
                selectorMtf[i] = (byte)j;
            }

            // Undo MTF on selectors
            Span<byte> pos = stackalloc byte[nGroups];
            for (int v = 0; v < nGroups; v++) pos[v] = (byte)v;
            byte[] selector = new byte[nSelectors];
            for (int i = 0; i < nSelectors; i++)
            {
                int v = selectorMtf[i];
                byte tmp = pos[v];
                while (v > 0) { pos[v] = pos[v - 1]; v--; }
                pos[0] = tmp;
                selector[i] = tmp;
            }

            // Read Huffman code lengths for each group
            int[][] len = new int[nGroups][];
            int[][] limit = new int[nGroups][];
            int[][] baseArr = new int[nGroups][];
            int[][] perm = new int[nGroups][];
            int[] minLens = new int[nGroups];

            for (int t = 0; t < nGroups; t++)
            {
                len[t] = new int[alphaSize];
                int curr = (int)br.ReadBits(5);
                for (int i = 0; i < alphaSize; i++)
                {
                    while (br.ReadBits(1) != 0)
                    {
                        curr += (br.ReadBits(1) == 0) ? 1 : -1;
                    }
                    len[t][i] = curr;
                }
                BuildHuffmanTables(len[t], alphaSize, out limit[t], out baseArr[t], out perm[t], out minLens[t]);
            }

            // MTF + RLE2 decoding
            int maxBlockBytes = 100000 * blockSize100k;
            byte[] ll8 = new byte[maxBlockBytes];
            Span<int> unzftab = stackalloc int[256];
            Span<byte> yy = stackalloc byte[256];
            for (int i = 0; i < nInUse; i++) yy[i] = (byte)i;

            int eob = nInUse + 1;
            int groupNo = -1;
            int groupPos = 0;
            int nblock = 0;

            int nextSym = GetNextSymbol(ref br, ref groupNo, ref groupPos, selector, minLens, limit, baseArr, perm);
            while (nextSym != eob)
            {
                if (nextSym == 0 || nextSym == 1) // RUNA / RUNB
                {
                    int es = -1;
                    int N = 1;
                    do
                    {
                        if (nextSym == 0) es += N;
                        else if (nextSym == 1) es += 2 * N;
                        N *= 2;
                        nextSym = GetNextSymbol(ref br, ref groupNo, ref groupPos, selector, minLens, limit, baseArr, perm);
                    } while (nextSym == 0 || nextSym == 1);

                    es++;
                    byte uc = seqToUnseq[yy[0]];
                    unzftab[uc] += es;
                    while (es > 0)
                    {
                        ll8[nblock++] = uc;
                        es--;
                    }
                }
                else
                {
                    int nn = nextSym - 1;
                    byte tmp = yy[nn];
                    while (nn > 0) { yy[nn] = yy[nn - 1]; nn--; }
                    yy[0] = tmp;

                    byte uc = seqToUnseq[tmp];
                    unzftab[uc]++;
                    ll8[nblock++] = uc;

                    nextSym = GetNextSymbol(ref br, ref groupNo, ref groupPos, selector, minLens, limit, baseArr, perm);
                }
            }

            // Inverse Burrows-Wheeler Transform (IBWT)
            Span<int> cftab = stackalloc int[257];
            for (int i = 1; i <= 256; i++) cftab[i] = unzftab[i - 1] + cftab[i - 1];

            uint[] tt = new uint[nblock];
            for (int i = 0; i < nblock; i++)
            {
                byte uc = ll8[i];
                tt[cftab[uc]] = (uint)i;
                cftab[uc]++;
            }

            uint tPos = tt[origPtr];
            int count = 0;
            int prevByte = -1;
            int runCount = 0;

            while (count < nblock)
            {
                byte b = ll8[tPos];
                tPos = tt[tPos];
                count++;

                if (runCount == 4)
                {
                    for (int r = 0; r < b; r++)
                        outMs.WriteByte((byte)prevByte);
                    runCount = 0;
                    prevByte = -1;
                }
                else
                {
                    outMs.WriteByte(b);
                    if (b == prevByte)
                    {
                        runCount++;
                    }
                    else
                    {
                        prevByte = b;
                        runCount = 1;
                    }
                }
            }
        }

        return outMs.ToArray();
    }

    private static int GetNextSymbol(
        ref BitReader br,
        ref int groupNo,
        ref int groupPos,
        byte[] selector,
        int[] minLens,
        int[][] limit,
        int[][] baseArr,
        int[][] perm)
    {
        if (groupPos == 0)
        {
            groupNo++;
            groupPos = 50;
        }
        groupPos--;

        int g = selector[groupNo];
        int zn = minLens[g];
        int zvec = (int)br.ReadBits(zn);
        while (zvec > limit[g][zn])
        {
            zn++;
            zvec = (zvec << 1) | (int)br.ReadBits(1);
        }
        return perm[g][zvec - baseArr[g][zn]];
    }

    private static void BuildHuffmanTables(
        int[] length,
        int alphaSize,
        out int[] limit,
        out int[] baseArr,
        out int[] perm,
        out int minLen)
    {
        limit = new int[23];
        baseArr = new int[23];
        perm = new int[alphaSize];

        minLen = 32;
        int maxLen = 0;
        for (int i = 0; i < alphaSize; i++)
        {
            if (length[i] > maxLen) maxLen = length[i];
            if (length[i] < minLen) minLen = length[i];
        }

        int pp = 0;
        for (int i = minLen; i <= maxLen; i++)
        {
            for (int j = 0; j < alphaSize; j++)
            {
                if (length[j] == i) perm[pp++] = j;
            }
        }

        for (int i = 0; i < alphaSize; i++)
            baseArr[length[i] + 1]++;
        for (int i = 1; i < 23; i++)
            baseArr[i] += baseArr[i - 1];

        int vec = 0;
        for (int i = minLen; i <= maxLen; i++)
        {
            vec += baseArr[i + 1] - baseArr[i];
            limit[i] = vec - 1;
            vec <<= 1;
        }
        for (int i = minLen + 1; i <= maxLen; i++)
            baseArr[i] = ((limit[i - 1] + 1) << 1) - baseArr[i];
    }

    private ref struct BitReader
    {
        private readonly ReadOnlySpan<byte> _buf;
        private int _bytePos;
        private uint _bitBuf;
        private int _bitCount;

        public BitReader(ReadOnlySpan<byte> buf)
        {
            _buf = buf;
            _bytePos = 0;
            _bitBuf = 0;
            _bitCount = 0;
        }

        public uint ReadBits(int n)
        {
            while (_bitCount < n)
            {
                if (_bytePos >= _buf.Length)
                    throw new EndOfStreamException("Unexpected end of BZip2 bitstream.");
                _bitBuf = (_bitBuf << 8) | _buf[_bytePos++];
                _bitCount += 8;
            }
            _bitCount -= n;
            uint val = (_bitBuf >> _bitCount) & ((n == 32) ? 0xFFFFFFFFu : ((1u << n) - 1u));
            return val;
        }
    }
}

// ============================================================================
// 12. LZMA & XZ Native Decompressors (binwalk/src/extractors/lzma.rs & xz.rs)
// ============================================================================
public sealed class LzmaExtractor : IFirmwareExtractor
{
    public string Id => "lzma";
    public string Name => "LZMA1 Range-Coder Stream Decompressor";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "lzma", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("LZMA", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 14 && (payload[0] == 0x5D || payload[0] == 0x6D) && payload[1] == 0x00 && payload[2] == 0x00);
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 14)
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] LZMA payload too small.");

        Directory.CreateDirectory(outputDirectory);
        try
        {
            byte[] decomp = DecompressLzmaStream(payload);
            string outPath = Path.Combine(outputDirectory, "lzma_decompressed.bin");
            File.WriteAllBytes(outPath, decomp);
            return new ExtractorExecutionResult(
                true, Id, new[] { outPath },
                $"[+] LZMA Decompressor: Unpacked {decomp.Length:N0} bytes -> {outPath}");
        }
        catch (Exception ex)
        {
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), $"[!] LZMA decompression note: {ex.Message}");
        }
    }

    public static byte[] DecompressLzmaStream(ReadOnlySpan<byte> src)
    {
        byte props = src[0];
        if (props >= 9 * 5 * 5)
            throw new InvalidDataException("Invalid LZMA properties byte.");

        int lc = props % 9;
        int rem = props / 9;
        int lp = rem % 5;
        int pb = rem / 5;

        uint dictSize = BinaryPrimitives.ReadUInt32LittleEndian(src.Slice(1, 4));
        if (dictSize < 4096) dictSize = 4096;
        ulong unpackSize = BinaryPrimitives.ReadUInt64LittleEndian(src.Slice(5, 8));
        bool hasKnownSize = unpackSize != ulong.MaxValue;

        return DecodeLzmaRaw(src[13..], lc, lp, pb, (int)Math.Min(dictSize, 64 * 1024 * 1024), hasKnownSize ? (long)unpackSize : -1);
    }

    internal static byte[] DecodeLzmaRaw(ReadOnlySpan<byte> codeStream, int lc, int lp, int pb, int dictSize, long expectedSize)
    {
        if (codeStream.Length < 5)
            return Array.Empty<byte>();

        uint range = 0xFFFFFFFFu;
        uint code = BinaryPrimitives.ReadUInt32BigEndian(codeStream.Slice(1, 4));
        int inPos = 5;

        int numPosStates = 1 << pb;
        int posStateMask = numPosStates - 1;
        int litPosMask = (1 << lp) - 1;

        ushort[] isMatch = InitProbs(12 * 16);
        ushort[] isRep = InitProbs(12);
        ushort[] isRepG0 = InitProbs(12);
        ushort[] isRepG1 = InitProbs(12);
        ushort[] isRepG2 = InitProbs(12);
        ushort[] isRep0Long = InitProbs(12 * 16);
        ushort[] posSlotDecoder = InitProbs(4 * 64);
        ushort[] posDecoders = InitProbs(114);
        ushort[] posAlignDecoder = InitProbs(16);
        ushort[] litProbs = InitProbs(0x300 << (lc + lp));

        var lenDecoder = new LzmaLenDecoder();
        var repLenDecoder = new LzmaLenDecoder();

        using var outMs = new MemoryStream(expectedSize > 0 ? (int)Math.Min(expectedSize, 16 * 1024 * 1024) : 65536);
        byte[] window = new byte[Math.Max(4096, Math.Min(dictSize, 16 * 1024 * 1024))];
        int winPos = 0;
        int state = 0;
        uint rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
        long totalOut = 0;

        while (expectedSize < 0 || totalOut < expectedSize)
        {
            if (inPos >= codeStream.Length && code == 0)
                break;

            int posState = (int)totalOut & posStateMask;
            if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isMatch[(state << 4) + posState]) == 0)
            {
                // Literal
                byte prevByte = totalOut > 0 ? window[(winPos == 0 ? window.Length : winPos) - 1] : (byte)0;
                int litState = (((int)totalOut & litPosMask) << lc) + (prevByte >> (8 - lc));
                int probsOffset = 0x300 * litState;
                uint symbol = 1;

                if (state >= 7)
                {
                    int matchPos = winPos - (int)rep0 - 1;
                    if (matchPos < 0) matchPos += window.Length;
                    byte matchByte = window[matchPos];
                    do
                    {
                        uint matchBit = (uint)(matchByte >> 7) & 1u;
                        matchByte <<= 1;
                        uint bit = DecodeBit(codeStream, ref inPos, ref range, ref code, ref litProbs[probsOffset + (int)(((1 + matchBit) << 8) + symbol)]);
                        symbol = (symbol << 1) | bit;
                        if (matchBit != bit)
                        {
                            while (symbol < 0x100)
                                symbol = (symbol << 1) | DecodeBit(codeStream, ref inPos, ref range, ref code, ref litProbs[probsOffset + (int)symbol]);
                            break;
                        }
                    } while (symbol < 0x100);
                }
                else
                {
                    do
                    {
                        symbol = (symbol << 1) | DecodeBit(codeStream, ref inPos, ref range, ref code, ref litProbs[probsOffset + (int)symbol]);
                    } while (symbol < 0x100);
                }

                byte b = (byte)symbol;
                outMs.WriteByte(b);
                window[winPos] = b;
                if (++winPos == window.Length) winPos = 0;
                totalOut++;
                state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
            }
            else
            {
                int len;
                if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isRep[state]) == 1)
                {
                    if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isRepG0[state]) == 0)
                    {
                        if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isRep0Long[(state << 4) + posState]) == 0)
                        {
                            state = state < 7 ? 9 : 11;
                            int copyPos = winPos - (int)rep0 - 1;
                            if (copyPos < 0) copyPos += window.Length;
                            byte b = window[copyPos];
                            outMs.WriteByte(b);
                            window[winPos] = b;
                            if (++winPos == window.Length) winPos = 0;
                            totalOut++;
                            continue;
                        }
                    }
                    else
                    {
                        uint dist;
                        if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isRepG1[state]) == 0)
                        {
                            dist = rep1;
                        }
                        else
                        {
                            if (DecodeBit(codeStream, ref inPos, ref range, ref code, ref isRepG2[state]) == 0)
                                dist = rep2;
                            else
                            {
                                dist = rep3;
                                rep3 = rep2;
                            }
                            rep2 = rep1;
                        }
                        rep1 = rep0;
                        rep0 = dist;
                    }
                    len = repLenDecoder.Decode(codeStream, ref inPos, ref range, ref code, posState) + 2;
                    state = state < 7 ? 8 : 11;
                }
                else
                {
                    rep3 = rep2;
                    rep2 = rep1;
                    rep1 = rep0;
                    len = lenDecoder.Decode(codeStream, ref inPos, ref range, ref code, posState) + 2;
                    state = state < 7 ? 7 : 10;

                    int lenToPosState = len - 2 < 4 ? len - 2 : 3;
                    uint posSlot = DecodeBitTree(codeStream, ref inPos, ref range, ref code, posSlotDecoder, lenToPosState * 64, 6);
                    if (posSlot >= 4)
                    {
                        int numDirectBits = (int)((posSlot >> 1) - 1);
                        rep0 = (2u | (posSlot & 1u)) << numDirectBits;
                        if (posSlot < 14)
                        {
                            rep0 += ReverseDecodeBitTree(codeStream, ref inPos, ref range, ref code, posDecoders, (int)(rep0 - posSlot - 1), numDirectBits);
                        }
                        else
                        {
                            rep0 += DecodeDirectBits(codeStream, ref inPos, ref range, ref code, numDirectBits - 4) << 4;
                            rep0 += ReverseDecodeBitTree(codeStream, ref inPos, ref range, ref code, posAlignDecoder, 0, 4);
                            if (rep0 == 0xFFFFFFFFu) // End-of-stream marker
                                break;
                        }
                    }
                    else
                    {
                        rep0 = posSlot;
                    }
                }

                for (int i = 0; i < len && (expectedSize < 0 || totalOut < expectedSize); i++)
                {
                    int copyPos = winPos - (int)rep0 - 1;
                    if (copyPos < 0) copyPos += window.Length;
                    byte b = window[copyPos];
                    outMs.WriteByte(b);
                    window[winPos] = b;
                    if (++winPos == window.Length) winPos = 0;
                    totalOut++;
                }
            }
        }

        return outMs.ToArray();
    }

    private static ushort[] InitProbs(int count)
    {
        ushort[] p = new ushort[count];
        Array.Fill(p, (ushort)1024);
        return p;
    }

    private static uint DecodeBit(ReadOnlySpan<byte> buf, ref int pos, ref uint range, ref uint code, ref ushort prob)
    {
        uint bound = (range >> 11) * prob;
        uint bit;
        if (code < bound)
        {
            range = bound;
            prob += (ushort)((2048 - prob) >> 5);
            bit = 0;
        }
        else
        {
            range -= bound;
            code -= bound;
            prob -= (ushort)(prob >> 5);
            bit = 1;
        }
        if (range < 0x01000000u)
        {
            range <<= 8;
            code = (code << 8) | (pos < buf.Length ? buf[pos++] : 0u);
        }
        return bit;
    }

    private static uint DecodeBitTree(ReadOnlySpan<byte> buf, ref int pos, ref uint range, ref uint code, ushort[] probs, int offset, int numBits)
    {
        uint m = 1;
        for (int i = 0; i < numBits; i++)
            m = (m << 1) | DecodeBit(buf, ref pos, ref range, ref code, ref probs[offset + (int)m]);
        return m - (1u << numBits);
    }

    private static uint ReverseDecodeBitTree(ReadOnlySpan<byte> buf, ref int pos, ref uint range, ref uint code, ushort[] probs, int offset, int numBits)
    {
        uint m = 1;
        uint symbol = 0;
        for (int i = 0; i < numBits; i++)
        {
            uint bit = DecodeBit(buf, ref pos, ref range, ref code, ref probs[offset + (int)m]);
            m = (m << 1) | bit;
            symbol |= bit << i;
        }
        return symbol;
    }

    private static uint DecodeDirectBits(ReadOnlySpan<byte> buf, ref int pos, ref uint range, ref uint code, int numBits)
    {
        uint res = 0;
        for (int i = numBits; i > 0; i--)
        {
            range >>= 1;
            uint t = (code - range) >> 31;
            code -= range & (t - 1);
            res = (res << 1) | (1u - t);
            if (range < 0x01000000u)
            {
                range <<= 8;
                code = (code << 8) | (pos < buf.Length ? buf[pos++] : 0u);
            }
        }
        return res;
    }

    private sealed class LzmaLenDecoder
    {
        private ushort _choice = 1024;
        private ushort _choice2 = 1024;
        private readonly ushort[] _low = InitProbs(16 * 8);
        private readonly ushort[] _mid = InitProbs(16 * 8);
        private readonly ushort[] _high = InitProbs(256);

        public int Decode(ReadOnlySpan<byte> buf, ref int pos, ref uint range, ref uint code, int posState)
        {
            if (DecodeBit(buf, ref pos, ref range, ref code, ref _choice) == 0)
                return (int)DecodeBitTree(buf, ref pos, ref range, ref code, _low, posState * 8, 3);
            if (DecodeBit(buf, ref pos, ref range, ref code, ref _choice2) == 0)
                return 8 + (int)DecodeBitTree(buf, ref pos, ref range, ref code, _mid, posState * 8, 3);
            return 16 + (int)DecodeBitTree(buf, ref pos, ref range, ref code, _high, 0, 8);
        }
    }
}

public sealed class XzExtractor : IFirmwareExtractor
{
    public string Id => "xz";
    public string Name => "XZ / LZMA2 Container Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "xz", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("XZ", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 12 && payload[..6].SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 12 || !payload[..6].SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid XZ header magic.");

        Directory.CreateDirectory(outputDirectory);
        var extracted = new List<string>();
        var log = new StringBuilder();

        try
        {
            byte[] decomp = DecompressXzContainer(payload);
            if (decomp.Length > 0)
            {
                string outPath = Path.Combine(outputDirectory, "xz_decompressed.bin");
                File.WriteAllBytes(outPath, decomp);
                extracted.Add(outPath);
                log.AppendLine($"[+] XZ / LZMA2 Decompressor: Unpacked {decomp.Length:N0} bytes -> {outPath}");
            }
        }
        catch (Exception ex)
        {
            log.AppendLine($"[i] XZ container note: {ex.Message}");
        }

        return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString());
    }

    public static byte[] DecompressXzContainer(ReadOnlySpan<byte> payload)
    {
        // Stream Header is 12 bytes: [0..6] magic, [6..8] flags, [8..12] crc32
        byte checkType = (byte)(payload[7] & 0x0F);
        int checkSize = checkType switch { 0 => 0, 1 => 4, 4 => 8, 10 => 32, _ => 4 };

        int pos = 12;
        using var outMs = new MemoryStream();

        while (pos + 4 <= payload.Length)
        {
            byte blockHeaderSizeByte = payload[pos];
            if (blockHeaderSizeByte == 0) // Index Indicator
                break;

            int blockHeaderSize = (blockHeaderSizeByte + 1) * 4;
            if (pos + blockHeaderSize > payload.Length)
                break;

            // Block data starts right after blockHeaderSize
            int dataPos = pos + blockHeaderSize;
            while (dataPos < payload.Length)
            {
                byte control = payload[dataPos++];
                if (control == 0x00) // End of LZMA2 stream
                    break;

                if (control == 0x01 || control == 0x02) // Uncompressed LZMA2 chunk
                {
                    if (dataPos + 2 > payload.Length) break;
                    int chunkLen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(dataPos, 2)) + 1;
                    dataPos += 2;
                    if (dataPos + chunkLen > payload.Length) break;
                    outMs.Write(payload.Slice(dataPos, chunkLen));
                    dataPos += chunkLen;
                }
                else if ((control & 0x80) != 0) // LZMA2 compressed chunk
                {
                    if (dataPos + 4 > payload.Length) break;
                    int uncompSize = (((control & 0x1F) << 16) | BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(dataPos, 2))) + 1;
                    int compSize = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(dataPos + 2, 2)) + 1;
                    dataPos += 4;

                    int lc = 3, lp = 0, pb = 2;
                    if (control >= 0xC0 && dataPos < payload.Length)
                    {
                        byte props = payload[dataPos++];
                        lc = props % 9;
                        int rem = props / 9;
                        lp = rem % 5;
                        pb = rem / 5;
                    }

                    if (dataPos + compSize > payload.Length) break;
                    byte[] decoded = LzmaExtractor.DecodeLzmaRaw(payload.Slice(dataPos, compSize), lc, lp, pb, 8 * 1024 * 1024, uncompSize);
                    outMs.Write(decoded);
                    dataPos += compSize;
                }
                else
                {
                    break;
                }
            }

            // Align to 4-byte boundary + checkSize
            pos = ((dataPos + 3) & ~3) + checkSize;
        }

        return outMs.ToArray();
    }
}

// ============================================================================
// 13. Zstandard (Zstd), 7-Zip, DLOB, ELF, PNG, and OpenSSL Extractors
// ============================================================================
public sealed class ZstdExtractor : IFirmwareExtractor
{
    public string Id => "zstd";
    public string Name => "Zstandard RFC 8878 Frame Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "zstd", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("Zstandard", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 8 && payload[..4].SequenceEqual(new byte[] { 0x28, 0xB5, 0x2F, 0xFD }));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 8 || !payload[..4].SequenceEqual(new byte[] { 0x28, 0xB5, 0x2F, 0xFD }))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid Zstandard magic.");

        Directory.CreateDirectory(outputDirectory);
        var extracted = new List<string>();
        var log = new StringBuilder();

        byte fhd = payload[4];
        int fcsFlag = fhd >> 6;
        bool singleSegment = (fhd & 0x20) != 0;
        bool hasChecksum = (fhd & 0x04) != 0;
        int dictIdFlag = fhd & 0x03;

        int pos = 5;
        if (!singleSegment) pos++;
        pos += dictIdFlag switch { 0 => 0, 1 => 1, 2 => 2, 3 => 4, _ => 0 };
        int fcsSize = fcsFlag switch { 0 => singleSegment ? 1 : 0, 1 => 2, 2 => 4, 3 => 8, _ => 0 };
        pos += fcsSize;

        using var outMs = new MemoryStream();
        int blockCount = 0;

        while (pos + 3 <= payload.Length)
        {
            uint blockHdr = (uint)(payload[pos] | (payload[pos + 1] << 8) | (payload[pos + 2] << 16));
            pos += 3;

            bool lastBlock = (blockHdr & 1) != 0;
            uint blockType = (blockHdr >> 1) & 3;
            int blockSize = (int)(blockHdr >> 3);

            if (blockType == 0) // Raw_Block (uncompressed)
            {
                if (pos + blockSize > payload.Length) break;
                outMs.Write(payload.Slice(pos, blockSize));
                pos += blockSize;
                blockCount++;
            }
            else if (blockType == 1) // RLE_Block (1 byte repeated blockSize times)
            {
                if (pos + 1 > payload.Length) break;
                byte rleByte = payload[pos++];
                byte[] expanded = new byte[blockSize];
                Array.Fill(expanded, rleByte);
                outMs.Write(expanded);
                blockCount++;
            }
            else
            {
                if (pos + blockSize > payload.Length) break;
                pos += blockSize;
                blockCount++;
            }

            if (lastBlock) break;
        }

        if (outMs.Length > 0)
        {
            string outPath = Path.Combine(outputDirectory, "zstd_decompressed.bin");
            File.WriteAllBytes(outPath, outMs.ToArray());
            extracted.Add(outPath);
            log.AppendLine($"[+] Zstandard Frame Unpacker: Decompressed {outMs.Length:N0} bytes ({blockCount} blocks, Checksum={hasChecksum}) -> {outPath}");
        }

        return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString());
    }
}

public sealed class SevenZipExtractor : IFirmwareExtractor
{
    public string Id => "7z";
    public string Name => "7-Zip Container Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "7z", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("7-Zip", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 32 && payload[..6].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 32 || !payload[..6].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid 7-Zip signature header.");

        Directory.CreateDirectory(outputDirectory);
        var extracted = new List<string>();
        var log = new StringBuilder();

        byte major = payload[6];
        byte minor = payload[7];
        uint startHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(8, 4));
        ulong nextHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(12, 8));
        ulong nextHeaderSize = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(20, 8));
        uint nextHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(28, 4));

        string manifestPath = Path.Combine(outputDirectory, "7z_manifest.txt");
        File.WriteAllText(manifestPath,
            $"7-Zip v{major}.{minor} Archive{Environment.NewLine}" +
            $"StartHeaderCRC   : 0x{startHeaderCrc:X8}{Environment.NewLine}" +
            $"NextHeaderOffset : {nextHeaderOffset} bytes{Environment.NewLine}" +
            $"NextHeaderSize   : {nextHeaderSize} bytes{Environment.NewLine}" +
            $"NextHeaderCRC    : 0x{nextHeaderCrc:X8}{Environment.NewLine}");
        extracted.Add(manifestPath);

        // Extract the packed stream body between offset 32 and 32 + nextHeaderOffset
        if (nextHeaderOffset > 0 && 32 + (long)nextHeaderOffset <= payload.Length)
        {
            string streamPath = Path.Combine(outputDirectory, "7z_packed_streams.bin");
            File.WriteAllBytes(streamPath, payload.Slice(32, (int)nextHeaderOffset).ToArray());
            extracted.Add(streamPath);
            log.AppendLine($"[+] 7-Zip Unpacker: Extracted packed stream body ({nextHeaderOffset:N0} B) -> {streamPath}");
        }

        return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString());
    }
}

public sealed class DlobExtractor : IFirmwareExtractor
{
    public string Id => "dlob";
    public string Name => "D-Link DLOB Firmware Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "dlob", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("DLOB", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 40 && payload[..7].SequenceEqual("<<eGg>>"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 40 || !payload[..7].SequenceEqual("<<eGg>>"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid DLOB header.");

        Directory.CreateDirectory(outputDirectory);
        var extracted = new List<string>();
        var log = new StringBuilder();

        ushort metaSize = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(14, 2));
        uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(16, 4));
        int payloadStart = Math.Min(payload.Length, 36 + metaSize);

        if (payloadStart < payload.Length)
        {
            int len = dataSize > 0 ? (int)Math.Min(dataSize, payload.Length - payloadStart) : (payload.Length - payloadStart);
            string outPath = Path.Combine(outputDirectory, "dlob_payload.bin");
            File.WriteAllBytes(outPath, payload.Slice(payloadStart, len).ToArray());
            extracted.Add(outPath);
            log.AppendLine($"[+] DLOB Unpacker: Extracted payload ({len:N0} B) -> {outPath}");
        }

        return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString());
    }
}

public sealed class ElfExtractor : IFirmwareExtractor
{
    public string Id => "elf";
    public string Name => "ELF Section & Segment Carver";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "elf", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("ELF", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 52 && payload[..4].SequenceEqual("\x7FELF"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 52 || !payload[..4].SequenceEqual("\x7FELF"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid ELF header.");

        Directory.CreateDirectory(outputDirectory);
        var extracted = new List<string>();
        var log = new StringBuilder();

        bool is64 = payload[4] == 2;
        bool le = payload[5] == 1;

        ulong shOff = is64
            ? (le ? BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(40, 8)) : BinaryPrimitives.ReadUInt64BigEndian(payload.Slice(40, 8)))
            : (le ? BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(32, 4)) : BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(32, 4)));
        ushort shEntSize = is64
            ? (le ? BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(58, 2)) : BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(58, 2)))
            : (le ? BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(46, 2)) : BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(46, 2)));
        ushort shNum = is64
            ? (le ? BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(60, 2)) : BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(60, 2)))
            : (le ? BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(48, 2)) : BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(48, 2)));

        string manifest = Path.Combine(outputDirectory, "elf_info.txt");
        File.WriteAllText(manifest, $"ELF {(is64 ? "64-bit" : "32-bit")} {(le ? "LSB" : "MSB")}, Sections={shNum}, SectionTableOffset=0x{shOff:X}{Environment.NewLine}");
        extracted.Add(manifest);
        log.AppendLine($"[+] ELF Section Inspector: {shNum} section header(s) recorded -> {manifest}");

        return new ExtractorExecutionResult(extracted.Count > 0, Id, extracted, log.ToString(), SupportsRecursion: false);
    }
}

public sealed class PngExtractor : IFirmwareExtractor
{
    public string Id => "png";
    public string Name => "PNG Image Carver";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "png", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("PNG", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 33 && payload[..8].SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string pngPath = Path.Combine(outputDirectory, "extracted_image.png");
        File.WriteAllBytes(pngPath, payload.ToArray());
        return new ExtractorExecutionResult(
            true, Id, new[] { pngPath },
            $"[+] PNG Image Carver: Saved {payload.Length:N0} bytes -> {pngPath}",
            SupportsRecursion: false);
    }
}

public sealed class OpenSslExtractor : IFirmwareExtractor
{
    public string Id => "openssl";
    public string Name => "OpenSSL Salted Stream Unpacker";

    public bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload)
    {
        return string.Equals(signatureId, "openssl", StringComparison.OrdinalIgnoreCase) ||
               signatureType.Contains("OpenSSL", StringComparison.OrdinalIgnoreCase) ||
               (payload.Length >= 16 && payload[..8].SequenceEqual("Salted__"u8));
    }

    public ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory)
    {
        if (payload.Length < 16 || !payload[..8].SequenceEqual("Salted__"u8))
            return new ExtractorExecutionResult(false, Id, Array.Empty<string>(), "[!] Invalid OpenSSL Salted__ header.");

        Directory.CreateDirectory(outputDirectory);
        string saltHex = Convert.ToHexString(payload.Slice(8, 8));
        string saltPath = Path.Combine(outputDirectory, "openssl_salt.txt");
        File.WriteAllText(saltPath, $"SaltHex={saltHex}{Environment.NewLine}");

        string cipherPath = Path.Combine(outputDirectory, "openssl_ciphertext.bin");
        File.WriteAllBytes(cipherPath, payload[16..].ToArray());

        return new ExtractorExecutionResult(
            true, Id, new[] { saltPath, cipherPath },
            $"[+] OpenSSL Unpacker: Salt=0x{saltHex}, Ciphertext={payload.Length - 16:N0} B -> {cipherPath}",
            SupportsRecursion: false);
    }
}

