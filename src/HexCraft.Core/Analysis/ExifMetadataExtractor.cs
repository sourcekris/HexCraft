using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using HexCraft.Core.Buffers;

namespace HexCraft.Core.Analysis;

public sealed record MetadataTagEntry(
    string Group,
    string TagName,
    string Value,
    long? SourceOffset = null,
    int? SourceLength = null);

/// <summary>
/// Extracts Exif, TIFF IFD, PNG (tEXt/iTXt/eXIf/pHYs/tIME), PDF, PE/ELF/SquashFS/Archive
/// metadata tags (ExifTool-style inspection) in-memory with zero unsafe code, and optionally
/// merges output from external `exiftool` if installed on Windows 11, WSL2, or Linux.
/// </summary>
public static class ExifMetadataExtractor
{
    private static readonly Dictionary<ushort, string> TiffTagNames = new()
    {
        [0x0100] = "ImageWidth",
        [0x0101] = "ImageHeight",
        [0x0102] = "BitsPerSample",
        [0x0103] = "Compression",
        [0x0106] = "PhotometricInterpretation",
        [0x010E] = "ImageDescription",
        [0x010F] = "Make",
        [0x0110] = "Model",
        [0x0112] = "Orientation",
        [0x011A] = "XResolution",
        [0x011B] = "YResolution",
        [0x0128] = "ResolutionUnit",
        [0x0131] = "Software",
        [0x0132] = "ModifyDate",
        [0x013B] = "Artist",
        [0x8298] = "Copyright",
        [0x8769] = "ExifOffset",
        [0x8825] = "GPSInfo",
        [0x829A] = "ExposureTime",
        [0x829D] = "FNumber",
        [0x8827] = "ISO",
        [0x9000] = "ExifVersion",
        [0x9003] = "DateTimeOriginal",
        [0x9004] = "CreateDate",
        [0x920A] = "FocalLength",
        [0x9286] = "UserComment",
        [0xA001] = "ColorSpace",
        [0xA002] = "ExifImageWidth",
        [0xA003] = "ExifImageHeight",
        [0xA420] = "ImageUniqueID",
        [0xA430] = "OwnerName",
        [0xA431] = "SerialNumber",
        [0xA432] = "LensInfo",
        [0xA433] = "LensMake",
        [0xA434] = "LensModel"
    };

    private static readonly Dictionary<ushort, string> GpsTagNames = new()
    {
        [0x0000] = "GPSVersionID",
        [0x0001] = "GPSLatitudeRef",
        [0x0002] = "GPSLatitude",
        [0x0003] = "GPSLongitudeRef",
        [0x0004] = "GPSLongitude",
        [0x0005] = "GPSAltitudeRef",
        [0x0006] = "GPSAltitude",
        [0x001D] = "GPSDateStamp"
    };

    public static IReadOnlyList<MetadataTagEntry> Extract(BinaryDocument doc, bool tryExternalExifTool = false)
    {
        var tags = new List<MetadataTagEntry>();
        if (doc.Length == 0)
            return tags;

        int maxInspect = (int)Math.Min(doc.Length, 4 * 1024 * 1024);
        byte[] data = doc.ReadBytes(0, maxInspect);
        ReadOnlySpan<byte> span = data;

        // 1. PNG chunks (IHDR, tEXt, iTXt, pHYs, tIME, eXIf)
        if (span.Length >= 8 && span[..8].SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }))
        {
            ExtractPngMetadata(span, tags);
        }

        // 2. JPEG markers (SOF0/SOF2, APP0 JFIF, APP1 Exif/XMP, COM)
        if (span.Length >= 4 && span[0] == 0xFF && span[1] == 0xD8 && span[2] == 0xFF)
        {
            ExtractJpegMetadata(span, tags);
        }

        // 3. Raw TIFF (II*\0 or MM\0*)
        if (span.Length >= 8 &&
            ((span[0] == 'I' && span[1] == 'I' && span[2] == 0x2A && span[3] == 0x00) ||
             (span[0] == 'M' && span[1] == 'M' && span[2] == 0x00 && span[3] == 0x2A)))
        {
            ParseTiffHeader(span, 0, tags);
        }

        // 4. Scan for embedded "Exif\0\0" blocks anywhere in the first 512 KB (common in firmware/media blobs)
        ScanEmbeddedExifBlocks(span, tags);

        // 5. PDF Document Info (/Author, /Producer, /Creator, /Title, /CreationDate)
        if (span.Length >= 5 && span[..5].SequenceEqual("%PDF-"u8))
        {
            ExtractPdfMetadata(span, tags);
        }

        // 6. PE / ELF / SquashFS / U-Boot / GZip ExifTool-style structural tags
        ExtractBinaryFormatTags(span, tags);

        // 7. Optional external ExifTool CLI integration
        if (tryExternalExifTool && !string.IsNullOrEmpty(doc.FilePath) && File.Exists(doc.FilePath))
        {
            TryMergeExternalExifTool(doc.FilePath, tags);
        }

        return tags;
    }

    private static void ExtractPngMetadata(ReadOnlySpan<byte> span, List<MetadataTagEntry> tags)
    {
        int pos = 8;
        while (pos + 12 <= span.Length)
        {
            uint len = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(pos, 4));
            string type = Encoding.ASCII.GetString(span.Slice(pos + 4, 4));
            int dataOffset = pos + 8;

            if (len > (uint)(span.Length - dataOffset - 4))
                break;

            ReadOnlySpan<byte> payload = span.Slice(dataOffset, (int)len);

            switch (type)
            {
                case "IHDR" when payload.Length >= 13:
                {
                    uint width = BinaryPrimitives.ReadUInt32BigEndian(payload[..4]);
                    uint height = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(4, 4));
                    byte bitDepth = payload[8];
                    byte colorType = payload[9];
                    byte interlace = payload[12];

                    string colorDesc = colorType switch
                    {
                        0 => "Grayscale",
                        2 => "RGB",
                        3 => "Palette",
                        4 => "Grayscale with Alpha",
                        6 => "RGB with Alpha",
                        _ => $"Type {colorType}"
                    };

                    tags.Add(new MetadataTagEntry("PNG", "ImageSize", $"{width}x{height}", dataOffset, 8));
                    tags.Add(new MetadataTagEntry("PNG", "BitDepth", bitDepth.ToString(), dataOffset + 8, 1));
                    tags.Add(new MetadataTagEntry("PNG", "ColorType", colorDesc, dataOffset + 9, 1));
                    tags.Add(new MetadataTagEntry("PNG", "Interlace", interlace == 0 ? "Noninterlaced" : "Adam7 Interlace", dataOffset + 12, 1));
                    break;
                }

                case "tEXt":
                {
                    int nul = payload.IndexOf((byte)0);
                    if (nul > 0 && nul < payload.Length)
                    {
                        string key = Encoding.Latin1.GetString(payload[..nul]);
                        string val = Encoding.UTF8.GetString(payload[(nul + 1)..]);
                        tags.Add(new MetadataTagEntry("PNG:tEXt", key, val, dataOffset, (int)len));
                    }
                    break;
                }

                case "iTXt":
                {
                    int nul = payload.IndexOf((byte)0);
                    if (nul > 0 && nul + 5 <= payload.Length)
                    {
                        string key = Encoding.UTF8.GetString(payload[..nul]);
                        string text = ExtractPrintableText(payload[(nul + 1)..]);
                        tags.Add(new MetadataTagEntry("PNG:iTXt", key, text, dataOffset, (int)len));
                    }
                    break;
                }

                case "pHYs" when payload.Length >= 9:
                {
                    uint ppuX = BinaryPrimitives.ReadUInt32BigEndian(payload[..4]);
                    uint ppuY = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(4, 4));
                    byte unit = payload[8];
                    tags.Add(new MetadataTagEntry("PNG", "PixelsPerUnit", $"{ppuX}x{ppuY} ({(unit == 1 ? "meters" : "unknown")})", dataOffset, 9));
                    break;
                }

                case "tIME" when payload.Length >= 7:
                {
                    ushort year = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                    tags.Add(new MetadataTagEntry("PNG", "ModifyDate",
                        $"{year:D4}:{payload[2]:D2}:{payload[3]:D2} {payload[4]:D2}:{payload[5]:D2}:{payload[6]:D2}", dataOffset, 7));
                    break;
                }

                case "eXIf" when payload.Length >= 8:
                {
                    ParseTiffHeader(payload, dataOffset, tags);
                    break;
                }
            }

            pos += 12 + (int)len;
            if (type == "IEND")
                break;
        }
    }

    private static void ExtractJpegMetadata(ReadOnlySpan<byte> span, List<MetadataTagEntry> tags)
    {
        int pos = 2;
        while (pos + 4 <= span.Length && span[pos] == 0xFF)
        {
            byte marker = span[pos + 1];
            if (marker == 0xDA || marker == 0xD9) // SOS or EOI
                break;

            ushort segLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos + 2, 2));
            if (segLen < 2 || pos + 2 + segLen > span.Length)
                break;

            int payloadStart = pos + 4;
            int payloadLen = segLen - 2;
            ReadOnlySpan<byte> payload = span.Slice(payloadStart, payloadLen);

            if (marker == 0xE0 && payload.Length >= 12 && payload[..5].SequenceEqual("JFIF\0"u8))
            {
                tags.Add(new MetadataTagEntry("JFIF", "JFIFVersion", $"{payload[5]}.{payload[6]:D2}", payloadStart + 5, 2));
                ushort xDensity = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2));
                ushort yDensity = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(10, 2));
                tags.Add(new MetadataTagEntry("JFIF", "Resolution", $"{xDensity}x{yDensity}", payloadStart + 8, 4));
            }
            else if (marker == 0xE1 && payload.Length >= 14 && payload[..6].SequenceEqual("Exif\0\0"u8))
            {
                ParseTiffHeader(payload[6..], payloadStart + 6, tags);
            }
            else if ((marker == 0xC0 || marker == 0xC2) && payload.Length >= 6)
            {
                byte precision = payload[0];
                ushort height = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1, 2));
                ushort width = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
                byte components = payload[5];
                tags.Add(new MetadataTagEntry("JPEG", "ImageSize", $"{width}x{height}", payloadStart + 1, 4));
                tags.Add(new MetadataTagEntry("JPEG", "EncodingProcess", marker == 0xC0 ? "Baseline DCT" : "Progressive DCT", pos, 4));
                tags.Add(new MetadataTagEntry("JPEG", "ColorComponents", $"{components} ({precision}-bit)", payloadStart, 6));
            }
            else if (marker == 0xFE && payload.Length > 0)
            {
                tags.Add(new MetadataTagEntry("JPEG", "Comment", Encoding.UTF8.GetString(payload).TrimEnd('\0'), payloadStart, payloadLen));
            }

            pos += 2 + segLen;
        }
    }

    private static void ScanEmbeddedExifBlocks(ReadOnlySpan<byte> span, List<MetadataTagEntry> tags)
    {
        int limit = Math.Min(span.Length, 512 * 1024);
        ReadOnlySpan<byte> searchWindow = span[..limit];
        ReadOnlySpan<byte> exifSig = "Exif\0\0"u8;

        int pos = 0;
        while (pos <= searchWindow.Length - 14)
        {
            int idx = searchWindow[pos..].IndexOf(exifSig);
            if (idx < 0) break;

            int matchOffset = pos + idx;
            int tiffStart = matchOffset + 6;
            // Avoid duplicate parsing if JPEG APP1 already parsed this exact offset
            bool alreadyParsed = false;
            foreach (var t in tags)
            {
                if (t.SourceOffset.HasValue && Math.Abs(t.SourceOffset.Value - tiffStart) < 64)
                {
                    alreadyParsed = true;
                    break;
                }
            }

            if (!alreadyParsed && tiffStart + 8 <= span.Length)
            {
                ParseTiffHeader(span[tiffStart..], tiffStart, tags);
            }

            pos = matchOffset + 6;
        }
    }

    private static void ParseTiffHeader(ReadOnlySpan<byte> tiffSpan, long baseDocOffset, List<MetadataTagEntry> tags)
    {
        if (tiffSpan.Length < 8)
            return;

        bool bigEndian;
        if (tiffSpan[0] == 'I' && tiffSpan[1] == 'I')
            bigEndian = false;
        else if (tiffSpan[0] == 'M' && tiffSpan[1] == 'M')
            bigEndian = true;
        else
            return;

        ushort magic = ReadU16(tiffSpan.Slice(2, 2), bigEndian);
        if (magic != 42)
            return;

        tags.Add(new MetadataTagEntry("Exif", "ExifByteOrder",
            bigEndian ? "Big-endian (Motorola, MM)" : "Little-endian (Intel, II)", baseDocOffset, 2));

        uint ifd0Offset = ReadU32(tiffSpan.Slice(4, 4), bigEndian);
        var visited = new HashSet<uint>();
        ParseIfd(tiffSpan, ifd0Offset, bigEndian, "IFD0", TiffTagNames, baseDocOffset, tags, visited);
    }

    private static void ParseIfd(
        ReadOnlySpan<byte> tiffSpan,
        uint ifdOffset,
        bool bigEndian,
        string groupName,
        Dictionary<ushort, string> tagDictionary,
        long baseDocOffset,
        List<MetadataTagEntry> tags,
        HashSet<uint> visited)
    {
        if (ifdOffset == 0 || ifdOffset + 2 > tiffSpan.Length || !visited.Add(ifdOffset) || visited.Count > 8)
            return;

        int pos = (int)ifdOffset;
        ushort entryCount = ReadU16(tiffSpan.Slice(pos, 2), bigEndian);
        if (entryCount > 256)
            return;

        pos += 2;
        for (int i = 0; i < entryCount && pos + 12 <= tiffSpan.Length; i++, pos += 12)
        {
            ReadOnlySpan<byte> entry = tiffSpan.Slice(pos, 12);
            ushort tagId = ReadU16(entry[..2], bigEndian);
            ushort format = ReadU16(entry.Slice(2, 2), bigEndian);
            uint count = ReadU32(entry.Slice(4, 4), bigEndian);
            uint valueOrOffset = ReadU32(entry.Slice(8, 4), bigEndian);

            if (tagId == 0x8769) // ExifSubIFD
            {
                ParseIfd(tiffSpan, valueOrOffset, bigEndian, "ExifIFD", TiffTagNames, baseDocOffset, tags, visited);
                continue;
            }
            if (tagId == 0x8825) // GPS IFD
            {
                ParseIfd(tiffSpan, valueOrOffset, bigEndian, "GPS", GpsTagNames, baseDocOffset, tags, visited);
                continue;
            }

            string tagName = tagDictionary.TryGetValue(tagId, out string? known)
                ? known
                : $"Tag_0x{tagId:X4}";

            var (valText, valOffset, valByteLen) = DecodeTiffTagValue(
                tiffSpan, pos, format, count, valueOrOffset, bigEndian, baseDocOffset);

            if (!string.IsNullOrEmpty(valText))
            {
                tags.Add(new MetadataTagEntry(groupName, tagName, valText, valOffset, valByteLen));
            }
        }
    }

    private static (string Value, long Offset, int Length) DecodeTiffTagValue(
        ReadOnlySpan<byte> tiffSpan,
        int entryPos,
        ushort format,
        uint count,
        uint valueOrOffset,
        bool bigEndian,
        long baseDocOffset)
    {
        int unitSize = format switch
        {
            1 or 2 or 6 or 7 => 1, // Byte, ASCII, SByte, Undefined
            3 or 8 => 2,           // UShort, SShort
            4 or 9 or 11 => 4,     // ULong, SLong, Float
            5 or 10 or 12 => 8,    // URational, SRational, Double
            _ => 1
        };

        long totalBytesLong = (long)count * unitSize;
        if (totalBytesLong <= 0 || totalBytesLong > 65536)
            return ("", baseDocOffset + entryPos, 12);

        int totalBytes = (int)totalBytesLong;
        int dataPos = totalBytes <= 4 ? entryPos + 8 : (int)valueOrOffset;
        if (dataPos < 0 || dataPos + totalBytes > tiffSpan.Length)
            return ("", baseDocOffset + entryPos, 12);

        ReadOnlySpan<byte> valSpan = tiffSpan.Slice(dataPos, totalBytes);
        long docOffset = baseDocOffset + dataPos;

        switch (format)
        {
            case 2: // ASCII string
                return (Encoding.UTF8.GetString(valSpan).TrimEnd('\0').Trim(), docOffset, totalBytes);

            case 1 or 7: // Byte / Undefined
                if (totalBytes == 4 && valSpan[0] == '0' && valSpan[1] == '2')
                    return (Encoding.ASCII.GetString(valSpan), docOffset, totalBytes);
                if (totalBytes == 1)
                    return (valSpan[0].ToString(), docOffset, 1);
                return (Convert.ToHexString(valSpan[..Math.Min(16, totalBytes)]), docOffset, totalBytes);

            case 3: // UShort
                return (ReadU16(valSpan[..2], bigEndian).ToString(), docOffset, totalBytes);

            case 4: // ULong
                return (ReadU32(valSpan[..4], bigEndian).ToString(), docOffset, totalBytes);

            case 5 when totalBytes >= 8: // Unsigned Rational (num / den)
            {
                if (count >= 3 && totalBytes >= 24)
                {
                    // GPS DMS array (Degrees, Minutes, Seconds)
                    double deg = ReadRational(valSpan[..8], bigEndian);
                    double min = ReadRational(valSpan.Slice(8, 8), bigEndian);
                    double sec = ReadRational(valSpan.Slice(16, 8), bigEndian);
                    return ($"{deg:0}° {min:0}' {sec:0.##}\"", docOffset, totalBytes);
                }

                uint num = ReadU32(valSpan[..4], bigEndian);
                uint den = ReadU32(valSpan.Slice(4, 4), bigEndian);
                if (den == 0) return ("0", docOffset, 8);
                if (num % den == 0) return ($"{num / den}", docOffset, 8);
                double dec = (double)num / den;
                return ($"{dec:0.####} ({num}/{den})", docOffset, 8);
            }

            default:
                return ($"0x{valueOrOffset:X}", baseDocOffset + entryPos, 12);
        }
    }

    private static double ReadRational(ReadOnlySpan<byte> span, bool bigEndian)
    {
        uint num = ReadU32(span[..4], bigEndian);
        uint den = ReadU32(span.Slice(4, 4), bigEndian);
        return den == 0 ? 0.0 : (double)num / den;
    }

    private static void ExtractPdfMetadata(ReadOnlySpan<byte> span, List<MetadataTagEntry> tags)
    {
        int headerEnd = span[..Math.Min(32, span.Length)].IndexOf((byte)'\n');
        if (headerEnd < 0) headerEnd = Math.Min(16, span.Length);
        string ver = Encoding.ASCII.GetString(span[..headerEnd]).Trim();
        tags.Add(new MetadataTagEntry("PDF", "PDFVersion", ver, 0, headerEnd));

        string[] pdfKeys = { "/Title", "/Author", "/Subject", "/Producer", "/Creator", "/CreationDate", "/ModDate" };
        string ascii = Encoding.Latin1.GetString(span[..Math.Min(span.Length, 256 * 1024)]);

        foreach (string key in pdfKeys)
        {
            int idx = ascii.IndexOf(key, StringComparison.Ordinal);
            if (idx >= 0)
            {
                int parenStart = ascii.IndexOf('(', idx + key.Length);
                int parenEnd = parenStart >= 0 ? ascii.IndexOf(')', parenStart + 1) : -1;
                if (parenStart >= 0 && parenEnd > parenStart && parenEnd - parenStart < 256)
                {
                    string val = ascii.Substring(parenStart + 1, parenEnd - parenStart - 1);
                    tags.Add(new MetadataTagEntry("PDF", key.TrimStart('/'), val, idx, parenEnd - idx + 1));
                }
            }
        }
    }

    private static void ExtractBinaryFormatTags(ReadOnlySpan<byte> span, List<MetadataTagEntry> tags)
    {
        // Windows PE / COFF Header
        if (span.Length >= 0x40 && span[0] == 'M' && span[1] == 'Z')
        {
            uint peOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(0x3C, 4));
            if (peOffset + 24 <= span.Length && span.Slice((int)peOffset, 4).SequenceEqual("PE\0\0"u8))
            {
                int coff = (int)peOffset + 4;
                ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(coff, 2));
                ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(coff + 2, 2));
                uint timestamp = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(coff + 4, 4));

                string arch = machine switch
                {
                    0x8664 => "AMD64 (x86_64)",
                    0x014C => "Intel 386 (x86)",
                    0xAA64 => "ARM64 (AArch64)",
                    0x01C0 => "ARM Little-Endian",
                    _ => $"0x{machine:X4}"
                };

                tags.Add(new MetadataTagEntry("PE", "MachineType", arch, coff, 2));
                tags.Add(new MetadataTagEntry("PE", "SectionCount", sections.ToString(), coff + 2, 2));
                tags.Add(new MetadataTagEntry("PE", "TimeStamp",
                    DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime.ToString("yyyy:MM:dd HH:mm:ss 'UTC'"), coff + 4, 4));
            }
        }

        // ELF Header
        if (span.Length >= 24 && span[..4].SequenceEqual(new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' }))
        {
            bool is64 = span[4] == 2;
            bool be = span[5] == 2;
            ushort eType = ReadU16(span.Slice(16, 2), be);
            ushort eMachine = ReadU16(span.Slice(18, 2), be);

            tags.Add(new MetadataTagEntry("ELF", "CPUClass", is64 ? "64-bit" : "32-bit", 4, 1));
            tags.Add(new MetadataTagEntry("ELF", "ByteOrder", be ? "Big Endian" : "Little Endian", 5, 1));
            tags.Add(new MetadataTagEntry("ELF", "ObjectFileType", eType switch
            {
                1 => "Relocatable",
                2 => "Executable",
                3 => "Shared Object / PIE",
                4 => "Core Dump",
                _ => $"0x{eType:X}"
            }, 16, 2));
            tags.Add(new MetadataTagEntry("ELF", "CPUType", eMachine switch
            {
                3 => "x86 (i386)",
                8 => "MIPS",
                40 => "ARM",
                62 => "AMD x86-64",
                183 => "ARM64 (AArch64)",
                243 => "RISC-V",
                _ => $"0x{eMachine:X}"
            }, 18, 2));
        }

        // Scan for SquashFS Superblock ('hsqs')
        int sqIdx = span[..Math.Min(span.Length, 65536)].IndexOf("hsqs"u8);
        if (sqIdx >= 0 && sqIdx + 48 <= span.Length)
        {
            var sq = span.Slice(sqIdx, 48);
            uint inodes = BinaryPrimitives.ReadUInt32LittleEndian(sq.Slice(4, 4));
            uint mkfsTime = BinaryPrimitives.ReadUInt32LittleEndian(sq.Slice(8, 4));
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(sq.Slice(12, 4));
            ushort comp = BinaryPrimitives.ReadUInt16LittleEndian(sq.Slice(20, 2));
            ulong bytesUsed = BinaryPrimitives.ReadUInt64LittleEndian(sq.Slice(40, 8));

            tags.Add(new MetadataTagEntry("SquashFS", "CreateDate",
                DateTimeOffset.FromUnixTimeSeconds(mkfsTime).UtcDateTime.ToString("yyyy:MM:dd HH:mm:ss 'UTC'"), sqIdx + 8, 4));
            tags.Add(new MetadataTagEntry("SquashFS", "Compression",
                comp switch { 1 => "zlib", 2 => "lzma", 3 => "lzo", 4 => "xz", 5 => "lz4", 6 => "zstd", _ => comp.ToString() }, sqIdx + 20, 2));
            tags.Add(new MetadataTagEntry("SquashFS", "InodeCount", inodes.ToString(CultureInfo.InvariantCulture), sqIdx + 4, 4));
            tags.Add(new MetadataTagEntry("SquashFS", "BlockSize", $"{blockSize:N0} bytes", sqIdx + 12, 4));
            tags.Add(new MetadataTagEntry("SquashFS", "FilesystemSize", $"{bytesUsed:N0} bytes", sqIdx + 40, 8));
        }
    }

    private static void TryMergeExternalExifTool(string filePath, List<MetadataTagEntry> tags)
    {
        try
        {
            bool isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            string exeName = isLinux ? "exiftool" : "exiftool.exe";
            string? pathEnv = Environment.GetEnvironmentVariable("PATH");
            string? foundExe = null;

            if (!string.IsNullOrEmpty(pathEnv))
            {
                foreach (string dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    string candidate = Path.Combine(dir.Trim(), exeName);
                    if (File.Exists(candidate))
                    {
                        foundExe = candidate;
                        break;
                    }
                }
            }

            if (foundExe is null) return;

            var psi = new ProcessStartInfo
            {
                FileName = foundExe,
                Arguments = $"-j -G \"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;

            string json = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
            {
                var obj = doc.RootElement[0];
                foreach (var prop in obj.EnumerateObject())
                {
                    if (prop.Name.Equals("SourceFile", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string group = "ExifTool";
                    string name = prop.Name;
                    int colon = prop.Name.IndexOf(':');
                    if (colon > 0)
                    {
                        group = prop.Name[..colon];
                        name = prop.Name[(colon + 1)..];
                    }

                    string val = prop.Value.ToString();
                    tags.Add(new MetadataTagEntry(group, name, val));
                }
            }
        }
        catch
        {
            // Keep built-in extracted tags if external exiftool fails
        }
    }

    private static string ExtractPrintableText(ReadOnlySpan<byte> span)
    {
        var sb = new StringBuilder();
        foreach (byte b in span)
        {
            if (b >= 32 && b < 127)
                sb.Append((char)b);
            else if (sb.Length > 0 && sb[^1] != ' ')
                sb.Append(' ');
        }
        return sb.ToString().Trim();
    }

    private static ushort ReadU16(ReadOnlySpan<byte> b, bool bigEndian) =>
        bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);

    private static uint ReadU32(ReadOnlySpan<byte> b, bool bigEndian) =>
        bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
}

