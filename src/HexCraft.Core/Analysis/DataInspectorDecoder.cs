using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using HexCraft.Core.Buffers;

namespace HexCraft.Core.Analysis;

public sealed record DataInspectorEntry(
    string TypeName,
    string ValueText,
    int ByteSize);

/// <summary>
/// Decodes primitive values, timestamps, and strings at a given document offset
/// in both Little Endian and Big Endian formats.
/// </summary>
public static class DataInspectorDecoder
{
    public static IReadOnlyList<DataInspectorEntry> DecodeAt(BinaryDocument doc, long offset, bool bigEndian = false)
    {
        var entries = new List<DataInspectorEntry>();
        if (offset < 0 || offset >= doc.Length)
            return entries;

        Span<byte> buf = stackalloc byte[16];
        int available = doc.ReadBytes(offset, buf);
        if (available <= 0)
            return entries;

        byte b0 = buf[0];
        sbyte sb0 = unchecked((sbyte)b0);

        entries.Add(new DataInspectorEntry("Binary (8-bit)", Convert.ToString(b0, 2).PadLeft(8, '0'), 1));
        entries.Add(new DataInspectorEntry("Int8 (sbyte)", $"{sb0} (0x{b0:X2})", 1));
        entries.Add(new DataInspectorEntry("UInt8 (byte)", $"{b0} (0x{b0:X2})", 1));

        if (available >= 2)
        {
            short i16 = bigEndian
                ? BinaryPrimitives.ReadInt16BigEndian(buf[..2])
                : BinaryPrimitives.ReadInt16LittleEndian(buf[..2]);
            ushort u16 = bigEndian
                ? BinaryPrimitives.ReadUInt16BigEndian(buf[..2])
                : BinaryPrimitives.ReadUInt16LittleEndian(buf[..2]);

            entries.Add(new DataInspectorEntry("Int16", $"{i16:N0}", 2));
            entries.Add(new DataInspectorEntry("UInt16", $"{u16:N0} (0x{u16:X4})", 2));
            entries.Add(new DataInspectorEntry("DOS Date", DecodeDosDate(u16), 2));
            entries.Add(new DataInspectorEntry("DOS Time", DecodeDosTime(u16), 2));
        }
        else
        {
            entries.Add(new DataInspectorEntry("Int16", "<EOF>", 2));
            entries.Add(new DataInspectorEntry("UInt16", "<EOF>", 2));
        }

        if (available >= 4)
        {
            int i32 = bigEndian
                ? BinaryPrimitives.ReadInt32BigEndian(buf[..4])
                : BinaryPrimitives.ReadInt32LittleEndian(buf[..4]);
            uint u32 = bigEndian
                ? BinaryPrimitives.ReadUInt32BigEndian(buf[..4])
                : BinaryPrimitives.ReadUInt32LittleEndian(buf[..4]);
            float f32 = bigEndian
                ? BinaryPrimitives.ReadSingleBigEndian(buf[..4])
                : BinaryPrimitives.ReadSingleLittleEndian(buf[..4]);

            entries.Add(new DataInspectorEntry("Int32", $"{i32:N0}", 4));
            entries.Add(new DataInspectorEntry("UInt32", $"{u32:N0} (0x{u32:X8})", 4));
            entries.Add(new DataInspectorEntry("Float32", $"{f32:G7}", 4));

            string unixTime = DecodeUnixTime32(u32);
            entries.Add(new DataInspectorEntry("time_t (32-bit)", unixTime, 4));
        }
        else
        {
            entries.Add(new DataInspectorEntry("Int32", "<EOF>", 4));
            entries.Add(new DataInspectorEntry("UInt32", "<EOF>", 4));
            entries.Add(new DataInspectorEntry("Float32", "<EOF>", 4));
        }

        if (available >= 8)
        {
            long i64 = bigEndian
                ? BinaryPrimitives.ReadInt64BigEndian(buf[..8])
                : BinaryPrimitives.ReadInt64LittleEndian(buf[..8]);
            ulong u64 = bigEndian
                ? BinaryPrimitives.ReadUInt64BigEndian(buf[..8])
                : BinaryPrimitives.ReadUInt64LittleEndian(buf[..8]);
            double f64 = bigEndian
                ? BinaryPrimitives.ReadDoubleBigEndian(buf[..8])
                : BinaryPrimitives.ReadDoubleLittleEndian(buf[..8]);

            entries.Add(new DataInspectorEntry("Int64", $"{i64:N0}", 8));
            entries.Add(new DataInspectorEntry("UInt64", $"{u64:N0} (0x{u64:X16})", 8));
            entries.Add(new DataInspectorEntry("Float64", $"{f64:G15}", 8));
            entries.Add(new DataInspectorEntry("FILETIME", DecodeFileTime(i64), 8));
        }
        else
        {
            entries.Add(new DataInspectorEntry("Int64", "<EOF>", 8));
            entries.Add(new DataInspectorEntry("UInt64", "<EOF>", 8));
            entries.Add(new DataInspectorEntry("Float64", "<EOF>", 8));
        }

        // Character & String previews
        entries.Add(new DataInspectorEntry("ASCII Char", FormatAsciiChar(b0), 1));
        entries.Add(new DataInspectorEntry("UTF-8 Char", DecodeUtf8Char(buf[..available], out int utf8Len), utf8Len));

        if (available >= 2)
        {
            var encoding = bigEndian ? Encoding.BigEndianUnicode : Encoding.Unicode;
            string u16Char = encoding.GetString(buf[..2]);
            entries.Add(new DataInspectorEntry("UTF-16 Char", FormatCharDisplay(u16Char[0]), 2));
        }

        return entries;
    }

    public static string DecodeDosDate(ushort raw)
    {
        int day = raw & 0x1F;
        int month = (raw >> 5) & 0x0F;
        int year = ((raw >> 9) & 0x7F) + 1980;
        if (month is >= 1 and <= 12 && day is >= 1 and <= 31)
            return $"{year:D4}-{month:D2}-{day:D2}";
        return $"Invalid (0x{raw:X4})";
    }

    public static string DecodeDosTime(ushort raw)
    {
        int sec = (raw & 0x1F) * 2;
        int min = (raw >> 5) & 0x3F;
        int hour = (raw >> 11) & 0x1F;
        if (hour < 24 && min < 60 && sec < 60)
            return $"{hour:D2}:{min:D2}:{sec:D2}";
        return $"Invalid (0x{raw:X4})";
    }

    private static string DecodeUnixTime32(uint seconds)
    {
        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        }
        catch
        {
            return "Out of range";
        }
    }

    private static string DecodeFileTime(long fileTime)
    {
        try
        {
            if (fileTime <= 0 || fileTime > 2650467743999999999L)
                return "Out of range";
            return DateTime.FromFileTimeUtc(fileTime).ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        }
        catch
        {
            return "Out of range";
        }
    }

    private static string FormatAsciiChar(byte b)
    {
        if (b >= 32 && b < 127)
            return $"'{(char)b}' ({b})";
        return b switch
        {
            0x00 => "'\\0' (NUL)",
            0x09 => "'\\t' (TAB)",
            0x0A => "'\\n' (LF)",
            0x0D => "'\\r' (CR)",
            _ => $"0x{b:X2} (non-printable)"
        };
    }

    private static string DecodeUtf8Char(ReadOnlySpan<byte> bytes, out int byteLen)
    {
        byteLen = 1;
        if (bytes.IsEmpty) return "";
        if (Rune.DecodeFromUtf8(bytes, out Rune rune, out int consumed) == System.Buffers.OperationStatus.Done)
        {
            byteLen = consumed;
            return Rune.IsControl(rune) ? $"U+{rune.Value:X4} (ctrl)" : $"'{rune}' (U+{rune.Value:X4})";
        }
        return $"0x{bytes[0]:X2} (invalid UTF-8)";
    }

    private static string FormatCharDisplay(char c)
    {
        return char.IsControl(c) ? $"U+{(int)c:X4} (ctrl)" : $"'{c}' (U+{(int)c:X4})";
    }
}

