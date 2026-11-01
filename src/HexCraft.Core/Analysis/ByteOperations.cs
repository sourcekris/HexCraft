using System;
using System.Text;
using HexCraft.Core.Buffers;

namespace HexCraft.Core.Analysis;

public enum CopyExportFormat
{
    HexSpaceSeparated,
    CArray,
    CSharpArray,
    PythonBytes,
    Base64
}

/// <summary>
/// Provides memory-safe in-place byte transformations (XOR, Bitwise NOT, Fill, Reverse, Rotate)
/// and code-snippet export formatters for reverse engineering workflows.
/// </summary>
public static class ByteOperations
{
    public static void XorRange(BinaryDocument doc, long offset, long length, ReadOnlySpan<byte> key)
    {
        if (length <= 0 || key.IsEmpty || offset < 0 || offset >= doc.Length)
            return;

        int actualLen = (int)Math.Min(length, doc.Length - offset);
        byte[] data = doc.ReadBytes(offset, actualLen);
        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= key[i % key.Length];
        }
        doc.OverwriteBytes(offset, data);
    }

    public static void InvertRange(BinaryDocument doc, long offset, long length)
    {
        if (length <= 0 || offset < 0 || offset >= doc.Length)
            return;

        int actualLen = (int)Math.Min(length, doc.Length - offset);
        byte[] data = doc.ReadBytes(offset, actualLen);
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)~data[i];
        }
        doc.OverwriteBytes(offset, data);
    }

    public static void FillRange(BinaryDocument doc, long offset, long length, byte fillValue)
    {
        if (length <= 0 || offset < 0 || offset >= doc.Length)
            return;

        int actualLen = (int)Math.Min(length, doc.Length - offset);
        byte[] data = new byte[actualLen];
        Array.Fill(data, fillValue);
        doc.OverwriteBytes(offset, data);
    }

    public static void ReverseRange(BinaryDocument doc, long offset, long length)
    {
        if (length <= 1 || offset < 0 || offset >= doc.Length)
            return;

        int actualLen = (int)Math.Min(length, doc.Length - offset);
        byte[] data = doc.ReadBytes(offset, actualLen);
        Array.Reverse(data);
        doc.OverwriteBytes(offset, data);
    }

    public static string FormatBytesAsCode(ReadOnlySpan<byte> bytes, CopyExportFormat format, string variableName = "payload")
    {
        if (bytes.IsEmpty)
            return string.Empty;

        switch (format)
        {
            case CopyExportFormat.HexSpaceSeparated:
            {
                var sb = new StringBuilder(bytes.Length * 3);
                for (int i = 0; i < bytes.Length; i++)
                {
                    if (i > 0) sb.Append(' ');
                    sb.Append(bytes[i].ToString("X2"));
                }
                return sb.ToString();
            }

            case CopyExportFormat.CArray:
            {
                var sb = new StringBuilder();
                sb.AppendLine($"const uint8_t {variableName}[{bytes.Length}] = {{");
                AppendFormattedHexLines(sb, bytes, "    ");
                sb.AppendLine();
                sb.Append("};");
                return sb.ToString();
            }

            case CopyExportFormat.CSharpArray:
            {
                var sb = new StringBuilder();
                sb.AppendLine($"byte[] {variableName} = new byte[{bytes.Length}]");
                sb.AppendLine("{");
                AppendFormattedHexLines(sb, bytes, "    ");
                sb.AppendLine();
                sb.Append("};");
                return sb.ToString();
            }

            case CopyExportFormat.PythonBytes:
            {
                var sb = new StringBuilder();
                sb.Append($"{variableName} = b\"");
                for (int i = 0; i < bytes.Length; i++)
                {
                    sb.Append($"\\x{bytes[i]:x2}");
                }
                sb.Append('"');
                return sb.ToString();
            }

            case CopyExportFormat.Base64:
                return Convert.ToBase64String(bytes);

            default:
                return Convert.ToHexString(bytes);
        }
    }

    private static void AppendFormattedHexLines(StringBuilder sb, ReadOnlySpan<byte> bytes, string indent)
    {
        const int PerRow = 12;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i % PerRow == 0)
            {
                if (i > 0) sb.AppendLine(",");
                sb.Append(indent);
            }
            else
            {
                sb.Append(", ");
            }
            sb.Append($"0x{bytes[i]:X2}");
        }
    }
}

