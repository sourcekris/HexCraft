using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using HexCraft.Core.Buffers;

namespace HexCraft.Core.Analysis;

public enum ExtractedStringEncoding
{
    Ascii,
    Utf16LittleEndian,
    Utf16BigEndian
}

public sealed record ExtractedString(
    long Offset,
    int ByteLength,
    ExtractedStringEncoding Encoding,
    string Value)
{
    public string OffsetHex => $"0x{Offset:X8}";
    public string EncodingLabel => Encoding switch
    {
        ExtractedStringEncoding.Ascii => "ASCII/UTF-8",
        ExtractedStringEncoding.Utf16LittleEndian => "UTF-16 LE",
        ExtractedStringEncoding.Utf16BigEndian => "UTF-16 BE",
        _ => "ASCII"
    };
}

public sealed record StringScanOptions(
    int MinCharacters = 4,
    bool IncludeAscii = true,
    bool IncludeUtf16Le = true,
    bool IncludeUtf16Be = false,
    int MaxResults = 25000);

/// <summary>
/// Extracts printable ASCII/UTF-8 and UTF-16 strings from a BinaryDocument.
/// </summary>
public static class StringsScanner
{
    public static List<ExtractedString> Scan(
        BinaryDocument doc,
        StringScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new StringScanOptions();
        int minChars = Math.Max(2, options.MinCharacters);
        var results = new List<ExtractedString>();

        long maxScanBytes = Math.Min(doc.Length, 32L * 1024 * 1024); // Cap automatic scan at 32 MB
        if (maxScanBytes <= 0)
            return results;

        byte[] data = doc.ReadBytes(0, (int)maxScanBytes);

        if (options.IncludeAscii)
        {
            ScanAscii(data, minChars, options.MaxResults, results, cancellationToken);
        }

        if (options.IncludeUtf16Le && results.Count < options.MaxResults)
        {
            ScanUtf16(data, minChars, bigEndian: false, options.MaxResults, results, cancellationToken);
        }

        if (options.IncludeUtf16Be && results.Count < options.MaxResults)
        {
            ScanUtf16(data, minChars, bigEndian: true, options.MaxResults, results, cancellationToken);
        }

        results.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        return results;
    }

    public static List<ExtractedString> Filter(
        IEnumerable<ExtractedString> source,
        string? query,
        bool useRegex = false)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new List<ExtractedString>(source);

        var filtered = new List<ExtractedString>();
        Regex? regex = null;
        if (useRegex)
        {
            try
            {
                regex = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            catch
            {
                regex = null;
            }
        }

        foreach (var item in source)
        {
            if (regex is not null)
            {
                if (regex.IsMatch(item.Value))
                    filtered.Add(item);
            }
            else if (item.Value.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                     item.OffsetHex.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                filtered.Add(item);
            }
        }

        return filtered;
    }

    private static void ScanAscii(
        ReadOnlySpan<byte> data,
        int minChars,
        int maxResults,
        List<ExtractedString> results,
        CancellationToken ct)
    {
        var sb = new StringBuilder();
        long startOffset = -1;

        for (int i = 0; i < data.Length; i++)
        {
            if ((i & 0x3FFF) == 0 && ct.IsCancellationRequested)
                return;

            byte b = data[i];
            if (IsPrintableAscii(b))
            {
                if (startOffset < 0)
                    startOffset = i;
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minChars)
                {
                    results.Add(new ExtractedString(
                        startOffset,
                        sb.Length,
                        ExtractedStringEncoding.Ascii,
                        sb.ToString()));

                    if (results.Count >= maxResults)
                        return;
                }
                sb.Clear();
                startOffset = -1;
            }
        }

        if (sb.Length >= minChars && results.Count < maxResults)
        {
            results.Add(new ExtractedString(
                startOffset,
                sb.Length,
                ExtractedStringEncoding.Ascii,
                sb.ToString()));
        }
    }

    private static void ScanUtf16(
        ReadOnlySpan<byte> data,
        int minChars,
        bool bigEndian,
        int maxResults,
        List<ExtractedString> results,
        CancellationToken ct)
    {
        var sb = new StringBuilder();
        long startOffset = -1;

        for (int align = 0; align <= 1; align++)
        {
            sb.Clear();
            startOffset = -1;

            for (int i = align; i + 1 < data.Length; i += 2)
            {
                if ((i & 0x3FFF) == 0 && ct.IsCancellationRequested)
                    return;

                byte lo = bigEndian ? data[i + 1] : data[i];
                byte hi = bigEndian ? data[i] : data[i + 1];

                if (hi == 0x00 && IsPrintableAscii(lo))
                {
                    if (startOffset < 0)
                        startOffset = i;
                    sb.Append((char)lo);
                }
                else
                {
                    if (sb.Length >= minChars)
                    {
                        results.Add(new ExtractedString(
                            startOffset,
                            sb.Length * 2,
                            bigEndian ? ExtractedStringEncoding.Utf16BigEndian : ExtractedStringEncoding.Utf16LittleEndian,
                            sb.ToString()));

                        if (results.Count >= maxResults)
                            return;
                    }
                    sb.Clear();
                    startOffset = -1;
                }
            }

            if (sb.Length >= minChars && results.Count < maxResults)
            {
                results.Add(new ExtractedString(
                    startOffset,
                    sb.Length * 2,
                    bigEndian ? ExtractedStringEncoding.Utf16BigEndian : ExtractedStringEncoding.Utf16LittleEndian,
                    sb.ToString()));
            }
        }
    }

    private static bool IsPrintableAscii(byte b)
    {
        return (b >= 0x20 && b <= 0x7E) || b == 0x09;
    }
}

